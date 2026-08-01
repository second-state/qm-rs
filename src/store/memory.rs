//! Per-scope memory notebooks with a revision history.

use rusqlite::{params, Row};
use sha2::{Digest, Sha256};

use crate::db::{new_id, now_rfc3339, DbPool};
use crate::error::AppResult;
use crate::memory::{empty_document, fold_capture, query_bullets, recall_body};
use crate::types::ScopeId;

#[derive(Clone)]
pub struct MemoryStore {
    pool: DbPool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemoryHead {
    pub content: String,
    pub revision: String,
    pub updated_at: Option<String>,
}

#[derive(Debug, Clone)]
pub struct MemoryRevision {
    pub id: String,
    pub revision: String,
    pub content: String,
    pub operation: String,
    pub author: Option<String>,
    pub at: String,
}

/// Content-addressed revision token. Two writers producing identical content
/// converge on the same revision, so a redundant write is a no-op rather than
/// a spurious conflict.
fn revision_token(content: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(content.as_bytes());
    format!("{:x}", hasher.finalize())
}

fn revision_from_row(row: &Row<'_>) -> rusqlite::Result<MemoryRevision> {
    Ok(MemoryRevision {
        id: row.get("id")?,
        revision: row.get("revision")?,
        content: row.get("content")?,
        operation: row.get("operation")?,
        author: row.get("author")?,
        at: row.get("at")?,
    })
}

impl MemoryStore {
    pub fn new(pool: DbPool) -> Self {
        Self { pool }
    }

    /// The stored document, or a fresh one for a scope with no notebook yet.
    pub fn read(&self, scope_id: &ScopeId) -> AppResult<String> {
        Ok(self.head(scope_id)?.content)
    }

    pub fn head(&self, scope_id: &ScopeId) -> AppResult<MemoryHead> {
        let conn = self.pool.get()?;
        let mut stmt = conn
            .prepare("SELECT content, revision, updated_at FROM memory_docs WHERE scope_id = ?1")?;
        let mut rows = stmt.query_map([scope_id.as_str()], |r| {
            Ok(MemoryHead {
                content: r.get(0)?,
                revision: r.get(1)?,
                updated_at: r.get(2)?,
            })
        })?;
        Ok(rows.next().transpose()?.unwrap_or_else(|| {
            let content = empty_document();
            let revision = revision_token(&content);
            MemoryHead {
                content,
                revision,
                updated_at: None,
            }
        }))
    }

    /// What a turn sees: trimmed and tail-capped.
    pub fn recall(&self, scope_id: &ScopeId) -> AppResult<String> {
        Ok(recall_body(&self.read(scope_id)?))
    }

    /// Fold facts into the notebook. Returns how many were new.
    pub fn capture(
        &self,
        scope_id: &ScopeId,
        facts: &[String],
        author: Option<&str>,
        trusted_provenance: bool,
    ) -> AppResult<usize> {
        let existing = self.read(scope_id)?;
        let date = chrono::Utc::now().format("%Y-%m-%d").to_string();
        let result = fold_capture(&existing, facts, &date, trusted_provenance);
        if result.added == 0 {
            return Ok(0);
        }
        self.write(scope_id, &result.body, "capture", author)?;
        Ok(result.added)
    }

    pub fn replace(
        &self,
        scope_id: &ScopeId,
        content: &str,
        author: Option<&str>,
    ) -> AppResult<()> {
        self.write(scope_id, content, "replace", author)
    }

    /// Compare-and-swap on the revision token. Returns false when the caller's
    /// revision is stale — the concurrent-edit guard for the web editor.
    pub fn replace_if_revision(
        &self,
        scope_id: &ScopeId,
        content: &str,
        expected_revision: &str,
        author: Option<&str>,
    ) -> AppResult<bool> {
        let head = self.head(scope_id)?;
        if head.revision != expected_revision {
            return Ok(false);
        }
        self.write(scope_id, content, "replace", author)?;
        Ok(true)
    }

    /// Restore a prior revision, guarding against a concurrent edit.
    pub fn restore(
        &self,
        scope_id: &ScopeId,
        revision: &str,
        expected_revision: &str,
        author: Option<&str>,
    ) -> AppResult<bool> {
        let head = self.head(scope_id)?;
        if head.revision != expected_revision {
            return Ok(false);
        }
        let content = {
            let conn = self.pool.get()?;
            let mut stmt = conn.prepare(
                "SELECT content FROM memory_revisions WHERE scope_id = ?1 AND revision = ?2 LIMIT 1",
            )?;
            let mut rows = stmt.query_map(params![scope_id.as_str(), revision], |r| {
                r.get::<_, String>(0)
            })?;
            rows.next().transpose()?
        };
        let Some(content) = content else {
            return Ok(false);
        };
        self.write(scope_id, &content, "restore", author)?;
        Ok(true)
    }

    fn write(
        &self,
        scope_id: &ScopeId,
        content: &str,
        operation: &str,
        author: Option<&str>,
    ) -> AppResult<()> {
        let revision = revision_token(content);
        let now = now_rfc3339();
        let mut conn = self.pool.get()?;
        let tx = conn.transaction()?;
        tx.execute(
            "INSERT INTO memory_docs (scope_id, content, revision, updated_at)
             VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(scope_id) DO UPDATE SET
                content = excluded.content,
                revision = excluded.revision,
                updated_at = excluded.updated_at",
            params![scope_id.as_str(), content, revision, now],
        )?;
        tx.execute(
            "INSERT INTO memory_revisions (id, scope_id, revision, content, operation, author, at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                new_id(),
                scope_id.as_str(),
                revision,
                content,
                operation,
                author,
                now
            ],
        )?;
        tx.commit()?;
        Ok(())
    }

    pub fn query(&self, scope_id: &ScopeId, q: &str, limit: usize) -> AppResult<Vec<String>> {
        Ok(query_bullets(&self.read(scope_id)?, q, limit))
    }

    pub fn history(&self, scope_id: &ScopeId, limit: usize) -> AppResult<Vec<MemoryRevision>> {
        let conn = self.pool.get()?;
        let mut stmt = conn.prepare(
            "SELECT * FROM memory_revisions WHERE scope_id = ?1 ORDER BY at DESC, rowid DESC LIMIT ?2",
        )?;
        let rows = stmt.query_map(params![scope_id.as_str(), limit as i64], revision_from_row)?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    /// Every scope holding a notebook, with its size — the memory index page.
    pub fn index(&self) -> AppResult<Vec<(ScopeId, usize, String)>> {
        let conn = self.pool.get()?;
        let mut stmt = conn
            .prepare("SELECT scope_id, length(content), updated_at FROM memory_docs ORDER BY updated_at DESC")?;
        let rows = stmt.query_map([], |r| {
            Ok((
                ScopeId::from_raw(r.get::<_, String>(0)?),
                r.get::<_, i64>(1)? as usize,
                r.get::<_, String>(2)?,
            ))
        })?;
        Ok(rows.collect::<Result<_, _>>()?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::test_pool;
    use crate::memory::bullets;

    fn store() -> MemoryStore {
        MemoryStore::new(test_pool())
    }

    fn scope() -> ScopeId {
        ScopeId::personal("u1")
    }

    #[test]
    fn an_unwritten_scope_reads_as_a_fresh_notebook() {
        let s = store();
        let head = s.head(&scope()).unwrap();
        assert!(head.content.starts_with("# Memory"));
        assert!(head.updated_at.is_none());
        assert_eq!(s.recall(&scope()).unwrap(), "# Memory");
    }

    #[test]
    fn capture_persists_and_dedupes_across_calls() {
        let s = store();
        assert_eq!(
            s.capture(&scope(), &["likes tea".into()], Some("u1"), true)
                .unwrap(),
            1
        );
        assert_eq!(
            s.capture(&scope(), &["likes tea".into()], Some("u1"), true)
                .unwrap(),
            0
        );
        assert_eq!(bullets(&s.read(&scope()).unwrap()).len(), 1);
    }

    #[test]
    fn scopes_have_independent_notebooks() {
        let s = store();
        s.capture(&scope(), &["mine".into()], None, true).unwrap();
        let other = ScopeId::channel("eng");
        s.capture(&other, &["theirs".into()], None, true).unwrap();
        assert!(s.read(&scope()).unwrap().contains("mine"));
        assert!(!s.read(&scope()).unwrap().contains("theirs"));
        assert_eq!(s.index().unwrap().len(), 2);
    }

    #[test]
    fn a_no_op_capture_does_not_create_a_revision() {
        let s = store();
        s.capture(&scope(), &["fact".into()], None, true).unwrap();
        let before = s.history(&scope(), 50).unwrap().len();
        s.capture(&scope(), &["fact".into()], None, true).unwrap();
        assert_eq!(s.history(&scope(), 50).unwrap().len(), before);
    }

    #[test]
    fn revisions_accumulate_newest_first() {
        let s = store();
        s.capture(&scope(), &["one".into()], Some("a"), true)
            .unwrap();
        s.capture(&scope(), &["two".into()], Some("b"), true)
            .unwrap();
        let history = s.history(&scope(), 10).unwrap();
        assert_eq!(history.len(), 2);
        assert_eq!(history[0].author.as_deref(), Some("b"));
        assert_eq!(history[0].operation, "capture");
        assert!(history[0].content.contains("two"));
    }

    #[test]
    fn a_stale_revision_is_refused() {
        let s = store();
        s.replace(&scope(), "# Memory\n- v1\n", Some("u1")).unwrap();
        let head = s.head(&scope()).unwrap();

        // Someone else writes first.
        s.replace(&scope(), "# Memory\n- v2\n", Some("u2")).unwrap();

        assert!(
            !s.replace_if_revision(&scope(), "# Memory\n- v3\n", &head.revision, Some("u1"))
                .unwrap(),
            "a stale revision must not overwrite"
        );
        assert!(s.read(&scope()).unwrap().contains("v2"));

        let fresh = s.head(&scope()).unwrap();
        assert!(s
            .replace_if_revision(&scope(), "# Memory\n- v3\n", &fresh.revision, Some("u1"))
            .unwrap());
        assert!(s.read(&scope()).unwrap().contains("v3"));
    }

    #[test]
    fn identical_content_yields_an_identical_revision_token() {
        let s = store();
        s.replace(&scope(), "same", None).unwrap();
        let a = s.head(&scope()).unwrap().revision;
        s.replace(&ScopeId::channel("x"), "same", None).unwrap();
        let b = s.head(&ScopeId::channel("x")).unwrap().revision;
        assert_eq!(a, b);
    }

    #[test]
    fn restore_brings_back_an_earlier_revision() {
        let s = store();
        s.replace(&scope(), "# Memory\n- original\n", None).unwrap();
        let original = s.head(&scope()).unwrap().revision;
        s.replace(&scope(), "# Memory\n- clobbered\n", None)
            .unwrap();
        let current = s.head(&scope()).unwrap().revision;

        assert!(s
            .restore(&scope(), &original, &current, Some("u1"))
            .unwrap());
        assert!(s.read(&scope()).unwrap().contains("original"));
        assert_eq!(s.history(&scope(), 1).unwrap()[0].operation, "restore");
    }

    #[test]
    fn restore_refuses_on_a_stale_expectation_or_unknown_revision() {
        let s = store();
        s.replace(&scope(), "a", None).unwrap();
        let rev_a = s.head(&scope()).unwrap().revision;
        s.replace(&scope(), "b", None).unwrap();

        assert!(!s
            .restore(&scope(), &rev_a, "not-the-current-revision", None)
            .unwrap());
        let current = s.head(&scope()).unwrap().revision;
        assert!(!s
            .restore(&scope(), "no-such-revision", &current, None)
            .unwrap());
        assert_eq!(s.read(&scope()).unwrap(), "b");
    }

    #[test]
    fn query_reads_the_stored_notebook() {
        let s = store();
        s.capture(
            &scope(),
            &["likes coffee".into(), "likes tea".into()],
            None,
            true,
        )
        .unwrap();
        assert_eq!(s.query(&scope(), "likes", 10).unwrap().len(), 2);
        assert_eq!(s.query(&scope(), "coffee", 10).unwrap().len(), 1);
        assert!(s.query(&scope(), "beer", 10).unwrap().is_empty());
    }
}
