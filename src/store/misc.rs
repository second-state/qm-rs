//! The smaller durable stores: files, keychain, approvals, deliveries, audit.
//!
//! Each is small enough that a separate module would be ceremony, and they
//! share one property worth stating once: everything here is written to
//! SQLite rather than kept in process memory, because an operator or the
//! system reads it back later.

use rusqlite::{params, Row};

use crate::db::{new_id, now_rfc3339, DbPool};
use crate::error::{AppError, AppResult};
use crate::types::{Destination, PendingApproval, ScopeId};

// ---------------------------------------------------------------------------
// Files
// ---------------------------------------------------------------------------

#[derive(Clone)]
pub struct FileStore {
    pool: DbPool,
}

#[derive(Debug, Clone)]
pub struct FileArtifact {
    pub id: String,
    pub scope_id: ScopeId,
    pub name: String,
    pub mimetype: String,
    pub size_bytes: i64,
    pub direction: String,
    pub author: Option<String>,
    pub created_at: String,
}

fn artifact_from_row(row: &Row<'_>) -> rusqlite::Result<FileArtifact> {
    Ok(FileArtifact {
        id: row.get("id")?,
        scope_id: ScopeId::from_raw(row.get::<_, String>("scope_id")?),
        name: row.get("name")?,
        mimetype: row.get("mimetype")?,
        size_bytes: row.get("size_bytes")?,
        direction: row.get("direction")?,
        author: row.get("author")?,
        created_at: row.get("created_at")?,
    })
}

/// Best-effort content type from a filename. Kept small and explicit rather
/// than pulling in a mime database for a handful of cases.
pub fn mime_from_name(name: &str) -> &'static str {
    match name
        .rsplit('.')
        .next()
        .map(str::to_ascii_lowercase)
        .as_deref()
    {
        Some("txt") | Some("log") => "text/plain",
        Some("md") => "text/markdown",
        Some("json") => "application/json",
        Some("csv") => "text/csv",
        Some("html") => "text/html",
        Some("png") => "image/png",
        Some("jpg") | Some("jpeg") => "image/jpeg",
        Some("gif") => "image/gif",
        Some("pdf") => "application/pdf",
        _ => "application/octet-stream",
    }
}

impl FileStore {
    pub fn new(pool: DbPool) -> Self {
        Self { pool }
    }

    pub fn put(
        &self,
        scope_id: &ScopeId,
        name: &str,
        data: &[u8],
        direction: &str,
        author: Option<&str>,
    ) -> AppResult<FileArtifact> {
        let id = new_id();
        let conn = self.pool.get()?;
        conn.execute(
            "INSERT INTO file_artifacts
                (id, scope_id, name, mimetype, size_bytes, data, direction, author, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                id,
                scope_id.as_str(),
                name,
                mime_from_name(name),
                data.len() as i64,
                data,
                direction,
                author,
                now_rfc3339(),
            ],
        )?;
        self.require(&id)
    }

    pub fn get(&self, id: &str) -> AppResult<Option<FileArtifact>> {
        let conn = self.pool.get()?;
        let mut stmt = conn.prepare("SELECT * FROM file_artifacts WHERE id = ?1")?;
        let mut rows = stmt.query_map([id], artifact_from_row)?;
        Ok(rows.next().transpose()?)
    }

    pub fn require(&self, id: &str) -> AppResult<FileArtifact> {
        self.get(id)?
            .ok_or_else(|| AppError::not_found(format!("file {id}")))
    }

    pub fn read(&self, id: &str) -> AppResult<Vec<u8>> {
        let conn = self.pool.get()?;
        let mut stmt = conn.prepare("SELECT data FROM file_artifacts WHERE id = ?1")?;
        let mut rows = stmt.query_map([id], |r| r.get::<_, Vec<u8>>(0))?;
        rows.next()
            .transpose()?
            .ok_or_else(|| AppError::not_found(format!("file {id}")))
    }

    pub fn list_for_scopes(&self, scopes: &[ScopeId]) -> AppResult<Vec<FileArtifact>> {
        if scopes.is_empty() {
            return Ok(Vec::new());
        }
        let conn = self.pool.get()?;
        let placeholders = vec!["?"; scopes.len()].join(",");
        let sql = format!(
            "SELECT * FROM file_artifacts WHERE scope_id IN ({placeholders})
             ORDER BY created_at DESC LIMIT 500"
        );
        let mut stmt = conn.prepare(&sql)?;
        let owned: Vec<String> = scopes.iter().map(|s| s.as_str().to_string()).collect();
        let args: Vec<&dyn rusqlite::ToSql> =
            owned.iter().map(|s| s as &dyn rusqlite::ToSql).collect();
        let rows = stmt.query_map(args.as_slice(), artifact_from_row)?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    pub fn delete(&self, id: &str) -> AppResult<bool> {
        let conn = self.pool.get()?;
        Ok(conn.execute("DELETE FROM file_artifacts WHERE id = ?1", [id])? > 0)
    }
}

// ---------------------------------------------------------------------------
// Keychain
// ---------------------------------------------------------------------------

#[derive(Clone)]
pub struct KeychainStore {
    pool: DbPool,
}

#[derive(Debug, Clone)]
pub struct KeychainEntry {
    pub scope_id: ScopeId,
    pub key: String,
    pub description: Option<String>,
    pub created_by: String,
    pub created_at: String,
}

/// A value shown in a UI or a log. Never render a secret in full.
pub fn mask(value: &str) -> String {
    let count = value.chars().count();
    if count <= 4 {
        return "•".repeat(count.max(1));
    }
    let tail: String = value.chars().skip(count - 4).collect();
    format!("{}{tail}", "•".repeat(count.min(20) - 4))
}

impl KeychainStore {
    pub fn new(pool: DbPool) -> Self {
        Self { pool }
    }

    /// Keychain keys become process environment variable names in the sandbox,
    /// so they are restricted to the shell-safe alphabet.
    fn validate_key(key: &str) -> AppResult<()> {
        let ok = !key.is_empty()
            && key.len() <= 128
            && key
                .chars()
                .next()
                .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
            && key.chars().all(|c| c.is_ascii_alphanumeric() || c == '_');
        if ok {
            Ok(())
        } else {
            Err(AppError::bad_request(format!(
                "invalid keychain key {key:?}: use A-Z, 0-9 and '_', starting with a letter or '_'"
            )))
        }
    }

    pub fn put(
        &self,
        scope_id: &ScopeId,
        key: &str,
        value: &str,
        description: Option<&str>,
        created_by: &str,
    ) -> AppResult<()> {
        Self::validate_key(key)?;
        let conn = self.pool.get()?;
        conn.execute(
            "INSERT INTO keychain (scope_id, key, value, description, created_by, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)
             ON CONFLICT(scope_id, key) DO UPDATE SET
                value = excluded.value, description = excluded.description",
            params![
                scope_id.as_str(),
                key,
                value,
                description,
                created_by,
                now_rfc3339()
            ],
        )?;
        Ok(())
    }

    pub fn delete(&self, scope_id: &ScopeId, key: &str) -> AppResult<bool> {
        let conn = self.pool.get()?;
        Ok(conn.execute(
            "DELETE FROM keychain WHERE scope_id = ?1 AND key = ?2",
            params![scope_id.as_str(), key],
        )? > 0)
    }

    /// Metadata only — deliberately never the values.
    pub fn list(&self, scopes: &[ScopeId]) -> AppResult<Vec<KeychainEntry>> {
        if scopes.is_empty() {
            return Ok(Vec::new());
        }
        let conn = self.pool.get()?;
        let placeholders = vec!["?"; scopes.len()].join(",");
        let sql = format!(
            "SELECT scope_id, key, description, created_by, created_at FROM keychain
             WHERE scope_id IN ({placeholders}) ORDER BY scope_id, key"
        );
        let mut stmt = conn.prepare(&sql)?;
        let owned: Vec<String> = scopes.iter().map(|s| s.as_str().to_string()).collect();
        let args: Vec<&dyn rusqlite::ToSql> =
            owned.iter().map(|s| s as &dyn rusqlite::ToSql).collect();
        let rows = stmt.query_map(args.as_slice(), |row| {
            Ok(KeychainEntry {
                scope_id: ScopeId::from_raw(row.get::<_, String>(0)?),
                key: row.get(1)?,
                description: row.get(2)?,
                created_by: row.get(3)?,
                created_at: row.get(4)?,
            })
        })?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    /// Values materialized into the sandbox environment for a turn.
    ///
    /// Later scopes win, so callers pass scopes from widest to narrowest and a
    /// personal secret overrides the org's.
    pub fn materialize(&self, scopes: &[ScopeId]) -> AppResult<Vec<(String, String)>> {
        let mut out: Vec<(String, String)> = Vec::new();
        let conn = self.pool.get()?;
        for scope in scopes {
            let mut stmt =
                conn.prepare("SELECT key, value FROM keychain WHERE scope_id = ?1 ORDER BY key")?;
            let rows = stmt.query_map([scope.as_str()], |r| {
                Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?))
            })?;
            for row in rows {
                let (key, value) = row?;
                match out.iter_mut().find(|(k, _)| *k == key) {
                    Some(slot) => slot.1 = value,
                    None => out.push((key, value)),
                }
            }
        }
        Ok(out)
    }
}

// ---------------------------------------------------------------------------
// Approvals
// ---------------------------------------------------------------------------

#[derive(Clone)]
pub struct ApprovalStore {
    pool: DbPool,
}

pub struct NewApproval<'a> {
    pub session_id: &'a str,
    pub command: &'a str,
    pub reason: &'a str,
    pub matched: Option<&'a str>,
    pub purpose: Option<&'a str>,
    pub summary: Option<&'a str>,
    pub approval_key: &'a str,
}

fn approval_from_row(row: &Row<'_>) -> rusqlite::Result<PendingApproval> {
    Ok(PendingApproval {
        request_id: row.get("request_id")?,
        session_id: row.get("session_id")?,
        command: row.get("command")?,
        reason: row.get("reason")?,
        matched: row.get("matched")?,
        purpose: row.get("purpose")?,
        summary: row.get("summary")?,
        approval_key: row.get("approval_key")?,
        created_at: row.get("created_at")?,
    })
}

impl ApprovalStore {
    pub fn new(pool: DbPool) -> Self {
        Self { pool }
    }

    pub fn create(&self, input: NewApproval<'_>) -> AppResult<PendingApproval> {
        let request_id = new_id();
        let conn = self.pool.get()?;
        conn.execute(
            "INSERT INTO pending_approvals
                (request_id, session_id, command, reason, matched, purpose, summary,
                 approval_key, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                request_id,
                input.session_id,
                input.command,
                input.reason,
                input.matched,
                input.purpose,
                input.summary,
                input.approval_key,
                now_rfc3339(),
            ],
        )?;
        self.get(&request_id)?
            .ok_or_else(|| AppError::internal("approval vanished after insert"))
    }

    pub fn get(&self, request_id: &str) -> AppResult<Option<PendingApproval>> {
        let conn = self.pool.get()?;
        let mut stmt = conn.prepare("SELECT * FROM pending_approvals WHERE request_id = ?1")?;
        let mut rows = stmt.query_map([request_id], approval_from_row)?;
        Ok(rows.next().transpose()?)
    }

    pub fn pending_for_session(&self, session_id: &str) -> AppResult<Vec<PendingApproval>> {
        let conn = self.pool.get()?;
        let mut stmt = conn.prepare(
            "SELECT * FROM pending_approvals
             WHERE session_id = ?1 AND resolved_at IS NULL ORDER BY created_at",
        )?;
        let rows = stmt.query_map([session_id], approval_from_row)?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    /// Resolve an approval. Returns false if it was already resolved, so a
    /// double-click cannot approve the same command twice.
    pub fn resolve(&self, request_id: &str, approved: bool) -> AppResult<bool> {
        let conn = self.pool.get()?;
        Ok(conn.execute(
            "UPDATE pending_approvals SET resolved_at = ?2, approved = ?3
             WHERE request_id = ?1 AND resolved_at IS NULL",
            params![request_id, now_rfc3339(), i64::from(approved)],
        )? > 0)
    }

    /// Record a standing grant so this class of command stops asking.
    pub fn grant(
        &self,
        actor_id: &str,
        approval_key: &str,
        grant_scope: &str,
        session_id: Option<&str>,
        command: &str,
    ) -> AppResult<()> {
        let conn = self.pool.get()?;
        conn.execute(
            "INSERT INTO command_approval_grants
                (actor_id, approval_key, grant_scope, session_id, command, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6) ON CONFLICT DO NOTHING",
            params![
                actor_id,
                approval_key,
                grant_scope,
                session_id.unwrap_or(""),
                command,
                now_rfc3339(),
            ],
        )?;
        Ok(())
    }

    /// Whether a standing grant already covers this command class.
    pub fn is_granted(
        &self,
        actor_id: &str,
        approval_key: &str,
        session_id: &str,
    ) -> AppResult<bool> {
        let conn = self.pool.get()?;
        Ok(conn.query_row(
            "SELECT EXISTS(
                 SELECT 1 FROM command_approval_grants
                 WHERE actor_id = ?1 AND approval_key = ?2
                   AND (grant_scope = 'always' OR (grant_scope = 'session' AND session_id = ?3))
             )",
            params![actor_id, approval_key, session_id],
            |r| r.get::<_, i64>(0),
        )? == 1)
    }

    pub fn revoke_grants(&self, actor_id: &str, approval_key: &str) -> AppResult<usize> {
        let conn = self.pool.get()?;
        Ok(conn.execute(
            "DELETE FROM command_approval_grants WHERE actor_id = ?1 AND approval_key = ?2",
            params![actor_id, approval_key],
        )?)
    }

    pub fn list_grants(&self, actor_id: &str) -> AppResult<Vec<(String, String, String)>> {
        let conn = self.pool.get()?;
        let mut stmt = conn.prepare(
            "SELECT approval_key, grant_scope, command FROM command_approval_grants
             WHERE actor_id = ?1 ORDER BY created_at DESC",
        )?;
        let rows = stmt.query_map([actor_id], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?;
        Ok(rows.collect::<Result<_, _>>()?)
    }
}

// ---------------------------------------------------------------------------
// Deliveries
// ---------------------------------------------------------------------------

#[derive(Clone)]
pub struct DeliveryStore {
    pool: DbPool,
}

#[derive(Debug, Clone)]
pub struct Delivery {
    pub id: String,
    pub destination: Destination,
    pub text: String,
    pub idempotency_key: String,
    pub created_at: String,
    pub delivered_at: Option<String>,
    pub error: Option<String>,
}

impl DeliveryStore {
    pub fn new(pool: DbPool) -> Self {
        Self { pool }
    }

    /// Enqueue a delivery. Returns `None` when `idempotency_key` was already
    /// enqueued — the guard that stops a retried cron fire double-posting.
    pub fn enqueue(
        &self,
        destination: &Destination,
        text: &str,
        idempotency_key: &str,
    ) -> AppResult<Option<String>> {
        let id = new_id();
        let conn = self.pool.get()?;
        let inserted = conn.execute(
            "INSERT INTO deliveries (id, destination, text, idempotency_key, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT(idempotency_key) DO NOTHING",
            params![
                id,
                serde_json::to_string(destination)?,
                text,
                idempotency_key,
                now_rfc3339(),
            ],
        )?;
        Ok((inserted > 0).then_some(id))
    }

    pub fn mark_delivered(&self, id: &str) -> AppResult<()> {
        let conn = self.pool.get()?;
        conn.execute(
            "UPDATE deliveries SET delivered_at = ?2, error = NULL WHERE id = ?1",
            params![id, now_rfc3339()],
        )?;
        Ok(())
    }

    pub fn mark_failed(&self, id: &str, error: &str) -> AppResult<()> {
        let conn = self.pool.get()?;
        conn.execute(
            "UPDATE deliveries SET error = ?2 WHERE id = ?1",
            params![id, error],
        )?;
        Ok(())
    }

    pub fn pending(&self, limit: usize) -> AppResult<Vec<Delivery>> {
        let conn = self.pool.get()?;
        let mut stmt = conn.prepare(
            "SELECT * FROM deliveries WHERE delivered_at IS NULL ORDER BY created_at LIMIT ?1",
        )?;
        let rows = stmt.query_map([limit as i64], |row| {
            let destination: String = row.get("destination")?;
            Ok(Delivery {
                id: row.get("id")?,
                destination: serde_json::from_str(&destination)
                    .unwrap_or_else(|_| Destination::new("unknown", "")),
                text: row.get("text")?,
                idempotency_key: row.get("idempotency_key")?,
                created_at: row.get("created_at")?,
                delivered_at: row.get("delivered_at")?,
                error: row.get("error")?,
            })
        })?;
        Ok(rows.collect::<Result<_, _>>()?)
    }
}

// ---------------------------------------------------------------------------
// Audit
// ---------------------------------------------------------------------------

#[derive(Clone)]
pub struct AuditLog {
    pool: DbPool,
}

#[derive(Debug, Clone)]
pub struct AuditEntry {
    pub id: String,
    pub at: String,
    pub actor: String,
    pub action: String,
    pub scope_id: Option<String>,
    pub target: Option<String>,
    pub detail: Option<serde_json::Value>,
    pub ok: bool,
}

impl AuditLog {
    pub fn new(pool: DbPool) -> Self {
        Self { pool }
    }

    /// Record an action. Auditing must never fail the operation it describes,
    /// so a write error is logged and swallowed.
    pub fn record(
        &self,
        actor: &str,
        action: &str,
        scope_id: Option<&ScopeId>,
        target: Option<&str>,
        detail: Option<serde_json::Value>,
        ok: bool,
    ) {
        let result = (|| -> AppResult<()> {
            let conn = self.pool.get()?;
            conn.execute(
                "INSERT INTO audit_log (id, at, actor, action, scope_id, target, detail, ok)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                params![
                    new_id(),
                    now_rfc3339(),
                    actor,
                    action,
                    scope_id.map(|s| s.as_str()),
                    target,
                    detail.as_ref().map(serde_json::to_string).transpose()?,
                    i64::from(ok),
                ],
            )?;
            Ok(())
        })();
        if let Err(e) = result {
            tracing::error!(error = %e, action, "failed to write audit entry");
        }
    }

    pub fn recent(&self, limit: usize) -> AppResult<Vec<AuditEntry>> {
        let conn = self.pool.get()?;
        let mut stmt =
            conn.prepare("SELECT * FROM audit_log ORDER BY at DESC, rowid DESC LIMIT ?1")?;
        let rows = stmt.query_map([limit as i64], |row| {
            let detail: Option<String> = row.get("detail")?;
            Ok(AuditEntry {
                id: row.get("id")?,
                at: row.get("at")?,
                actor: row.get("actor")?,
                action: row.get("action")?,
                scope_id: row.get("scope_id")?,
                target: row.get("target")?,
                detail: detail.as_deref().and_then(|d| serde_json::from_str(d).ok()),
                ok: row.get::<_, i64>("ok")? == 1,
            })
        })?;
        Ok(rows.collect::<Result<_, _>>()?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::test_pool;

    fn scope() -> ScopeId {
        ScopeId::personal("u1")
    }

    #[test]
    fn files_round_trip_with_a_guessed_mimetype() {
        let s = FileStore::new(test_pool());
        let artifact = s
            .put(&scope(), "notes.md", b"# hello", "out", Some("u1"))
            .unwrap();
        assert_eq!(artifact.mimetype, "text/markdown");
        assert_eq!(artifact.size_bytes, 7);
        assert_eq!(s.read(&artifact.id).unwrap(), b"# hello");
        assert_eq!(s.list_for_scopes(&[scope()]).unwrap().len(), 1);
        assert!(s
            .list_for_scopes(&[ScopeId::channel("eng")])
            .unwrap()
            .is_empty());
        assert!(s.delete(&artifact.id).unwrap());
        assert!(matches!(s.read(&artifact.id), Err(AppError::NotFound(_))));
    }

    #[test]
    fn unknown_extensions_fall_back_to_octet_stream() {
        assert_eq!(mime_from_name("a.png"), "image/png");
        assert_eq!(mime_from_name("a.weird"), "application/octet-stream");
        assert_eq!(mime_from_name("noextension"), "application/octet-stream");
        assert_eq!(mime_from_name("A.JSON"), "application/json");
    }

    #[test]
    fn keychain_lists_metadata_but_never_values() {
        let s = KeychainStore::new(test_pool());
        s.put(&scope(), "GITHUB_TOKEN", "ghp_secret", Some("CI"), "u1")
            .unwrap();
        let listed = s.list(&[scope()]).unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].key, "GITHUB_TOKEN");
        assert_eq!(listed[0].description.as_deref(), Some("CI"));
    }

    #[test]
    fn keychain_keys_must_be_environment_safe() {
        let s = KeychainStore::new(test_pool());
        for bad in [
            "",
            "has space",
            "has-dash",
            "1LEADING",
            "a;rm -rf /",
            "PATH$",
        ] {
            assert!(
                s.put(&scope(), bad, "v", None, "u1").is_err(),
                "{bad:?} allowed"
            );
        }
        assert!(s.put(&scope(), "_OK", "v", None, "u1").is_ok());
        assert!(s.put(&scope(), "OK_2", "v", None, "u1").is_ok());
    }

    #[test]
    fn a_narrower_scope_overrides_a_wider_ones_secret() {
        let s = KeychainStore::new(test_pool());
        let org = ScopeId::org("acme");
        s.put(&org, "TOKEN", "org-value", None, "admin").unwrap();
        s.put(&org, "ONLY_ORG", "shared", None, "admin").unwrap();
        s.put(&scope(), "TOKEN", "personal-value", None, "u1")
            .unwrap();

        // Widest first, narrowest last.
        let env = s.materialize(&[org, scope()]).unwrap();
        let token = env.iter().find(|(k, _)| k == "TOKEN").unwrap();
        assert_eq!(token.1, "personal-value");
        assert_eq!(env.len(), 2, "the org-only secret is still present");
    }

    #[test]
    fn masking_never_reveals_the_whole_secret() {
        let secret = "ghp_abcdefghijklmno";
        let masked = mask(secret);
        assert!(
            masked.ends_with("lmno"),
            "the last four stay legible: {masked}"
        );
        assert!(
            !masked.contains("ghp_abcdef"),
            "the head must be hidden: {masked}"
        );
        assert_eq!(
            masked.chars().filter(|c| *c == '•').count(),
            secret.len() - 4
        );

        // Short values reveal nothing at all.
        assert_eq!(mask("abcd"), "••••");
        assert_eq!(mask("ab"), "••");
        assert_eq!(mask(""), "•");

        // Long values do not leak their length beyond the cap.
        assert_eq!(mask(&"x".repeat(500)).chars().count(), 20);
        assert!(!mask("ghp_supersecretvalue").contains("supersecret"));
    }

    #[test]
    fn an_approval_resolves_exactly_once() {
        let s = ApprovalStore::new(test_pool());
        let approval = s
            .create(NewApproval {
                session_id: "s1",
                command: "rm -rf build",
                reason: "recursive delete",
                matched: Some("rm"),
                purpose: None,
                summary: None,
                approval_key: "rule:0",
            })
            .unwrap();

        assert_eq!(s.pending_for_session("s1").unwrap().len(), 1);
        assert!(s.resolve(&approval.request_id, true).unwrap());
        assert!(
            !s.resolve(&approval.request_id, true).unwrap(),
            "a double-click must not approve twice"
        );
        assert!(s.pending_for_session("s1").unwrap().is_empty());
    }

    #[test]
    fn standing_grants_are_scoped_to_a_session_or_to_always() {
        let s = ApprovalStore::new(test_pool());
        assert!(!s.is_granted("u1", "rule:0", "s1").unwrap());

        s.grant("u1", "rule:0", "session", Some("s1"), "rm -rf build")
            .unwrap();
        assert!(s.is_granted("u1", "rule:0", "s1").unwrap());
        assert!(
            !s.is_granted("u1", "rule:0", "s2").unwrap(),
            "a session grant must not leak into another session"
        );
        assert!(
            !s.is_granted("u2", "rule:0", "s1").unwrap(),
            "grants are per-actor"
        );

        s.grant("u1", "rule:1", "always", None, "git push -f")
            .unwrap();
        assert!(s.is_granted("u1", "rule:1", "any-session").unwrap());

        assert_eq!(s.list_grants("u1").unwrap().len(), 2);
        assert_eq!(s.revoke_grants("u1", "rule:1").unwrap(), 1);
        assert!(!s.is_granted("u1", "rule:1", "any-session").unwrap());
    }

    #[test]
    fn deliveries_are_idempotent_per_key() {
        let s = DeliveryStore::new(test_pool());
        let destination = Destination::new("telegram", "12345");
        let first = s
            .enqueue(&destination, "hello", "cron:1:2026-08-01")
            .unwrap();
        assert!(first.is_some());
        assert!(
            s.enqueue(&destination, "hello", "cron:1:2026-08-01")
                .unwrap()
                .is_none(),
            "a retried fire must not double-post"
        );
        assert_eq!(s.pending(10).unwrap().len(), 1);

        s.mark_delivered(&first.unwrap()).unwrap();
        assert!(s.pending(10).unwrap().is_empty());
    }

    #[test]
    fn a_failed_delivery_stays_pending_with_its_error() {
        let s = DeliveryStore::new(test_pool());
        let id = s
            .enqueue(&Destination::new("telegram", "1"), "hi", "k1")
            .unwrap()
            .unwrap();
        s.mark_failed(&id, "429 Too Many Requests").unwrap();
        let pending = s.pending(10).unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].error.as_deref(), Some("429 Too Many Requests"));
    }

    #[test]
    fn audit_entries_are_recorded_newest_first() {
        let s = AuditLog::new(test_pool());
        s.record("u1", "cron.create", Some(&scope()), Some("c1"), None, true);
        s.record(
            "u1",
            "execute.denied",
            Some(&scope()),
            Some("mkfs"),
            Some(serde_json::json!({"reason": "destructive"})),
            false,
        );
        let recent = s.recent(10).unwrap();
        assert_eq!(recent.len(), 2);
        assert_eq!(recent[0].action, "execute.denied");
        assert!(!recent[0].ok);
        assert_eq!(recent[0].detail.as_ref().unwrap()["reason"], "destructive");
    }
}

// ---------------------------------------------------------------------------
// Slack event dedupe
// ---------------------------------------------------------------------------

/// One row per Slack event id.
///
/// Slack redelivers an event when an ack is slow or lost, and Socket Mode
/// redelivers on reconnect. Claiming the id is what turns a retry into a no-op
/// instead of a second turn — the same pattern as `cron_fires`.
#[derive(Clone)]
pub struct SlackDedupeStore {
    pool: DbPool,
}

impl SlackDedupeStore {
    pub fn new(pool: DbPool) -> Self {
        Self { pool }
    }

    /// Claim an event id. `true` means this caller is the first to see it.
    pub fn claim(&self, event_id: &str) -> AppResult<bool> {
        let conn = self.pool.get()?;
        Ok(conn.execute(
            "INSERT INTO slack_event_dedupe (event_id, seen_at) VALUES (?1, ?2)
             ON CONFLICT(event_id) DO NOTHING",
            params![event_id, now_rfc3339()],
        )? > 0)
    }

    /// Drop rows older than `older_than_secs`. Slack does not retry for
    /// anywhere near that long, so keeping them forever only grows the table.
    pub fn sweep(&self, older_than_secs: i64) -> AppResult<usize> {
        let cutoff = (chrono::Utc::now() - chrono::Duration::seconds(older_than_secs.max(60)))
            .to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
        let conn = self.pool.get()?;
        Ok(conn.execute(
            "DELETE FROM slack_event_dedupe WHERE seen_at < ?1",
            [cutoff],
        )?)
    }
}

#[cfg(test)]
mod slack_dedupe_tests {
    use super::*;
    use crate::db::test_pool;

    #[test]
    fn an_event_id_can_only_be_claimed_once() {
        let s = SlackDedupeStore::new(test_pool());
        assert!(s.claim("evt_1").unwrap());
        assert!(
            !s.claim("evt_1").unwrap(),
            "a redelivery must not win the claim"
        );
        assert!(s.claim("evt_2").unwrap());
    }

    #[test]
    fn sweeping_removes_old_rows_but_keeps_recent_ones() {
        let s = SlackDedupeStore::new(test_pool());
        s.claim("recent").unwrap();
        s.claim("old").unwrap();
        s.pool
            .get()
            .unwrap()
            .execute(
                "UPDATE slack_event_dedupe SET seen_at = '2000-01-01T00:00:00Z' WHERE event_id = 'old'",
                [],
            )
            .unwrap();

        assert_eq!(s.sweep(3600).unwrap(), 1);
        assert!(!s.claim("recent").unwrap(), "the recent claim must survive");
        assert!(s.claim("old").unwrap(), "the swept id is claimable again");
    }
}
