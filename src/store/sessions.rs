//! Sessions and the append-only entry log.

use rusqlite::{params, Connection, Row};

use crate::db::{new_id, now_rfc3339, DbPool};
use crate::error::{AppError, AppResult};
use crate::types::{EntryType, NewEntry, ScopeId, Session, SessionEntry, SessionType};

#[derive(Clone)]
pub struct SessionStore {
    pool: DbPool,
}

fn session_from_row(row: &Row<'_>) -> rusqlite::Result<Session> {
    Ok(Session {
        id: row.get("id")?,
        session_type: SessionType::parse(&row.get::<_, String>("type")?),
        scope_id: ScopeId::from_raw(row.get::<_, String>("scope_id")?),
        thread_ref: row.get("thread_ref")?,
        surface: row.get("surface")?,
        channel_name: row.get("channel_name")?,
        title: row.get("title")?,
        archived: row.get::<_, i64>("archived")? == 1,
        pinned: row.get::<_, i64>("pinned")? == 1,
        color: row.get("color")?,
        created_at: row.get("created_at")?,
        last_activity_at: row.get("last_activity_at")?,
    })
}

fn entry_from_row(row: &Row<'_>) -> rusqlite::Result<SessionEntry> {
    let raw: String = row.get("payload")?;
    let type_str: String = row.get("type")?;
    Ok(SessionEntry {
        session_id: row.get("session_id")?,
        seq: row.get("seq")?,
        parent_seq: row.get("parent_seq")?,
        // An unknown type from a newer schema degrades to `system` rather than
        // failing the whole history load.
        entry_type: EntryType::parse(&type_str).unwrap_or(EntryType::System),
        payload: serde_json::from_str(&raw).unwrap_or(serde_json::Value::Null),
        scope_label: ScopeId::from_raw(row.get::<_, String>("scope_label")?),
        created_at: row.get("created_at")?,
    })
}

impl SessionStore {
    pub fn new(pool: DbPool) -> Self {
        Self { pool }
    }

    /// Find the session for a thread, or open one. `(surface, thread_ref)` is
    /// unique, so a Telegram chat and a web thread never collide.
    pub fn ensure(
        &self,
        surface: &str,
        thread_ref: &str,
        scope_id: &ScopeId,
        session_type: SessionType,
        channel_name: Option<&str>,
    ) -> AppResult<Session> {
        let conn = self.pool.get()?;
        if let Some(session) = Self::find_on(&conn, surface, thread_ref)? {
            return Ok(session);
        }
        let now = now_rfc3339();
        let id = new_id();
        conn.execute(
            "INSERT INTO sessions
                (id, type, scope_id, thread_ref, surface, channel_name,
                 created_at, last_activity_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?7)
             ON CONFLICT(surface, thread_ref) DO NOTHING",
            params![
                id,
                session_type.as_str(),
                scope_id.as_str(),
                thread_ref,
                surface,
                channel_name,
                now,
            ],
        )?;
        // The conflict clause means another writer may have won the race; read
        // back rather than assuming the row we just built is the live one.
        Self::find_on(&conn, surface, thread_ref)?
            .ok_or_else(|| AppError::internal("session vanished immediately after insert"))
    }

    fn find_on(conn: &Connection, surface: &str, thread_ref: &str) -> AppResult<Option<Session>> {
        let mut stmt =
            conn.prepare("SELECT * FROM sessions WHERE surface = ?1 AND thread_ref = ?2")?;
        let mut rows = stmt.query_map(params![surface, thread_ref], session_from_row)?;
        Ok(rows.next().transpose()?)
    }

    pub fn get(&self, id: &str) -> AppResult<Option<Session>> {
        let conn = self.pool.get()?;
        let mut stmt = conn.prepare("SELECT * FROM sessions WHERE id = ?1")?;
        let mut rows = stmt.query_map([id], session_from_row)?;
        Ok(rows.next().transpose()?)
    }

    pub fn require(&self, id: &str) -> AppResult<Session> {
        self.get(id)?
            .ok_or_else(|| AppError::not_found(format!("session {id}")))
    }

    /// Sessions visible to a set of scopes, most recently active first.
    pub fn list_for_scopes(
        &self,
        scopes: &[ScopeId],
        include_archived: bool,
    ) -> AppResult<Vec<Session>> {
        if scopes.is_empty() {
            return Ok(Vec::new());
        }
        let conn = self.pool.get()?;
        let placeholders = vec!["?"; scopes.len()].join(",");
        let sql = format!(
            "SELECT * FROM sessions
             WHERE scope_id IN ({placeholders}) {}
             ORDER BY pinned DESC, last_activity_at DESC
             LIMIT 200",
            if include_archived {
                ""
            } else {
                "AND archived = 0"
            }
        );
        let mut stmt = conn.prepare(&sql)?;
        let owned: Vec<String> = scopes.iter().map(|s| s.as_str().to_string()).collect();
        let args: Vec<&dyn rusqlite::ToSql> =
            owned.iter().map(|s| s as &dyn rusqlite::ToSql).collect();
        let rows = stmt.query_map(args.as_slice(), session_from_row)?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    /// Append an entry, assigning the next sequence number.
    ///
    /// The read of `MAX(seq)` and the insert share one immediate transaction so
    /// two concurrent turns on the same session cannot be handed the same seq.
    pub fn append(&self, session_id: &str, entry: NewEntry) -> AppResult<SessionEntry> {
        let mut conn = self.pool.get()?;
        let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let seq: i64 = tx.query_row(
            "SELECT COALESCE(MAX(seq), -1) + 1 FROM session_entries WHERE session_id = ?1",
            [session_id],
            |r| r.get(0),
        )?;
        let now = now_rfc3339();
        let payload = serde_json::to_string(&entry.payload)?;
        tx.execute(
            "INSERT INTO session_entries
                (session_id, seq, parent_seq, type, payload, scope_label, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                session_id,
                seq,
                entry.parent_seq,
                entry.entry_type.as_str(),
                payload,
                entry.scope_label.as_str(),
                now,
            ],
        )?;
        tx.execute(
            "UPDATE sessions SET last_activity_at = ?2 WHERE id = ?1",
            params![session_id, now],
        )?;
        tx.commit()?;

        Ok(SessionEntry {
            session_id: session_id.to_string(),
            seq,
            parent_seq: entry.parent_seq,
            entry_type: entry.entry_type,
            payload: entry.payload,
            scope_label: entry.scope_label,
            created_at: now,
        })
    }

    /// Full transcript in sequence order.
    pub fn history(&self, session_id: &str) -> AppResult<Vec<SessionEntry>> {
        let conn = self.pool.get()?;
        let mut stmt =
            conn.prepare("SELECT * FROM session_entries WHERE session_id = ?1 ORDER BY seq")?;
        let rows = stmt.query_map([session_id], entry_from_row)?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    /// The most recent `limit` entries, still in ascending sequence order.
    pub fn recent_history(&self, session_id: &str, limit: usize) -> AppResult<Vec<SessionEntry>> {
        let conn = self.pool.get()?;
        let mut stmt = conn.prepare(
            "SELECT * FROM (
                 SELECT * FROM session_entries WHERE session_id = ?1
                 ORDER BY seq DESC LIMIT ?2
             ) ORDER BY seq",
        )?;
        let rows = stmt.query_map(params![session_id, limit as i64], entry_from_row)?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    /// Substring search across a set of scopes' transcripts.
    pub fn search(
        &self,
        scopes: &[ScopeId],
        query: &str,
        limit: usize,
    ) -> AppResult<Vec<SessionEntry>> {
        let trimmed = query.trim();
        if scopes.is_empty() || trimmed.is_empty() {
            return Ok(Vec::new());
        }
        let conn = self.pool.get()?;
        let placeholders = vec!["?"; scopes.len()].join(",");
        let sql = format!(
            "SELECT e.* FROM session_entries e
             JOIN sessions s ON s.id = e.session_id
             WHERE s.scope_id IN ({placeholders})
               AND e.type IN ('user','assistant')
               AND lower(e.payload) LIKE ?{}
             ORDER BY e.created_at DESC
             LIMIT ?{}",
            scopes.len() + 1,
            scopes.len() + 2
        );
        let mut stmt = conn.prepare(&sql)?;
        let pattern = format!("%{}%", trimmed.to_lowercase());
        let owned: Vec<String> = scopes.iter().map(|s| s.as_str().to_string()).collect();
        let mut args: Vec<&dyn rusqlite::ToSql> =
            owned.iter().map(|s| s as &dyn rusqlite::ToSql).collect();
        args.push(&pattern);
        let limit = limit as i64;
        args.push(&limit);
        let rows = stmt.query_map(args.as_slice(), entry_from_row)?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    pub fn set_title(&self, session_id: &str, title: &str) -> AppResult<()> {
        let conn = self.pool.get()?;
        conn.execute(
            "UPDATE sessions SET title = ?2 WHERE id = ?1",
            params![session_id, title],
        )?;
        Ok(())
    }

    pub fn set_archived(&self, session_id: &str, archived: bool) -> AppResult<()> {
        let conn = self.pool.get()?;
        conn.execute(
            "UPDATE sessions SET archived = ?2 WHERE id = ?1",
            params![session_id, i64::from(archived)],
        )?;
        Ok(())
    }

    pub fn set_pinned(&self, session_id: &str, pinned: bool) -> AppResult<()> {
        let conn = self.pool.get()?;
        conn.execute(
            "UPDATE sessions SET pinned = ?2 WHERE id = ?1",
            params![session_id, i64::from(pinned)],
        )?;
        Ok(())
    }

    pub fn add_participant(&self, session_id: &str, principal_id: &str) -> AppResult<()> {
        let conn = self.pool.get()?;
        conn.execute(
            "INSERT INTO participants (session_id, principal_id, joined_at)
             VALUES (?1, ?2, ?3) ON CONFLICT DO NOTHING",
            params![session_id, principal_id, now_rfc3339()],
        )?;
        Ok(())
    }

    pub fn participants(&self, session_id: &str) -> AppResult<Vec<String>> {
        let conn = self.pool.get()?;
        let mut stmt = conn.prepare(
            "SELECT principal_id FROM participants WHERE session_id = ?1 ORDER BY joined_at",
        )?;
        let rows = stmt.query_map([session_id], |r| r.get(0))?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    pub fn count(&self) -> AppResult<i64> {
        let conn = self.pool.get()?;
        Ok(conn.query_row("SELECT COUNT(*) FROM sessions", [], |r| r.get(0))?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::test_pool;

    fn store() -> SessionStore {
        SessionStore::new(test_pool())
    }

    fn scope() -> ScopeId {
        ScopeId::personal("u1")
    }

    #[test]
    fn ensure_is_idempotent_per_surface_and_thread() {
        let s = store();
        let a = s
            .ensure("web", "t1", &scope(), SessionType::Dm, None)
            .unwrap();
        let b = s
            .ensure("web", "t1", &scope(), SessionType::Dm, None)
            .unwrap();
        assert_eq!(a.id, b.id);

        // Same thread ref on a different surface is a different session.
        let c = s
            .ensure("telegram", "t1", &scope(), SessionType::Dm, None)
            .unwrap();
        assert_ne!(a.id, c.id);
        assert_eq!(s.count().unwrap(), 2);
    }

    #[test]
    fn entries_get_dense_sequence_numbers_and_bump_activity() {
        let s = store();
        let session = s
            .ensure("web", "t1", &scope(), SessionType::Dm, None)
            .unwrap();
        for i in 0..3 {
            let e = s
                .append(
                    &session.id,
                    NewEntry::text(EntryType::User, scope(), format!("msg {i}")),
                )
                .unwrap();
            assert_eq!(e.seq, i);
        }
        let history = s.history(&session.id).unwrap();
        assert_eq!(history.len(), 3);
        assert_eq!(history[2].text(), "msg 2");
        assert!(s.get(&session.id).unwrap().unwrap().last_activity_at >= session.created_at);
    }

    #[test]
    fn tool_results_link_back_to_their_call() {
        let s = store();
        let session = s
            .ensure("web", "t1", &scope(), SessionType::Dm, None)
            .unwrap();
        let call = s
            .append(
                &session.id,
                NewEntry::new(
                    EntryType::ToolCall,
                    scope(),
                    serde_json::json!({"tool": "execute", "args": {"command": "ls"}}),
                ),
            )
            .unwrap();
        let result = s
            .append(
                &session.id,
                NewEntry::text(EntryType::ToolResult, scope(), "a.txt").with_parent(call.seq),
            )
            .unwrap();
        assert_eq!(result.parent_seq, Some(call.seq));

        let loaded = s.history(&session.id).unwrap();
        assert_eq!(loaded[1].parent_seq, Some(0));
        assert_eq!(loaded[0].entry_type, EntryType::ToolCall);
    }

    #[test]
    fn recent_history_returns_the_tail_in_ascending_order() {
        let s = store();
        let session = s
            .ensure("web", "t1", &scope(), SessionType::Dm, None)
            .unwrap();
        for i in 0..10 {
            s.append(
                &session.id,
                NewEntry::text(EntryType::User, scope(), format!("m{i}")),
            )
            .unwrap();
        }
        let tail = s.recent_history(&session.id, 3).unwrap();
        assert_eq!(tail.len(), 3);
        assert_eq!(tail[0].text(), "m7");
        assert_eq!(tail[2].text(), "m9");
    }

    #[test]
    fn listing_is_scoped_and_hides_archived_by_default() {
        let s = store();
        let mine = s
            .ensure("web", "t1", &scope(), SessionType::Dm, None)
            .unwrap();
        let theirs = s
            .ensure("web", "t2", &ScopeId::personal("u2"), SessionType::Dm, None)
            .unwrap();

        let listed = s.list_for_scopes(&[scope()], false).unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].id, mine.id);

        s.set_archived(&mine.id, true).unwrap();
        assert!(s.list_for_scopes(&[scope()], false).unwrap().is_empty());
        assert_eq!(s.list_for_scopes(&[scope()], true).unwrap().len(), 1);

        let both = s
            .list_for_scopes(&[scope(), ScopeId::personal("u2")], true)
            .unwrap();
        assert_eq!(both.len(), 2);
        assert!(both.iter().any(|x| x.id == theirs.id));

        assert!(s.list_for_scopes(&[], true).unwrap().is_empty());
    }

    #[test]
    fn search_stays_inside_the_given_scopes() {
        let s = store();
        let mine = s
            .ensure("web", "t1", &scope(), SessionType::Dm, None)
            .unwrap();
        let other_scope = ScopeId::personal("u2");
        let theirs = s
            .ensure("web", "t2", &other_scope, SessionType::Dm, None)
            .unwrap();
        s.append(
            &mine.id,
            NewEntry::text(EntryType::User, scope(), "the quarterly Roadmap"),
        )
        .unwrap();
        s.append(
            &theirs.id,
            NewEntry::text(EntryType::User, other_scope.clone(), "secret roadmap"),
        )
        .unwrap();

        let hits = s.search(&[scope()], "roadmap", 10).unwrap();
        assert_eq!(hits.len(), 1, "must not leak the other scope's transcript");
        assert_eq!(hits[0].session_id, mine.id);

        // Case-insensitive.
        assert_eq!(s.search(&[scope()], "ROADMAP", 10).unwrap().len(), 1);
        assert!(s.search(&[scope()], "   ", 10).unwrap().is_empty());
        assert!(s.search(&[], "roadmap", 10).unwrap().is_empty());
    }

    #[test]
    fn search_ignores_tool_traffic() {
        let s = store();
        let session = s
            .ensure("web", "t1", &scope(), SessionType::Dm, None)
            .unwrap();
        s.append(
            &session.id,
            NewEntry::text(EntryType::ToolResult, scope(), "roadmap.txt"),
        )
        .unwrap();
        assert!(s.search(&[scope()], "roadmap", 10).unwrap().is_empty());
    }

    #[test]
    fn participants_are_recorded_once() {
        let s = store();
        let session = s
            .ensure("web", "t1", &scope(), SessionType::Dm, None)
            .unwrap();
        s.add_participant(&session.id, "u1").unwrap();
        s.add_participant(&session.id, "u1").unwrap();
        s.add_participant(&session.id, "u2").unwrap();
        assert_eq!(s.participants(&session.id).unwrap().len(), 2);
    }

    #[test]
    fn require_reports_a_missing_session_as_not_found() {
        let s = store();
        let err = s.require("nope").unwrap_err();
        assert!(matches!(err, AppError::NotFound(_)), "got {err:?}");
    }
}
