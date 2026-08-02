//! Principals, channels, scope configuration and org settings.
//!
//! Together these answer "who is this, what may they reach, and how is that
//! scope configured" — the inputs [`crate::resolution`] composes into a turn.

use rusqlite::{params, Row};

use crate::db::{now_rfc3339, DbPool};
use crate::error::{AppError, AppResult};
use crate::policy::{CommandPolicy, SecurityPosture};
use crate::types::{Principal, PrincipalKind, ScopeId, ScopeKind};

#[derive(Clone)]
pub struct DirectoryStore {
    pool: DbPool,
}

#[derive(Debug, Clone)]
pub struct Channel {
    pub id: String,
    pub name: String,
    pub kind: String,
    pub is_private: bool,
    pub created_at: String,
}

#[derive(Debug, Clone)]
pub struct Group {
    pub id: String,
    pub name: String,
    pub participant_key: String,
    pub created_by: String,
    pub created_at: String,
}

#[derive(Debug, Clone)]
pub struct ConnectorIdentity {
    pub surface: String,
    pub external_id: String,
    pub principal_id: String,
    pub label: Option<String>,
    pub created_at: String,
}

#[derive(Debug, Clone)]
pub struct ConnectorChannel {
    pub surface: String,
    pub external_id: String,
    pub scope_id: String,
    pub label: Option<String>,
    pub created_at: String,
}

/// Per-scope overrides. Every field is optional: an absent value inherits the
/// org floor.
#[derive(Debug, Clone, Default)]
pub struct ScopeConfig {
    pub id: ScopeId,
    pub title: Option<String>,
    pub security_posture: Option<SecurityPosture>,
    pub command_policy: Option<CommandPolicy>,
    pub memory_recall: Option<String>,
    pub memory_capture: Option<String>,
    pub system_prompt: Option<String>,
}

fn principal_from_row(row: &Row<'_>) -> rusqlite::Result<Principal> {
    let teams: String = row.get("team_ids")?;
    Ok(Principal {
        id: row.get("id")?,
        kind: PrincipalKind::parse(&row.get::<_, String>("kind")?),
        display_name: row.get("display_name")?,
        email: row.get("email")?,
        team_ids: serde_json::from_str(&teams).unwrap_or_default(),
        active: row.get::<_, i64>("active")? == 1,
        created_at: row.get("created_at")?,
    })
}

fn channel_from_row(row: &Row<'_>) -> rusqlite::Result<Channel> {
    Ok(Channel {
        id: row.get("id")?,
        name: row.get("name")?,
        kind: row.get("kind")?,
        is_private: row.get::<_, i64>("is_private")? == 1,
        created_at: row.get("created_at")?,
    })
}

impl DirectoryStore {
    pub fn new(pool: DbPool) -> Self {
        Self { pool }
    }

    // -- principals ---------------------------------------------------------

    /// Insert or update a principal, keeping the original `created_at`.
    pub fn upsert_principal(
        &self,
        id: &str,
        kind: PrincipalKind,
        display_name: Option<&str>,
        email: Option<&str>,
    ) -> AppResult<Principal> {
        let conn = self.pool.get()?;
        conn.execute(
            "INSERT INTO principals (id, kind, display_name, email, team_ids, active, created_at)
             VALUES (?1, ?2, ?3, ?4, '[]', 1, ?5)
             ON CONFLICT(id) DO UPDATE SET
                kind = excluded.kind,
                display_name = COALESCE(excluded.display_name, principals.display_name),
                email = COALESCE(excluded.email, principals.email)",
            params![id, kind.as_str(), display_name, email, now_rfc3339()],
        )?;
        self.require_principal(id)
    }

    pub fn principal(&self, id: &str) -> AppResult<Option<Principal>> {
        let conn = self.pool.get()?;
        let mut stmt = conn.prepare("SELECT * FROM principals WHERE id = ?1")?;
        let mut rows = stmt.query_map([id], principal_from_row)?;
        Ok(rows.next().transpose()?)
    }

    pub fn require_principal(&self, id: &str) -> AppResult<Principal> {
        self.principal(id)?
            .ok_or_else(|| AppError::not_found(format!("principal {id}")))
    }

    /// Look a principal up by email address, case-insensitively. This is how
    /// a magic link resolves to a person.
    pub fn principal_by_email(&self, email: &str) -> AppResult<Option<Principal>> {
        let conn = self.pool.get()?;
        let mut stmt =
            conn.prepare("SELECT * FROM principals WHERE lower(email) = lower(?1) LIMIT 1")?;
        let mut rows = stmt.query_map([email.trim()], principal_from_row)?;
        Ok(rows.next().transpose()?)
    }

    pub fn list_principals(&self) -> AppResult<Vec<Principal>> {
        let conn = self.pool.get()?;
        let mut stmt = conn.prepare("SELECT * FROM principals ORDER BY display_name, id")?;
        let rows = stmt.query_map([], principal_from_row)?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    pub fn set_active(&self, id: &str, active: bool) -> AppResult<()> {
        let conn = self.pool.get()?;
        conn.execute(
            "UPDATE principals SET active = ?2 WHERE id = ?1",
            params![id, i64::from(active)],
        )?;
        Ok(())
    }

    // -- channels -----------------------------------------------------------

    pub fn upsert_channel(
        &self,
        id: &str,
        name: &str,
        kind: &str,
        is_private: bool,
    ) -> AppResult<()> {
        let conn = self.pool.get()?;
        conn.execute(
            "INSERT INTO directory_channels (id, name, kind, is_private, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT(id) DO UPDATE SET
                name = excluded.name, kind = excluded.kind, is_private = excluded.is_private",
            params![id, name, kind, i64::from(is_private), now_rfc3339()],
        )?;
        Ok(())
    }

    pub fn list_channels(&self) -> AppResult<Vec<Channel>> {
        let conn = self.pool.get()?;
        let mut stmt = conn.prepare("SELECT * FROM directory_channels ORDER BY name")?;
        let rows = stmt.query_map([], channel_from_row)?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    pub fn add_channel_member(&self, channel_id: &str, principal_id: &str) -> AppResult<()> {
        let conn = self.pool.get()?;
        conn.execute(
            "INSERT INTO directory_channel_members (channel_id, principal_id)
             VALUES (?1, ?2) ON CONFLICT DO NOTHING",
            params![channel_id, principal_id],
        )?;
        Ok(())
    }

    pub fn channel_members(&self, channel_id: &str) -> AppResult<Vec<String>> {
        let conn = self.pool.get()?;
        let mut stmt = conn
            .prepare("SELECT principal_id FROM directory_channel_members WHERE channel_id = ?1")?;
        let rows = stmt.query_map([channel_id], |r| r.get(0))?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    /// Channels a principal belongs to, as scope ids.
    pub fn reachable_channel_scopes(&self, principal_id: &str) -> AppResult<Vec<ScopeId>> {
        let conn = self.pool.get()?;
        let mut stmt = conn.prepare(
            "SELECT c.id FROM directory_channels c
             JOIN directory_channel_members m ON m.channel_id = c.id
             WHERE m.principal_id = ?1
             ORDER BY c.name",
        )?;
        let rows = stmt.query_map([principal_id], |r| r.get::<_, String>(0))?;
        Ok(rows
            .collect::<Result<Vec<_>, _>>()?
            .into_iter()
            .map(|id| ScopeId::channel(&id))
            .collect())
    }

    /// Whether a principal may read a shared scope. Personal scopes belong to
    /// exactly one person; channel and group scopes go by membership; the org
    /// scope is readable by every internal principal.
    pub fn entitled(&self, principal_id: &str, scope: &ScopeId) -> AppResult<bool> {
        match scope.kind() {
            Some(ScopeKind::Personal) => Ok(scope.reference() == principal_id),
            Some(ScopeKind::Channel) => Ok(self
                .channel_members(scope.reference())?
                .iter()
                .any(|m| m == principal_id)),
            Some(ScopeKind::Group) => Ok(self
                .group_members(scope.reference())?
                .iter()
                .any(|m| m == principal_id)),
            Some(ScopeKind::Org) | Some(ScopeKind::Team) => Ok(self
                .principal(principal_id)?
                .is_some_and(|p| p.kind == PrincipalKind::Internal && p.active)),
            None => Ok(false),
        }
    }

    pub fn remove_channel_member(&self, channel_id: &str, principal_id: &str) -> AppResult<bool> {
        let conn = self.pool.get()?;
        Ok(conn.execute(
            "DELETE FROM directory_channel_members WHERE channel_id = ?1 AND principal_id = ?2",
            params![channel_id, principal_id],
        )? > 0)
    }

    pub fn delete_channel(&self, channel_id: &str) -> AppResult<bool> {
        let conn = self.pool.get()?;
        Ok(conn.execute("DELETE FROM directory_channels WHERE id = ?1", [channel_id])? > 0)
    }

    /// Channel ids are used as scope refs and as connector bindings, so they are
    /// restricted to a slug alphabet rather than accepting free text.
    pub fn normalize_channel_id(raw: &str) -> AppResult<String> {
        let slug: String = raw
            .trim()
            .chars()
            .map(|c| {
                if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                    c.to_ascii_lowercase()
                } else {
                    '-'
                }
            })
            .collect();
        let slug = slug.trim_matches('-').to_string();
        if slug.is_empty() || slug.len() > 64 {
            return Err(AppError::bad_request(format!(
                "invalid group name {raw:?}: use letters, digits, '-' and '_' (max 64 chars)"
            )));
        }
        Ok(slug)
    }

    // -- groups -------------------------------------------------------------

    /// Upstream's `groupParticipantsKey`: sorted, deduped, comma-joined.
    ///
    /// This is what makes a multi-person conversation resolve to the same group
    /// every time — the same three people in any order, on any surface, key to
    /// the same string.
    pub fn participant_key(participants: &[String]) -> String {
        let mut unique: Vec<&str> = participants
            .iter()
            .map(|p| p.trim())
            .filter(|p| !p.is_empty())
            .collect();
        unique.sort_unstable();
        unique.dedup();
        unique.join(",")
    }

    /// Create or update a group over a set of participants.
    ///
    /// Keyed by the participant set, so calling this twice with the same people
    /// updates the same group rather than making a second one.
    pub fn upsert_group(
        &self,
        id: &str,
        name: &str,
        participants: &[String],
        created_by: &str,
    ) -> AppResult<String> {
        let id = Self::normalize_channel_id(id)?;
        if participants.len() < 2 {
            return Err(AppError::bad_request("a group needs at least two people"));
        }
        for principal in participants {
            self.require_principal(principal)?;
        }
        let key = Self::participant_key(participants);

        let mut conn = self.pool.get()?;
        let tx = conn.transaction()?;

        // An existing group over exactly these people wins, so the same set
        // does not accumulate duplicates under different names.
        let existing: Option<String> = {
            let mut stmt =
                tx.prepare("SELECT id FROM directory_groups WHERE participant_key = ?1")?;
            let mut rows = stmt.query_map([&key], |r| r.get::<_, String>(0))?;
            rows.next().transpose()?
        };
        let group_id = existing.unwrap_or(id);

        tx.execute(
            "INSERT INTO directory_groups (id, name, participant_key, created_by, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT(id) DO UPDATE SET name = excluded.name,
                                           participant_key = excluded.participant_key",
            params![group_id, name, key, created_by, now_rfc3339()],
        )?;
        tx.execute(
            "DELETE FROM directory_group_members WHERE group_id = ?1",
            [&group_id],
        )?;
        for principal in participants {
            tx.execute(
                "INSERT INTO directory_group_members (group_id, principal_id)
                 VALUES (?1, ?2) ON CONFLICT DO NOTHING",
                params![group_id, principal],
            )?;
        }
        tx.commit()?;
        Ok(group_id)
    }

    /// The group over exactly this participant set, if one exists.
    pub fn resolve_group_by_participants(
        &self,
        participants: &[String],
    ) -> AppResult<Option<String>> {
        let key = Self::participant_key(participants);
        let conn = self.pool.get()?;
        let mut stmt =
            conn.prepare("SELECT id FROM directory_groups WHERE participant_key = ?1")?;
        let mut rows = stmt.query_map([&key], |r| r.get(0))?;
        Ok(rows.next().transpose()?)
    }

    pub fn list_groups(&self) -> AppResult<Vec<Group>> {
        let conn = self.pool.get()?;
        let mut stmt = conn.prepare("SELECT * FROM directory_groups ORDER BY name")?;
        let rows = stmt.query_map([], |r| {
            Ok(Group {
                id: r.get("id")?,
                name: r.get("name")?,
                participant_key: r.get("participant_key")?,
                created_by: r.get("created_by")?,
                created_at: r.get("created_at")?,
            })
        })?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    pub fn group_members(&self, group_id: &str) -> AppResult<Vec<String>> {
        let conn = self.pool.get()?;
        let mut stmt = conn
            .prepare("SELECT principal_id FROM directory_group_members WHERE group_id = ?1 ORDER BY principal_id")?;
        let rows = stmt.query_map([group_id], |r| r.get(0))?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    /// Groups a principal belongs to, as scope ids.
    pub fn reachable_group_scopes(&self, principal_id: &str) -> AppResult<Vec<ScopeId>> {
        let conn = self.pool.get()?;
        let mut stmt = conn.prepare(
            "SELECT g.id FROM directory_groups g
             JOIN directory_group_members m ON m.group_id = g.id
             WHERE m.principal_id = ?1
             ORDER BY g.name",
        )?;
        let rows = stmt.query_map([principal_id], |r| r.get::<_, String>(0))?;
        Ok(rows
            .collect::<Result<Vec<_>, _>>()?
            .into_iter()
            .map(|id| ScopeId::new(ScopeKind::Group, &id))
            .collect())
    }

    pub fn delete_group(&self, group_id: &str) -> AppResult<bool> {
        let conn = self.pool.get()?;
        Ok(conn.execute("DELETE FROM directory_groups WHERE id = ?1", [group_id])? > 0)
    }

    // -- connector identities -----------------------------------------------

    /// Bind an external account to a principal, so a Telegram or Slack message
    /// from them runs as that person rather than as a guest.
    pub fn link_identity(
        &self,
        surface: &str,
        external_id: &str,
        principal_id: &str,
        label: Option<&str>,
        linked_by: &str,
    ) -> AppResult<()> {
        if external_id.trim().is_empty() {
            return Err(AppError::bad_request("an external id is required"));
        }
        self.require_principal(principal_id)?;
        let conn = self.pool.get()?;
        conn.execute(
            "INSERT INTO connector_identities
                (surface, external_id, principal_id, label, linked_by, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)
             ON CONFLICT(surface, external_id) DO UPDATE SET
                principal_id = excluded.principal_id,
                label = excluded.label,
                linked_by = excluded.linked_by",
            params![
                surface,
                external_id.trim(),
                principal_id,
                label.map(str::trim).filter(|l| !l.is_empty()),
                linked_by,
                now_rfc3339(),
            ],
        )?;
        Ok(())
    }

    pub fn unlink_identity(&self, surface: &str, external_id: &str) -> AppResult<bool> {
        let conn = self.pool.get()?;
        Ok(conn.execute(
            "DELETE FROM connector_identities WHERE surface = ?1 AND external_id = ?2",
            params![surface, external_id],
        )? > 0)
    }

    /// The principal an external account belongs to, if the admin linked it.
    pub fn identity_principal(
        &self,
        surface: &str,
        external_id: &str,
    ) -> AppResult<Option<String>> {
        let conn = self.pool.get()?;
        let mut stmt = conn.prepare(
            "SELECT principal_id FROM connector_identities WHERE surface = ?1 AND external_id = ?2",
        )?;
        let mut rows = stmt.query_map(params![surface, external_id], |r| r.get(0))?;
        Ok(rows.next().transpose()?)
    }

    pub fn list_identities(&self) -> AppResult<Vec<ConnectorIdentity>> {
        let conn = self.pool.get()?;
        let mut stmt = conn.prepare(
            "SELECT surface, external_id, principal_id, label, created_at
             FROM connector_identities ORDER BY surface, principal_id",
        )?;
        let rows = stmt.query_map([], |r| {
            Ok(ConnectorIdentity {
                surface: r.get(0)?,
                external_id: r.get(1)?,
                principal_id: r.get(2)?,
                label: r.get(3)?,
                created_at: r.get(4)?,
            })
        })?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    // -- connector channels -------------------------------------------------

    /// Point an external conversation at a scope that already exists, so a
    /// Telegram group, a Slack channel and the web UI share one memory.
    pub fn link_channel(
        &self,
        surface: &str,
        external_id: &str,
        scope: &ScopeId,
        label: Option<&str>,
        linked_by: &str,
    ) -> AppResult<()> {
        if external_id.trim().is_empty() {
            return Err(AppError::bad_request("an external chat id is required"));
        }
        if !scope.is_shared() {
            return Err(AppError::bad_request(
                "an external conversation can only be bound to a shared scope — a channel or a group",
            ));
        }
        let conn = self.pool.get()?;
        conn.execute(
            "INSERT INTO connector_channels
                (surface, external_id, scope_id, label, linked_by, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)
             ON CONFLICT(surface, external_id) DO UPDATE SET
                scope_id = excluded.scope_id,
                label = excluded.label,
                linked_by = excluded.linked_by",
            params![
                surface,
                external_id.trim(),
                scope.as_str(),
                label.map(str::trim).filter(|l| !l.is_empty()),
                linked_by,
                now_rfc3339(),
            ],
        )?;
        Ok(())
    }

    pub fn unlink_channel(&self, surface: &str, external_id: &str) -> AppResult<bool> {
        let conn = self.pool.get()?;
        Ok(conn.execute(
            "DELETE FROM connector_channels WHERE surface = ?1 AND external_id = ?2",
            params![surface, external_id],
        )? > 0)
    }

    /// The scope an external conversation is bound to, if any.
    pub fn channel_scope(&self, surface: &str, external_id: &str) -> AppResult<Option<ScopeId>> {
        let conn = self.pool.get()?;
        let mut stmt = conn.prepare(
            "SELECT scope_id FROM connector_channels WHERE surface = ?1 AND external_id = ?2",
        )?;
        let mut rows = stmt.query_map(params![surface, external_id], |r| r.get::<_, String>(0))?;
        Ok(rows.next().transpose()?.map(ScopeId::from_raw))
    }

    pub fn list_channel_links(&self) -> AppResult<Vec<ConnectorChannel>> {
        let conn = self.pool.get()?;
        let mut stmt = conn.prepare(
            "SELECT surface, external_id, scope_id, label, created_at
             FROM connector_channels ORDER BY surface, scope_id",
        )?;
        let rows = stmt.query_map([], |r| {
            Ok(ConnectorChannel {
                surface: r.get(0)?,
                external_id: r.get(1)?,
                scope_id: r.get(2)?,
                label: r.get(3)?,
                created_at: r.get(4)?,
            })
        })?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    // -- scope configuration ------------------------------------------------

    pub fn scope_config(&self, scope_id: &ScopeId) -> AppResult<Option<ScopeConfig>> {
        let conn = self.pool.get()?;
        let mut stmt = conn.prepare("SELECT * FROM scopes WHERE id = ?1")?;
        let mut rows = stmt.query_map([scope_id.as_str()], |row| {
            let policy_json: Option<String> = row.get("command_policy")?;
            let posture: Option<String> = row.get("security_posture")?;
            Ok(ScopeConfig {
                id: ScopeId::from_raw(row.get::<_, String>("id")?),
                title: row.get("title")?,
                // A posture that no longer parses is dropped, which inherits
                // the org floor — never silently loosens it.
                security_posture: posture.as_deref().and_then(SecurityPosture::parse),
                command_policy: policy_json
                    .as_deref()
                    .and_then(|j| serde_json::from_str::<serde_json::Value>(j).ok())
                    .and_then(|v| crate::policy::parse_command_policy(&v).ok()),
                memory_recall: row.get("memory_recall")?,
                memory_capture: row.get("memory_capture")?,
                system_prompt: row.get("system_prompt")?,
            })
        })?;
        Ok(rows.next().transpose()?)
    }

    pub fn put_scope_config(&self, config: &ScopeConfig) -> AppResult<()> {
        let conn = self.pool.get()?;
        let policy = config
            .command_policy
            .as_ref()
            .map(serde_json::to_string)
            .transpose()?;
        conn.execute(
            "INSERT INTO scopes
                (id, kind, ref, title, security_posture, command_policy,
                 memory_recall, memory_capture, system_prompt, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)
             ON CONFLICT(id) DO UPDATE SET
                title = excluded.title,
                security_posture = excluded.security_posture,
                command_policy = excluded.command_policy,
                memory_recall = excluded.memory_recall,
                memory_capture = excluded.memory_capture,
                system_prompt = excluded.system_prompt",
            params![
                config.id.as_str(),
                config.id.kind().map(|k| k.as_str()).unwrap_or("unknown"),
                config.id.reference(),
                config.title,
                config.security_posture.map(|p| p.as_str()),
                policy,
                config.memory_recall,
                config.memory_capture,
                config.system_prompt,
                now_rfc3339(),
            ],
        )?;
        Ok(())
    }

    pub fn list_scope_configs(&self) -> AppResult<Vec<ScopeId>> {
        let conn = self.pool.get()?;
        let mut stmt = conn.prepare("SELECT id FROM scopes ORDER BY id")?;
        let rows = stmt.query_map([], |r| Ok(ScopeId::from_raw(r.get::<_, String>(0)?)))?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    // -- settings -----------------------------------------------------------

    pub fn setting(&self, key: &str) -> AppResult<Option<String>> {
        let conn = self.pool.get()?;
        let mut stmt = conn.prepare("SELECT value FROM settings WHERE key = ?1")?;
        let mut rows = stmt.query_map([key], |r| r.get(0))?;
        Ok(rows.next().transpose()?)
    }

    pub fn put_setting(&self, key: &str, value: &str) -> AppResult<()> {
        let conn = self.pool.get()?;
        conn.execute(
            "INSERT INTO settings (key, value, updated_at) VALUES (?1, ?2, ?3)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at",
            params![key, value, now_rfc3339()],
        )?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::test_pool;
    use crate::policy::{default_org_policy, PolicyMode};

    fn store() -> DirectoryStore {
        DirectoryStore::new(test_pool())
    }

    #[test]
    fn principals_upsert_without_losing_created_at_or_fields() {
        let s = store();
        let a = s
            .upsert_principal(
                "u1",
                PrincipalKind::Internal,
                Some("Ada"),
                Some("ada@x.test"),
            )
            .unwrap();
        let b = s
            .upsert_principal("u1", PrincipalKind::Internal, None, None)
            .unwrap();
        assert_eq!(a.created_at, b.created_at);
        assert_eq!(
            b.display_name.as_deref(),
            Some("Ada"),
            "null must not clobber"
        );
        assert_eq!(b.email.as_deref(), Some("ada@x.test"));
        assert_eq!(s.list_principals().unwrap().len(), 1);
    }

    #[test]
    fn a_principals_personal_scope_is_theirs_alone() {
        let s = store();
        s.upsert_principal("u1", PrincipalKind::Internal, None, None)
            .unwrap();
        s.upsert_principal("u2", PrincipalKind::Internal, None, None)
            .unwrap();
        assert!(s.entitled("u1", &ScopeId::personal("u1")).unwrap());
        assert!(!s.entitled("u2", &ScopeId::personal("u1")).unwrap());
    }

    #[test]
    fn channel_entitlement_follows_membership() {
        let s = store();
        s.upsert_principal("u1", PrincipalKind::Internal, None, None)
            .unwrap();
        s.upsert_principal("u2", PrincipalKind::Internal, None, None)
            .unwrap();
        s.upsert_channel("eng", "eng", "channel", false).unwrap();
        s.add_channel_member("eng", "u1").unwrap();

        assert!(s.entitled("u1", &ScopeId::channel("eng")).unwrap());
        assert!(!s.entitled("u2", &ScopeId::channel("eng")).unwrap());
        assert_eq!(
            s.reachable_channel_scopes("u1").unwrap(),
            vec![ScopeId::channel("eng")]
        );
        assert!(s.reachable_channel_scopes("u2").unwrap().is_empty());
    }

    #[test]
    fn guests_and_deactivated_principals_cannot_reach_the_org_scope() {
        let s = store();
        s.upsert_principal("staff", PrincipalKind::Internal, None, None)
            .unwrap();
        s.upsert_principal("visitor", PrincipalKind::Guest, None, None)
            .unwrap();
        let org = ScopeId::org("acme");

        assert!(s.entitled("staff", &org).unwrap());
        assert!(!s.entitled("visitor", &org).unwrap());

        s.set_active("staff", false).unwrap();
        assert!(!s.entitled("staff", &org).unwrap());
    }

    #[test]
    fn an_unknown_principal_or_malformed_scope_is_not_entitled() {
        let s = store();
        assert!(!s.entitled("ghost", &ScopeId::org("acme")).unwrap());
        assert!(!s.entitled("ghost", &ScopeId::from_raw("garbage")).unwrap());
    }

    #[test]
    fn scope_config_round_trips_including_the_command_policy() {
        let s = store();
        let scope = ScopeId::channel("eng");
        s.put_scope_config(&ScopeConfig {
            id: scope.clone(),
            title: Some("Engineering".into()),
            security_posture: Some(SecurityPosture::Strict),
            command_policy: Some(default_org_policy()),
            memory_recall: Some("writable".into()),
            memory_capture: None,
            system_prompt: Some("Be terse.".into()),
        })
        .unwrap();

        let loaded = s.scope_config(&scope).unwrap().unwrap();
        assert_eq!(loaded.title.as_deref(), Some("Engineering"));
        assert_eq!(loaded.security_posture, Some(SecurityPosture::Strict));
        assert_eq!(loaded.memory_recall.as_deref(), Some("writable"));
        assert!(loaded.memory_capture.is_none());
        let policy = loaded.command_policy.unwrap();
        assert_eq!(policy.mode, PolicyMode::Denylist);
        assert_eq!(policy.rules.len(), default_org_policy().rules.len());
    }

    #[test]
    fn an_unparseable_stored_posture_inherits_rather_than_loosening() {
        let s = store();
        let scope = ScopeId::channel("eng");
        s.put_scope_config(&ScopeConfig {
            id: scope.clone(),
            ..Default::default()
        })
        .unwrap();
        s.pool
            .get()
            .unwrap()
            .execute(
                "UPDATE scopes SET security_posture = 'relaxed' WHERE id = ?1",
                [scope.as_str()],
            )
            .unwrap();
        assert_eq!(
            s.scope_config(&scope).unwrap().unwrap().security_posture,
            None
        );
    }

    #[test]
    fn an_unset_scope_has_no_config() {
        let s = store();
        assert!(s.scope_config(&ScopeId::channel("nope")).unwrap().is_none());
        assert!(s.list_scope_configs().unwrap().is_empty());
    }

    #[test]
    fn principals_are_findable_by_email_case_insensitively() {
        let s = store();
        s.upsert_principal("ada", PrincipalKind::Internal, None, Some("Ada@Acme.test"))
            .unwrap();
        assert_eq!(
            s.principal_by_email("ada@acme.test").unwrap().unwrap().id,
            "ada"
        );
        assert_eq!(
            s.principal_by_email("ADA@ACME.TEST").unwrap().unwrap().id,
            "ada"
        );
        assert!(s.principal_by_email("nobody@acme.test").unwrap().is_none());
    }

    #[test]
    fn settings_round_trip_and_overwrite() {
        let s = store();
        assert!(s.setting("telegram.offset").unwrap().is_none());
        s.put_setting("telegram.offset", "42").unwrap();
        s.put_setting("telegram.offset", "43").unwrap();
        assert_eq!(s.setting("telegram.offset").unwrap().as_deref(), Some("43"));
    }
}
