//! Sessions, login tokens and API keys.
//!
//! Every lookup is by hash: the caller supplies the token, this module hashes
//! it and matches. Nothing here can hand back a usable credential.

use rusqlite::params;

use super::{hash_token, API_KEY_PREFIX};
use crate::db::{new_id, now_rfc3339, DbPool};
use crate::error::{AppError, AppResult};
use crate::types::{Principal, PrincipalKind};

#[derive(Clone)]
pub struct AuthStore {
    pool: DbPool,
}

#[derive(Debug, Clone)]
pub struct ApiKeyRecord {
    pub id: String,
    pub prefix: String,
    pub principal_id: String,
    pub name: Option<String>,
    pub created_at: String,
    pub last_used_at: Option<String>,
    pub revoked_at: Option<String>,
}

#[derive(Debug, Clone)]
pub struct SessionRecord {
    pub principal_id: String,
    pub created_at: String,
    pub expires_at: String,
    pub last_seen_at: String,
    pub user_agent: Option<String>,
}

impl AuthStore {
    pub fn new(pool: DbPool) -> Self {
        Self { pool }
    }

    // -- login tokens -------------------------------------------------------

    /// Mint a one-time login token. Returns the raw token; only its hash is
    /// stored, so this is the single moment it exists in readable form.
    pub fn create_login_token(
        &self,
        email: &str,
        principal_id: &str,
        ttl_secs: i64,
    ) -> AppResult<String> {
        let token = super::generate_token();
        let now = chrono::Utc::now();
        let expires = now + chrono::Duration::seconds(ttl_secs.max(60));
        let conn = self.pool.get()?;
        conn.execute(
            "INSERT INTO auth_login_tokens
                (token_hash, email, principal_id, created_at, expires_at)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                hash_token(&token),
                email.trim().to_ascii_lowercase(),
                principal_id,
                rfc3339(now),
                rfc3339(expires),
            ],
        )?;
        Ok(token)
    }

    /// Consume a login token, returning the principal it was issued for.
    ///
    /// The update is conditional on the token still being unconsumed and
    /// unexpired, so following the same link twice — or racing two tabs —
    /// yields exactly one session.
    pub fn consume_login_token(&self, token: &str) -> AppResult<Option<String>> {
        let conn = self.pool.get()?;
        let hash = hash_token(token);
        let now = now_rfc3339();

        let changed = conn.execute(
            "UPDATE auth_login_tokens SET consumed_at = ?2
             WHERE token_hash = ?1 AND consumed_at IS NULL AND expires_at > ?2",
            params![hash, now],
        )?;
        if changed == 0 {
            return Ok(None);
        }

        let mut stmt =
            conn.prepare("SELECT principal_id FROM auth_login_tokens WHERE token_hash = ?1")?;
        let mut rows = stmt.query_map([&hash], |r| r.get::<_, String>(0))?;
        Ok(rows.next().transpose()?)
    }

    /// How many links were requested for this address recently — the rate
    /// limit that stops the login form being used as a mail cannon.
    pub fn recent_login_requests(&self, email: &str, within_secs: i64) -> AppResult<i64> {
        let since = rfc3339(chrono::Utc::now() - chrono::Duration::seconds(within_secs.max(1)));
        let conn = self.pool.get()?;
        Ok(conn.query_row(
            "SELECT COUNT(*) FROM auth_login_tokens WHERE email = ?1 AND created_at > ?2",
            params![email.trim().to_ascii_lowercase(), since],
            |r| r.get(0),
        )?)
    }

    // -- sessions -----------------------------------------------------------

    pub fn create_session(
        &self,
        principal_id: &str,
        ttl_secs: i64,
        user_agent: Option<&str>,
    ) -> AppResult<String> {
        let token = super::generate_token();
        let now = chrono::Utc::now();
        let conn = self.pool.get()?;
        conn.execute(
            "INSERT INTO auth_sessions
                (token_hash, principal_id, created_at, expires_at, last_seen_at, user_agent)
             VALUES (?1, ?2, ?3, ?4, ?3, ?5)",
            params![
                hash_token(&token),
                principal_id,
                rfc3339(now),
                rfc3339(now + chrono::Duration::seconds(ttl_secs.max(60))),
                user_agent.map(|ua| ua.chars().take(200).collect::<String>()),
            ],
        )?;
        Ok(token)
    }

    /// Resolve a session cookie to its principal, if the session is live and
    /// the principal is still active.
    pub fn principal_for_session(&self, token: &str) -> AppResult<Option<Principal>> {
        let conn = self.pool.get()?;
        let now = now_rfc3339();
        let principal = {
            let mut stmt = conn.prepare(
                "SELECT p.id, p.kind, p.display_name, p.email, p.team_ids, p.active, p.created_at
                 FROM auth_sessions s
                 JOIN principals p ON p.id = s.principal_id
                 WHERE s.token_hash = ?1 AND s.expires_at > ?2 AND p.active = 1",
            )?;
            let mut rows = stmt.query_map(params![hash_token(token), now], principal_from_row)?;
            rows.next().transpose()?
        };
        let Some(principal) = principal else {
            return Ok(None);
        };

        // Best-effort activity stamp; failing to record it must not fail the
        // request that was otherwise authenticated.
        if let Err(e) = conn.execute(
            "UPDATE auth_sessions SET last_seen_at = ?2 WHERE token_hash = ?1",
            params![hash_token(token), now],
        ) {
            tracing::debug!(error = %e, "could not stamp session activity");
        }
        Ok(Some(principal))
    }

    pub fn revoke_session(&self, token: &str) -> AppResult<bool> {
        let conn = self.pool.get()?;
        Ok(conn.execute(
            "DELETE FROM auth_sessions WHERE token_hash = ?1",
            [hash_token(token)],
        )? > 0)
    }

    pub fn revoke_all_sessions(&self, principal_id: &str) -> AppResult<usize> {
        let conn = self.pool.get()?;
        Ok(conn.execute(
            "DELETE FROM auth_sessions WHERE principal_id = ?1",
            [principal_id],
        )?)
    }

    pub fn sessions_for(&self, principal_id: &str) -> AppResult<Vec<SessionRecord>> {
        let conn = self.pool.get()?;
        let mut stmt = conn.prepare(
            "SELECT principal_id, created_at, expires_at, last_seen_at, user_agent
             FROM auth_sessions WHERE principal_id = ?1 AND expires_at > ?2
             ORDER BY last_seen_at DESC",
        )?;
        let rows = stmt.query_map(params![principal_id, now_rfc3339()], |r| {
            Ok(SessionRecord {
                principal_id: r.get(0)?,
                created_at: r.get(1)?,
                expires_at: r.get(2)?,
                last_seen_at: r.get(3)?,
                user_agent: r.get(4)?,
            })
        })?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    /// Drop expired sessions and consumed or expired login tokens.
    pub fn sweep_expired(&self) -> AppResult<usize> {
        let conn = self.pool.get()?;
        let now = now_rfc3339();
        let sessions = conn.execute("DELETE FROM auth_sessions WHERE expires_at <= ?1", [&now])?;
        let tokens = conn.execute(
            "DELETE FROM auth_login_tokens WHERE expires_at <= ?1 OR consumed_at IS NOT NULL",
            [&now],
        )?;
        Ok(sessions + tokens)
    }

    // -- API keys -----------------------------------------------------------

    /// Mint an API key. Returns the raw key, which is shown once and never
    /// recoverable afterwards.
    pub fn create_api_key(
        &self,
        principal_id: &str,
        name: Option<&str>,
    ) -> AppResult<(String, String)> {
        let key = super::generate_api_key();
        let id = new_id();
        let prefix: String = key.chars().take(API_KEY_PREFIX.len() + 6).collect();
        let conn = self.pool.get()?;
        conn.execute(
            "INSERT INTO api_keys (id, key_hash, prefix, principal_id, name, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                id,
                hash_token(&key),
                prefix,
                principal_id,
                name.map(str::trim).filter(|n| !n.is_empty()),
                now_rfc3339(),
            ],
        )?;
        Ok((id, key))
    }

    /// Resolve a bearer key to its principal, if the key is live and the
    /// principal is still active.
    pub fn principal_for_api_key(&self, key: &str) -> AppResult<Option<Principal>> {
        let conn = self.pool.get()?;
        let hash = hash_token(key);
        let principal = {
            let mut stmt = conn.prepare(
                "SELECT p.id, p.kind, p.display_name, p.email, p.team_ids, p.active, p.created_at
                 FROM api_keys k
                 JOIN principals p ON p.id = k.principal_id
                 WHERE k.key_hash = ?1 AND k.revoked_at IS NULL AND p.active = 1",
            )?;
            let mut rows = stmt.query_map([&hash], principal_from_row)?;
            rows.next().transpose()?
        };
        let Some(principal) = principal else {
            return Ok(None);
        };

        if let Err(e) = conn.execute(
            "UPDATE api_keys SET last_used_at = ?2 WHERE key_hash = ?1",
            params![hash, now_rfc3339()],
        ) {
            tracing::debug!(error = %e, "could not stamp API key use");
        }
        Ok(Some(principal))
    }

    pub fn list_api_keys(&self, principal_id: &str) -> AppResult<Vec<ApiKeyRecord>> {
        let conn = self.pool.get()?;
        let mut stmt = conn.prepare(
            "SELECT id, prefix, principal_id, name, created_at, last_used_at, revoked_at
             FROM api_keys WHERE principal_id = ?1 ORDER BY created_at DESC",
        )?;
        let rows = stmt.query_map([principal_id], |r| {
            Ok(ApiKeyRecord {
                id: r.get(0)?,
                prefix: r.get(1)?,
                principal_id: r.get(2)?,
                name: r.get(3)?,
                created_at: r.get(4)?,
                last_used_at: r.get(5)?,
                revoked_at: r.get(6)?,
            })
        })?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    /// Revoke a key. Scoped to its owner, so one principal cannot revoke
    /// another's by guessing an id.
    pub fn revoke_api_key(&self, id: &str, principal_id: &str) -> AppResult<bool> {
        let conn = self.pool.get()?;
        Ok(conn.execute(
            "UPDATE api_keys SET revoked_at = ?3
             WHERE id = ?1 AND principal_id = ?2 AND revoked_at IS NULL",
            params![id, principal_id, now_rfc3339()],
        )? > 0)
    }

    pub fn any_api_key_exists(&self) -> AppResult<bool> {
        let conn = self.pool.get()?;
        Ok(
            conn.query_row("SELECT EXISTS(SELECT 1 FROM api_keys)", [], |r| {
                r.get::<_, i64>(0)
            })? == 1,
        )
    }

    /// Adopt an operator-supplied key verbatim, for first-boot bootstrapping.
    pub fn adopt_api_key(&self, key: &str, principal_id: &str, name: &str) -> AppResult<()> {
        if key.trim().len() < 16 {
            return Err(AppError::bad_request(
                "a bootstrap API key must be at least 16 characters",
            ));
        }
        let conn = self.pool.get()?;
        conn.execute(
            "INSERT INTO api_keys (id, key_hash, prefix, principal_id, name, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)
             ON CONFLICT(key_hash) DO NOTHING",
            params![
                new_id(),
                hash_token(key.trim()),
                key.trim().chars().take(10).collect::<String>(),
                principal_id,
                name,
                now_rfc3339(),
            ],
        )?;
        Ok(())
    }
}

fn principal_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<Principal> {
    let teams: String = row.get(4)?;
    Ok(Principal {
        id: row.get(0)?,
        kind: PrincipalKind::parse(&row.get::<_, String>(1)?),
        display_name: row.get(2)?,
        email: row.get(3)?,
        team_ids: serde_json::from_str(&teams).unwrap_or_default(),
        active: row.get::<_, i64>(5)? == 1,
        created_at: row.get(6)?,
    })
}

fn rfc3339(at: chrono::DateTime<chrono::Utc>) -> String {
    at.to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::test_pool;
    use crate::store::DirectoryStore;

    fn setup() -> (AuthStore, DirectoryStore) {
        let pool = test_pool();
        let directory = DirectoryStore::new(pool.clone());
        directory
            .upsert_principal(
                "ada",
                PrincipalKind::Internal,
                Some("Ada"),
                Some("ada@acme.test"),
            )
            .unwrap();
        (AuthStore::new(pool), directory)
    }

    #[test]
    fn a_login_token_works_once() {
        let (auth, _) = setup();
        let token = auth
            .create_login_token("ada@acme.test", "ada", 900)
            .unwrap();

        assert_eq!(
            auth.consume_login_token(&token).unwrap().as_deref(),
            Some("ada")
        );
        assert!(
            auth.consume_login_token(&token).unwrap().is_none(),
            "a magic link must not be reusable"
        );
    }

    #[test]
    fn an_expired_login_token_is_refused() {
        let (auth, _) = setup();
        let token = auth.create_login_token("ada@acme.test", "ada", 60).unwrap();
        // Backdate it past its own expiry.
        auth.pool
            .get()
            .unwrap()
            .execute(
                "UPDATE auth_login_tokens SET expires_at = '2000-01-01T00:00:00Z' WHERE token_hash = ?1",
                [hash_token(&token)],
            )
            .unwrap();
        assert!(auth.consume_login_token(&token).unwrap().is_none());
    }

    #[test]
    fn an_unknown_login_token_is_refused() {
        let (auth, _) = setup();
        assert!(auth.consume_login_token("not-a-token").unwrap().is_none());
    }

    #[test]
    fn the_raw_login_token_is_never_stored() {
        let (auth, _) = setup();
        let token = auth
            .create_login_token("ada@acme.test", "ada", 900)
            .unwrap();
        let stored: i64 = auth
            .pool
            .get()
            .unwrap()
            .query_row(
                "SELECT COUNT(*) FROM auth_login_tokens WHERE token_hash = ?1",
                [&token],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(stored, 0, "the database must hold the hash, not the token");
    }

    #[test]
    fn a_session_resolves_to_its_principal() {
        let (auth, _) = setup();
        let token = auth.create_session("ada", 3600, Some("curl/8")).unwrap();
        let principal = auth.principal_for_session(&token).unwrap().unwrap();
        assert_eq!(principal.id, "ada");
        assert_eq!(principal.email.as_deref(), Some("ada@acme.test"));
        assert_eq!(auth.sessions_for("ada").unwrap().len(), 1);
    }

    #[test]
    fn an_expired_or_revoked_session_stops_resolving() {
        let (auth, _) = setup();
        let token = auth.create_session("ada", 3600, None).unwrap();
        assert!(auth.revoke_session(&token).unwrap());
        assert!(auth.principal_for_session(&token).unwrap().is_none());

        let other = auth.create_session("ada", 3600, None).unwrap();
        auth.pool
            .get()
            .unwrap()
            .execute(
                "UPDATE auth_sessions SET expires_at = '2000-01-01T00:00:00Z'",
                [],
            )
            .unwrap();
        assert!(auth.principal_for_session(&other).unwrap().is_none());
    }

    #[test]
    fn deactivating_a_principal_kills_their_sessions_and_keys() {
        let (auth, directory) = setup();
        let session = auth.create_session("ada", 3600, None).unwrap();
        let (_, key) = auth.create_api_key("ada", Some("cli")).unwrap();
        assert!(auth.principal_for_session(&session).unwrap().is_some());
        assert!(auth.principal_for_api_key(&key).unwrap().is_some());

        directory.set_active("ada", false).unwrap();
        assert!(
            auth.principal_for_session(&session).unwrap().is_none(),
            "offboarding must take effect immediately"
        );
        assert!(auth.principal_for_api_key(&key).unwrap().is_none());
    }

    #[test]
    fn api_keys_resolve_and_revoke() {
        let (auth, _) = setup();
        let (id, key) = auth.create_api_key("ada", Some("cli")).unwrap();
        assert!(key.starts_with(API_KEY_PREFIX));
        assert_eq!(auth.principal_for_api_key(&key).unwrap().unwrap().id, "ada");

        let listed = auth.list_api_keys("ada").unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].name.as_deref(), Some("cli"));
        assert!(listed[0].last_used_at.is_some(), "use should be stamped");
        assert!(
            !listed[0].prefix.contains(&key[12..]),
            "the listing must not reveal the key"
        );

        assert!(auth.revoke_api_key(&id, "ada").unwrap());
        assert!(auth.principal_for_api_key(&key).unwrap().is_none());
        assert!(
            !auth.revoke_api_key(&id, "ada").unwrap(),
            "revoking twice is a no-op"
        );
    }

    #[test]
    fn one_principal_cannot_revoke_anothers_key() {
        let (auth, directory) = setup();
        directory
            .upsert_principal("bob", PrincipalKind::Internal, None, Some("bob@acme.test"))
            .unwrap();
        let (id, key) = auth.create_api_key("ada", None).unwrap();

        assert!(!auth.revoke_api_key(&id, "bob").unwrap());
        assert!(
            auth.principal_for_api_key(&key).unwrap().is_some(),
            "Ada's key must survive Bob's attempt"
        );
    }

    #[test]
    fn an_unknown_key_resolves_to_nothing() {
        let (auth, _) = setup();
        assert!(auth.principal_for_api_key("qmk_nope").unwrap().is_none());
        assert!(auth.principal_for_api_key("").unwrap().is_none());
    }

    #[test]
    fn rate_limiting_counts_recent_requests_for_one_address() {
        let (auth, _) = setup();
        assert_eq!(auth.recent_login_requests("ada@acme.test", 600).unwrap(), 0);
        auth.create_login_token("ada@acme.test", "ada", 900)
            .unwrap();
        auth.create_login_token("ADA@ACME.TEST", "ada", 900)
            .unwrap();
        assert_eq!(
            auth.recent_login_requests("ada@acme.test", 600).unwrap(),
            2,
            "the count is case-insensitive"
        );
        assert_eq!(auth.recent_login_requests("bob@acme.test", 600).unwrap(), 0);
    }

    #[test]
    fn sweeping_removes_expired_and_spent_credentials() {
        let (auth, _) = setup();
        let live = auth.create_session("ada", 3600, None).unwrap();
        let spent = auth
            .create_login_token("ada@acme.test", "ada", 900)
            .unwrap();
        auth.consume_login_token(&spent).unwrap();

        assert!(auth.sweep_expired().unwrap() >= 1);
        assert!(
            auth.principal_for_session(&live).unwrap().is_some(),
            "a live session must survive the sweep"
        );
    }

    #[test]
    fn a_bootstrap_key_is_adopted_once_and_validated() {
        let (auth, _) = setup();
        assert!(!auth.any_api_key_exists().unwrap());
        assert!(auth.adopt_api_key("short", "ada", "bootstrap").is_err());

        auth.adopt_api_key("bootstrap-key-that-is-long-enough", "ada", "bootstrap")
            .unwrap();
        assert!(auth.any_api_key_exists().unwrap());
        assert_eq!(
            auth.principal_for_api_key("bootstrap-key-that-is-long-enough")
                .unwrap()
                .unwrap()
                .id,
            "ada"
        );

        // Adopting the same key again does not duplicate the row.
        auth.adopt_api_key("bootstrap-key-that-is-long-enough", "ada", "bootstrap")
            .unwrap();
        assert_eq!(auth.list_api_keys("ada").unwrap().len(), 1);
    }
}
