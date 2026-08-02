//! SQLite connection pool and versioned schema migrations.

use r2d2::Pool;
use r2d2_sqlite::SqliteConnectionManager;
use rusqlite::Connection;

use crate::error::AppResult;

pub type DbPool = Pool<SqliteConnectionManager>;

#[derive(Debug)]
struct ConnectionCustomizer;

impl r2d2::CustomizeConnection<Connection, rusqlite::Error> for ConnectionCustomizer {
    fn on_acquire(&self, conn: &mut Connection) -> Result<(), rusqlite::Error> {
        // busy_timeout FIRST: without it, two connections initializing at once
        // collide on the WAL pragma and fail with "database is locked".
        conn.execute_batch(
            "PRAGMA busy_timeout=5000; PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON;",
        )?;
        Ok(())
    }
}

pub fn init_pool(path: &str) -> AppResult<DbPool> {
    if let Some(parent) = std::path::Path::new(path).parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
    }
    // Switch the file to WAL once, on a single connection, BEFORE the pool
    // spins up its eager connections — otherwise they race on the journal-mode
    // change of a fresh database and r2d2 logs "database is locked" errors.
    {
        let conn = Connection::open(path)?;
        conn.execute_batch("PRAGMA busy_timeout=5000; PRAGMA journal_mode=WAL;")?;
    }
    let manager = SqliteConnectionManager::file(path);
    Ok(Pool::builder()
        .connection_customizer(Box::new(ConnectionCustomizer))
        .build(manager)?)
}

/// Versioned migrations: `sql/migrations/NNNN_name.sql` files embedded at
/// compile time, applied in order inside their own transactions, tracked in
/// `schema_migrations`. To change the schema: add the next
/// `sql/migrations/NNNN_<what>.sql` and register it here — never edit an
/// applied migration. The `sql/` folder is the canonical, reviewable history;
/// deployment needs only the binary plus `templates/`.
pub const MIGRATIONS: &[(&str, &str)] = &[
    ("0001_init", include_str!("../sql/migrations/0001_init.sql")),
    (
        "0002_auth_and_slack",
        include_str!("../sql/migrations/0002_auth_and_slack.sql"),
    ),
    (
        "0003_onboarding",
        include_str!("../sql/migrations/0003_onboarding.sql"),
    ),
];

pub fn run_migrations(pool: &DbPool) -> AppResult<()> {
    let mut conn = pool.get()?;
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS schema_migrations (
            version    TEXT PRIMARY KEY,
            applied_at TEXT NOT NULL
         );",
    )?;

    for (version, sql) in MIGRATIONS {
        let already: bool = conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM schema_migrations WHERE version = ?1)",
            [version],
            |row| row.get(0),
        )?;
        if already {
            continue;
        }
        let tx = conn.transaction()?;
        tx.execute_batch(sql)?;
        tx.execute(
            "INSERT INTO schema_migrations (version, applied_at)
             VALUES (?1, strftime('%Y-%m-%dT%H:%M:%SZ','now'))",
            [version],
        )?;
        tx.commit()?;
        tracing::info!("applied migration {version}");
    }
    Ok(())
}

/// Migrations already applied to this database, oldest first. The admin page
/// renders this next to `MIGRATIONS` so an operator can see drift.
pub fn applied_migrations(pool: &DbPool) -> AppResult<Vec<(String, String)>> {
    let conn = pool.get()?;
    let mut stmt =
        conn.prepare("SELECT version, applied_at FROM schema_migrations ORDER BY version")?;
    let rows = stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?;
    Ok(rows.collect::<Result<_, _>>()?)
}

pub fn now_rfc3339() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

pub fn new_id() -> String {
    uuid::Uuid::new_v4().to_string()
}

#[cfg(test)]
pub fn test_pool() -> DbPool {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("t.db");
    // Leak the tempdir so the DB file outlives this fn during the test.
    std::mem::forget(tmp);
    let pool = init_pool(path.to_str().unwrap()).unwrap();
    run_migrations(&pool).unwrap();
    pool
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn migrations_apply_and_are_idempotent() {
        let pool = test_pool();
        run_migrations(&pool).unwrap();
        let n: i64 = pool
            .get()
            .unwrap()
            .query_row("SELECT COUNT(*) FROM schema_migrations", [], |r| r.get(0))
            .unwrap();
        assert_eq!(n as usize, MIGRATIONS.len());
    }

    #[test]
    fn migration_registry_is_ordered_and_unique() {
        let versions: Vec<&str> = MIGRATIONS.iter().map(|(v, _)| *v).collect();
        let mut sorted = versions.clone();
        sorted.sort();
        sorted.dedup();
        assert_eq!(versions, sorted, "migrations must be ordered and unique");
        assert!(MIGRATIONS.iter().all(|(_, sql)| !sql.trim().is_empty()));
    }

    #[test]
    fn schema_has_expected_tables() {
        let pool = test_pool();
        let conn = pool.get().unwrap();
        for table in [
            "principals",
            "directory_channels",
            "scopes",
            "settings",
            "sessions",
            "session_entries",
            "participants",
            "memory_docs",
            "memory_revisions",
            "skills",
            "acl_grants",
            "crons",
            "cron_fires",
            "file_artifacts",
            "keychain",
            "pending_approvals",
            "command_approval_grants",
            "deliveries",
            "audit_log",
            "connector_identities",
            "connector_channels",
        ] {
            let exists: i64 = conn
                .query_row(
                    "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?1",
                    [table],
                    |r| r.get(0),
                )
                .unwrap();
            assert_eq!(exists, 1, "missing table {table}");
        }
    }

    #[test]
    fn applied_migrations_reports_the_registry() {
        let pool = test_pool();
        let applied = applied_migrations(&pool).unwrap();
        assert_eq!(applied.len(), MIGRATIONS.len());
        assert_eq!(applied[0].0, MIGRATIONS[0].0);
    }
}
