//! Persistence.
//!
//! Every durable substrate QM keeps in Postgres lives here on SQLite instead.
//! Stores are cheap `Clone` handles over one shared r2d2 pool, so [`Stores`]
//! can be cloned into every task and surface without ceremony.

pub mod acl;
pub mod crons;
pub mod directory;
pub mod memory;
pub mod misc;
pub mod sessions;
pub mod skills;

pub use acl::AclStore;
pub use crons::CronStore;
pub use directory::DirectoryStore;
pub use memory::MemoryStore;
pub use misc::{
    ApprovalStore, AuditLog, DeliveryStore, FileStore, KeychainStore, SlackDedupeStore,
};
pub use sessions::SessionStore;
pub use skills::SkillStore;

use crate::db::DbPool;
use crate::error::AppResult;

/// Every store, sharing one pool.
#[derive(Clone)]
pub struct Stores {
    pub sessions: SessionStore,
    pub memory: MemoryStore,
    pub skills: SkillStore,
    pub acl: AclStore,
    pub crons: CronStore,
    pub files: FileStore,
    pub keychain: KeychainStore,
    pub approvals: ApprovalStore,
    pub deliveries: DeliveryStore,
    pub directory: DirectoryStore,
    pub audit: AuditLog,
    pub auth: crate::auth::store::AuthStore,
    pub slack_dedupe: SlackDedupeStore,
    /// The shared pool, for the few callers that need raw access — the admin
    /// page reads `schema_migrations` through it.
    pub pool: DbPool,
}

/// Setting under which the skill-signing secret is persisted.
const SIGNING_SECRET_KEY: &str = "skills.signing_secret";

impl Stores {
    /// Build every store over `pool`.
    ///
    /// The skill-signing secret is generated once and persisted: regenerating
    /// it per boot would invalidate every stored signature, which would hide
    /// all published skills after a restart.
    pub fn new(pool: DbPool) -> AppResult<Self> {
        let directory = DirectoryStore::new(pool.clone());
        let secret = match directory.setting(SIGNING_SECRET_KEY)? {
            Some(existing) => existing,
            None => {
                let generated = uuid::Uuid::new_v4().simple().to_string()
                    + &uuid::Uuid::new_v4().simple().to_string();
                directory.put_setting(SIGNING_SECRET_KEY, &generated)?;
                tracing::info!("generated a new skill-signing secret");
                generated
            }
        };

        Ok(Self {
            pool: pool.clone(),
            sessions: SessionStore::new(pool.clone()),
            memory: MemoryStore::new(pool.clone()),
            skills: SkillStore::new(pool.clone(), secret.into_bytes()),
            acl: AclStore::new(pool.clone()),
            crons: CronStore::new(pool.clone()),
            files: FileStore::new(pool.clone()),
            keychain: KeychainStore::new(pool.clone()),
            approvals: ApprovalStore::new(pool.clone()),
            deliveries: DeliveryStore::new(pool.clone()),
            auth: crate::auth::store::AuthStore::new(pool.clone()),
            slack_dedupe: SlackDedupeStore::new(pool.clone()),
            audit: AuditLog::new(pool),
            directory,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::{init_pool, run_migrations, test_pool};
    use crate::skills::SkillManifest;
    use crate::store::skills::SkillStatus;
    use crate::types::ScopeId;

    #[test]
    fn stores_share_one_pool_and_construct_cleanly() {
        let stores = Stores::new(test_pool()).unwrap();
        assert_eq!(stores.sessions.count().unwrap(), 0);
        assert!(stores
            .directory
            .setting(SIGNING_SECRET_KEY)
            .unwrap()
            .is_some());
    }

    #[test]
    fn the_signing_secret_survives_a_restart_so_skills_stay_visible() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("qm.db");
        let path = path.to_str().unwrap();

        let scope = ScopeId::personal("u1");
        let skill_id = {
            let pool = init_pool(path).unwrap();
            run_migrations(&pool).unwrap();
            let stores = Stores::new(pool).unwrap();
            let skill = stores
                .skills
                .create(
                    &scope,
                    SkillManifest {
                        name: "triage".into(),
                        description: "d".into(),
                        required_capabilities: vec![],
                        body: "b".into(),
                        files: vec![],
                    },
                    "u1",
                )
                .unwrap();
            stores
                .skills
                .set_status(&skill.id, SkillStatus::Published)
                .unwrap();
            assert_eq!(
                stores
                    .skills
                    .visible_for_scopes(std::slice::from_ref(&scope))
                    .unwrap()
                    .len(),
                1
            );
            skill.id
        };

        // Reboot against the same file.
        let pool = init_pool(path).unwrap();
        run_migrations(&pool).unwrap();
        let stores = Stores::new(pool).unwrap();
        let reloaded = stores.skills.require(&skill_id).unwrap();
        assert!(
            stores.skills.verify(&reloaded),
            "a restart must not invalidate stored skill signatures"
        );
        assert_eq!(stores.skills.visible_for_scopes(&[scope]).unwrap().len(), 1);
    }
}
