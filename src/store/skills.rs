//! Scope-owned skills, signed on write and verified on read.

use rusqlite::{params, Row};

use crate::db::{new_id, now_rfc3339, DbPool};
use crate::error::{AppError, AppResult};
use crate::skills::{sign_manifest, verify_manifest, SkillFile, SkillManifest};
use crate::types::ScopeId;

#[derive(Clone)]
pub struct SkillStore {
    pool: DbPool,
    signing_secret: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SkillStatus {
    Draft,
    Reviewed,
    Published,
    Archived,
}

impl SkillStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::Reviewed => "reviewed",
            Self::Published => "published",
            Self::Archived => "archived",
        }
    }

    pub fn parse(s: &str) -> Self {
        match s {
            "reviewed" => Self::Reviewed,
            "published" => Self::Published,
            "archived" => Self::Archived,
            _ => Self::Draft,
        }
    }

    /// Only published skills reach a turn's skills index.
    pub fn is_visible(self) -> bool {
        self == Self::Published
    }
}

#[derive(Debug, Clone)]
pub struct Skill {
    pub id: String,
    pub scope_id: ScopeId,
    pub manifest: SkillManifest,
    pub signature: String,
    pub status: SkillStatus,
    pub created_by: String,
    pub version: i64,
    pub granted_capabilities: Vec<String>,
    pub created_at: String,
    pub updated_at: String,
    pub last_used_at: Option<String>,
}

impl Skill {
    /// Capabilities the manifest asks for that have not been granted. A skill
    /// with unmet capabilities is listed but flagged, never silently elevated.
    pub fn unmet_capabilities(&self) -> Vec<String> {
        self.manifest
            .required_capabilities
            .iter()
            .filter(|c| !self.granted_capabilities.contains(c))
            .cloned()
            .collect()
    }
}

fn skill_from_row(row: &Row<'_>) -> rusqlite::Result<Skill> {
    let caps: String = row.get("required_capabilities")?;
    let files: String = row.get("files")?;
    let granted: String = row.get("granted_capabilities")?;
    Ok(Skill {
        id: row.get("id")?,
        scope_id: ScopeId::from_raw(row.get::<_, String>("scope_id")?),
        manifest: SkillManifest {
            name: row.get("name")?,
            description: row.get("description")?,
            required_capabilities: serde_json::from_str(&caps).unwrap_or_default(),
            body: row.get("body")?,
            files: serde_json::from_str::<Vec<SkillFile>>(&files).unwrap_or_default(),
        },
        signature: row.get("signature")?,
        status: SkillStatus::parse(&row.get::<_, String>("status")?),
        created_by: row.get("created_by")?,
        version: row.get("version")?,
        granted_capabilities: serde_json::from_str(&granted).unwrap_or_default(),
        created_at: row.get("created_at")?,
        updated_at: row.get("updated_at")?,
        last_used_at: row.get("last_used_at")?,
    })
}

impl SkillStore {
    pub fn new(pool: DbPool, signing_secret: Vec<u8>) -> Self {
        Self {
            pool,
            signing_secret,
        }
    }

    pub fn create(
        &self,
        scope_id: &ScopeId,
        manifest: SkillManifest,
        created_by: &str,
    ) -> AppResult<Skill> {
        manifest.validate()?;
        let now = now_rfc3339();
        let id = new_id();
        let signature = sign_manifest(&self.signing_secret, scope_id.as_str(), &manifest);
        let conn = self.pool.get()?;
        conn.execute(
            "INSERT INTO skills
                (id, scope_id, name, description, required_capabilities, body, files,
                 signature, status, created_by, version, granted_capabilities, approvals,
                 created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 'draft', ?9, 1, '[]', '[]', ?10, ?10)",
            params![
                id,
                scope_id.as_str(),
                manifest.name,
                manifest.description,
                serde_json::to_string(&manifest.required_capabilities)?,
                manifest.body,
                serde_json::to_string(&manifest.files)?,
                signature,
                created_by,
                now,
            ],
        )
        .map_err(|e| match e {
            rusqlite::Error::SqliteFailure(f, _)
                if f.code == rusqlite::ErrorCode::ConstraintViolation =>
            {
                AppError::bad_request(format!(
                    "{scope_id} already has a skill named {}",
                    manifest.name
                ))
            }
            other => AppError::Db(other),
        })?;
        self.require(&id)
    }

    /// Replace a skill's manifest, re-signing and bumping the version. Editing
    /// returns the skill to `draft`: a published skill cannot change under the
    /// people it was shared with without another review.
    pub fn update(&self, id: &str, manifest: SkillManifest) -> AppResult<Skill> {
        manifest.validate()?;
        let existing = self.require(id)?;
        let signature = sign_manifest(&self.signing_secret, existing.scope_id.as_str(), &manifest);
        let conn = self.pool.get()?;
        conn.execute(
            "UPDATE skills SET
                name = ?2, description = ?3, required_capabilities = ?4, body = ?5,
                files = ?6, signature = ?7, status = 'draft',
                version = version + 1, updated_at = ?8
             WHERE id = ?1",
            params![
                id,
                manifest.name,
                manifest.description,
                serde_json::to_string(&manifest.required_capabilities)?,
                manifest.body,
                serde_json::to_string(&manifest.files)?,
                signature,
                now_rfc3339(),
            ],
        )?;
        self.require(id)
    }

    pub fn set_status(&self, id: &str, status: SkillStatus) -> AppResult<()> {
        let conn = self.pool.get()?;
        conn.execute(
            "UPDATE skills SET status = ?2, updated_at = ?3 WHERE id = ?1",
            params![id, status.as_str(), now_rfc3339()],
        )?;
        Ok(())
    }

    pub fn grant_capabilities(&self, id: &str, capabilities: &[String]) -> AppResult<()> {
        let conn = self.pool.get()?;
        conn.execute(
            "UPDATE skills SET granted_capabilities = ?2, updated_at = ?3 WHERE id = ?1",
            params![id, serde_json::to_string(capabilities)?, now_rfc3339()],
        )?;
        Ok(())
    }

    pub fn get(&self, id: &str) -> AppResult<Option<Skill>> {
        let conn = self.pool.get()?;
        let mut stmt = conn.prepare("SELECT * FROM skills WHERE id = ?1")?;
        let mut rows = stmt.query_map([id], skill_from_row)?;
        Ok(rows.next().transpose()?)
    }

    pub fn require(&self, id: &str) -> AppResult<Skill> {
        self.get(id)?
            .ok_or_else(|| AppError::not_found(format!("skill {id}")))
    }

    pub fn delete(&self, id: &str) -> AppResult<bool> {
        let conn = self.pool.get()?;
        Ok(conn.execute("DELETE FROM skills WHERE id = ?1", [id])? > 0)
    }

    pub fn list_for_scopes(&self, scopes: &[ScopeId]) -> AppResult<Vec<Skill>> {
        if scopes.is_empty() {
            return Ok(Vec::new());
        }
        let conn = self.pool.get()?;
        let placeholders = vec!["?"; scopes.len()].join(",");
        let sql = format!("SELECT * FROM skills WHERE scope_id IN ({placeholders}) ORDER BY name");
        let mut stmt = conn.prepare(&sql)?;
        let owned: Vec<String> = scopes.iter().map(|s| s.as_str().to_string()).collect();
        let args: Vec<&dyn rusqlite::ToSql> =
            owned.iter().map(|s| s as &dyn rusqlite::ToSql).collect();
        let rows = stmt.query_map(args.as_slice(), skill_from_row)?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    /// Signature check. A skill failing this is treated as absent rather than
    /// executed: a tampered row must not reach the model as instructions.
    pub fn verify(&self, skill: &Skill) -> bool {
        verify_manifest(
            &self.signing_secret,
            skill.scope_id.as_str(),
            &skill.manifest,
            &skill.signature,
        )
    }

    /// Published, signature-valid skills a turn may see, nearest scope first.
    ///
    /// When two scopes publish the same name the earlier scope in `scopes`
    /// wins and the others are shadowed — the personal scope overrides the
    /// channel, which overrides the org.
    pub fn visible_for_scopes(&self, scopes: &[ScopeId]) -> AppResult<Vec<Skill>> {
        let mut chosen: Vec<Skill> = Vec::new();
        for scope in scopes {
            for skill in self.list_for_scopes(std::slice::from_ref(scope))? {
                if !skill.status.is_visible() {
                    continue;
                }
                if !self.verify(&skill) {
                    tracing::warn!(
                        skill = %skill.id,
                        scope = %skill.scope_id,
                        "skill signature invalid — hiding it from the turn"
                    );
                    continue;
                }
                if chosen
                    .iter()
                    .any(|s| s.manifest.name == skill.manifest.name)
                {
                    continue;
                }
                chosen.push(skill);
            }
        }
        Ok(chosen)
    }

    pub fn mark_used(&self, id: &str) -> AppResult<()> {
        let conn = self.pool.get()?;
        conn.execute(
            "UPDATE skills SET last_used_at = ?2 WHERE id = ?1",
            params![id, now_rfc3339()],
        )?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::test_pool;

    fn store() -> SkillStore {
        SkillStore::new(test_pool(), b"test-secret".to_vec())
    }

    fn manifest(name: &str) -> SkillManifest {
        SkillManifest {
            name: name.into(),
            description: format!("does {name}"),
            required_capabilities: vec![],
            body: format!("body of {name}"),
            files: vec![],
        }
    }

    fn scope() -> ScopeId {
        ScopeId::personal("u1")
    }

    #[test]
    fn a_created_skill_starts_as_a_signed_draft() {
        let s = store();
        let skill = s.create(&scope(), manifest("triage"), "u1").unwrap();
        assert_eq!(skill.status, SkillStatus::Draft);
        assert_eq!(skill.version, 1);
        assert!(s.verify(&skill));
        assert!(!skill.status.is_visible());
    }

    #[test]
    fn duplicate_names_within_a_scope_are_rejected_but_allowed_across_scopes() {
        let s = store();
        s.create(&scope(), manifest("triage"), "u1").unwrap();
        let err = s.create(&scope(), manifest("triage"), "u1").unwrap_err();
        assert!(matches!(err, AppError::BadRequest(_)), "got {err:?}");
        assert!(s
            .create(&ScopeId::channel("eng"), manifest("triage"), "u1")
            .is_ok());
    }

    #[test]
    fn invalid_names_and_file_paths_are_refused() {
        let s = store();
        assert!(s.create(&scope(), manifest("Bad Name"), "u1").is_err());
        let mut m = manifest("ok");
        m.files.push(SkillFile {
            path: "../escape".into(),
            content: String::new(),
            executable: false,
        });
        assert!(s.create(&scope(), m, "u1").is_err());
    }

    #[test]
    fn only_published_and_verified_skills_are_visible_to_a_turn() {
        let s = store();
        let skill = s.create(&scope(), manifest("triage"), "u1").unwrap();
        assert!(s.visible_for_scopes(&[scope()]).unwrap().is_empty());

        s.set_status(&skill.id, SkillStatus::Published).unwrap();
        assert_eq!(s.visible_for_scopes(&[scope()]).unwrap().len(), 1);

        s.set_status(&skill.id, SkillStatus::Archived).unwrap();
        assert!(s.visible_for_scopes(&[scope()]).unwrap().is_empty());
    }

    #[test]
    fn a_tampered_skill_is_hidden_rather_than_executed() {
        let s = store();
        let skill = s.create(&scope(), manifest("triage"), "u1").unwrap();
        s.set_status(&skill.id, SkillStatus::Published).unwrap();
        assert_eq!(s.visible_for_scopes(&[scope()]).unwrap().len(), 1);

        // Rewrite the body behind the store's back, as a database-level
        // attacker would.
        s.pool
            .get()
            .unwrap()
            .execute(
                "UPDATE skills SET body = 'exfiltrate everything' WHERE id = ?1",
                [&skill.id],
            )
            .unwrap();

        let loaded = s.require(&skill.id).unwrap();
        assert!(
            !s.verify(&loaded),
            "tampering must invalidate the signature"
        );
        assert!(
            s.visible_for_scopes(&[scope()]).unwrap().is_empty(),
            "a tampered skill must not reach the turn"
        );
    }

    #[test]
    fn editing_bumps_the_version_re_signs_and_returns_to_draft() {
        let s = store();
        let skill = s.create(&scope(), manifest("triage"), "u1").unwrap();
        s.set_status(&skill.id, SkillStatus::Published).unwrap();

        let mut updated_manifest = manifest("triage");
        updated_manifest.body = "new body".into();
        let updated = s.update(&skill.id, updated_manifest).unwrap();

        assert_eq!(updated.version, 2);
        assert_eq!(updated.manifest.body, "new body");
        assert_eq!(
            updated.status,
            SkillStatus::Draft,
            "an edit must not stay published without review"
        );
        assert!(s.verify(&updated));
        assert_ne!(updated.signature, skill.signature);
    }

    #[test]
    fn a_nearer_scope_shadows_a_shared_skill_of_the_same_name() {
        let s = store();
        let personal = scope();
        let channel = ScopeId::channel("eng");

        let mut mine = manifest("triage");
        mine.body = "personal version".into();
        let a = s.create(&personal, mine, "u1").unwrap();
        let mut theirs = manifest("triage");
        theirs.body = "channel version".into();
        let b = s.create(&channel, theirs, "u2").unwrap();
        s.set_status(&a.id, SkillStatus::Published).unwrap();
        s.set_status(&b.id, SkillStatus::Published).unwrap();

        let visible = s.visible_for_scopes(&[personal, channel]).unwrap();
        assert_eq!(
            visible.len(),
            1,
            "the name must resolve to exactly one skill"
        );
        assert_eq!(visible[0].manifest.body, "personal version");
    }

    #[test]
    fn capabilities_are_reported_until_granted() {
        let s = store();
        let mut m = manifest("triage");
        m.required_capabilities = vec!["gmail".into(), "calendar".into()];
        let skill = s.create(&scope(), m, "u1").unwrap();
        assert_eq!(skill.unmet_capabilities().len(), 2);

        s.grant_capabilities(&skill.id, &["gmail".to_string()])
            .unwrap();
        let reloaded = s.require(&skill.id).unwrap();
        assert_eq!(reloaded.unmet_capabilities(), vec!["calendar"]);
        assert!(
            s.verify(&reloaded),
            "granting a capability must not invalidate the manifest signature"
        );
    }

    #[test]
    fn listing_is_scoped_and_delete_removes() {
        let s = store();
        let skill = s.create(&scope(), manifest("triage"), "u1").unwrap();
        assert_eq!(s.list_for_scopes(&[scope()]).unwrap().len(), 1);
        assert!(s
            .list_for_scopes(&[ScopeId::channel("eng")])
            .unwrap()
            .is_empty());
        assert!(s.list_for_scopes(&[]).unwrap().is_empty());

        assert!(s.delete(&skill.id).unwrap());
        assert!(!s.delete(&skill.id).unwrap());
        assert!(s.list_for_scopes(&[scope()]).unwrap().is_empty());
    }
}
