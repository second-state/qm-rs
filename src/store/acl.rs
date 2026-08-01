//! Grants: what one scope has made reachable from another.
//!
//! A grant names a resource by ref — `file:notes/plan.md`, `skill:triage`,
//! `cron:<id>`. File grants surface to the agent as handles under `shared/`,
//! which is the only path by which a turn touches another scope's files.

use rusqlite::{params, Row};

use crate::db::{now_rfc3339, DbPool};
use crate::error::{AppError, AppResult};
use crate::types::{Grant, GrantedHandle, Permission, ScopeId};

#[derive(Clone)]
pub struct AclStore {
    pool: DbPool,
}

/// A parsed resource ref.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResourceRef {
    pub kind: String,
    pub path: String,
}

/// Split `kind:path`. An unprefixed ref is a file, matching upstream's default.
pub fn parse_ref(reference: &str) -> ResourceRef {
    match reference.split_once(':') {
        Some((kind, path)) if !kind.is_empty() && !path.is_empty() => ResourceRef {
            kind: kind.to_string(),
            path: path.to_string(),
        },
        _ => ResourceRef {
            kind: "file".to_string(),
            path: reference.to_string(),
        },
    }
}

fn basename(path: &str) -> &str {
    path.rsplit('/')
        .next()
        .filter(|s| !s.is_empty())
        .unwrap_or(path)
}

fn grant_from_row(row: &Row<'_>) -> rusqlite::Result<Grant> {
    Ok(Grant {
        owner_scope_id: ScopeId::from_raw(row.get::<_, String>("owner_scope_id")?),
        reference: row.get("ref")?,
        grantee_scope_id: ScopeId::from_raw(row.get::<_, String>("grantee_scope_id")?),
        permission: Permission::parse(&row.get::<_, String>("permission")?),
        granted_by: row.get("granted_by")?,
        created_at: row.get("created_at")?,
    })
}

fn to_handle(g: &Grant) -> GrantedHandle {
    let parsed = parse_ref(&g.reference);
    GrantedHandle {
        handle_path: format!("shared/{}", basename(&parsed.path)),
        owner_scope_id: g.owner_scope_id.clone(),
        owner_path: parsed.path,
        permission: g.permission,
    }
}

impl AclStore {
    pub fn new(pool: DbPool) -> Self {
        Self { pool }
    }

    /// Grant `reference` from `owner` to `grantee`. Re-granting updates the
    /// permission rather than erroring, so raising read to write is one call.
    pub fn grant(&self, g: &Grant) -> AppResult<()> {
        if g.owner_scope_id == g.grantee_scope_id {
            return Err(AppError::bad_request(
                "a scope already reaches its own resources — grant to a different scope",
            ));
        }
        if g.reference.trim().is_empty() {
            return Err(AppError::bad_request("a grant needs a resource ref"));
        }
        let conn = self.pool.get()?;
        conn.execute(
            "INSERT INTO acl_grants
                (owner_scope_id, ref, grantee_scope_id, permission, granted_by, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)
             ON CONFLICT(owner_scope_id, ref, grantee_scope_id) DO UPDATE SET
                permission = excluded.permission,
                granted_by = excluded.granted_by",
            params![
                g.owner_scope_id.as_str(),
                g.reference,
                g.grantee_scope_id.as_str(),
                g.permission.as_str(),
                g.granted_by,
                now_rfc3339(),
            ],
        )?;
        Ok(())
    }

    pub fn revoke(&self, owner: &ScopeId, reference: &str, grantee: &ScopeId) -> AppResult<bool> {
        let conn = self.pool.get()?;
        let n = conn.execute(
            "DELETE FROM acl_grants
             WHERE owner_scope_id = ?1 AND ref = ?2 AND grantee_scope_id = ?3",
            params![owner.as_str(), reference, grantee.as_str()],
        )?;
        Ok(n > 0)
    }

    /// Every grant reaching any of `scopes`.
    pub fn grants_for(&self, scopes: &[ScopeId]) -> AppResult<Vec<Grant>> {
        if scopes.is_empty() {
            return Ok(Vec::new());
        }
        let conn = self.pool.get()?;
        let placeholders = vec!["?"; scopes.len()].join(",");
        let sql = format!(
            "SELECT * FROM acl_grants WHERE grantee_scope_id IN ({placeholders})
             ORDER BY owner_scope_id, ref"
        );
        let mut stmt = conn.prepare(&sql)?;
        let owned: Vec<String> = scopes.iter().map(|s| s.as_str().to_string()).collect();
        let args: Vec<&dyn rusqlite::ToSql> =
            owned.iter().map(|s| s as &dyn rusqlite::ToSql).collect();
        let rows = stmt.query_map(args.as_slice(), grant_from_row)?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    /// File grants reaching `scopes`, as `shared/` handles.
    ///
    /// Handle paths are made unique: two grants whose basenames collide would
    /// otherwise both mount at `shared/<name>` and the second would shadow the
    /// first, silently reading the wrong scope's file.
    pub fn handles_for(&self, scopes: &[ScopeId]) -> AppResult<Vec<GrantedHandle>> {
        let grants = self.grants_for(scopes)?;
        let mut handles: Vec<GrantedHandle> = Vec::new();
        for g in grants
            .iter()
            .filter(|g| parse_ref(&g.reference).kind == "file")
        {
            let mut handle = to_handle(g);
            if handles.iter().any(|h| h.handle_path == handle.handle_path) {
                let owner = g.owner_scope_id.reference();
                let base = basename(&handle.owner_path);
                handle.handle_path = format!("shared/{owner}-{base}");
            }
            // Still colliding (same owner, same basename, different dirs):
            // fall back to the full owner path, which is unique by definition.
            if handles.iter().any(|h| h.handle_path == handle.handle_path) {
                handle.handle_path = format!(
                    "shared/{}-{}",
                    g.owner_scope_id.reference(),
                    handle.owner_path.replace('/', "-")
                );
            }
            handles.push(handle);
        }
        Ok(handles)
    }

    /// Non-file grants of one kind reaching `scopes` — how a shared skill or
    /// cron becomes visible.
    pub fn grants_of_kind(&self, kind: &str, scopes: &[ScopeId]) -> AppResult<Vec<Grant>> {
        Ok(self
            .grants_for(scopes)?
            .into_iter()
            .filter(|g| parse_ref(&g.reference).kind == kind)
            .collect())
    }

    /// Grants a scope has handed out — the "who can see my stuff" view.
    pub fn grants_by_owner(&self, owner: &ScopeId) -> AppResult<Vec<Grant>> {
        let conn = self.pool.get()?;
        let mut stmt =
            conn.prepare("SELECT * FROM acl_grants WHERE owner_scope_id = ?1 ORDER BY ref")?;
        let rows = stmt.query_map([owner.as_str()], grant_from_row)?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    /// The permission `scopes` hold on a specific resource, if any.
    pub fn permission_on(
        &self,
        owner: &ScopeId,
        reference: &str,
        scopes: &[ScopeId],
    ) -> AppResult<Option<Permission>> {
        Ok(self
            .grants_for(scopes)?
            .into_iter()
            .filter(|g| &g.owner_scope_id == owner && g.reference == reference)
            // Write beats read when a scope holds both directly and via a
            // channel it belongs to.
            .map(|g| g.permission)
            .max_by_key(|p| match p {
                Permission::Write => 1,
                Permission::Read => 0,
            }))
    }

    pub fn list(&self) -> AppResult<Vec<Grant>> {
        let conn = self.pool.get()?;
        let mut stmt = conn.prepare("SELECT * FROM acl_grants ORDER BY created_at DESC")?;
        let rows = stmt.query_map([], grant_from_row)?;
        Ok(rows.collect::<Result<_, _>>()?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::test_pool;

    fn store() -> AclStore {
        AclStore::new(test_pool())
    }

    fn grant(owner: &str, reference: &str, grantee: ScopeId, permission: Permission) -> Grant {
        Grant {
            owner_scope_id: ScopeId::personal(owner),
            reference: reference.to_string(),
            grantee_scope_id: grantee,
            permission,
            granted_by: owner.to_string(),
            created_at: now_rfc3339(),
        }
    }

    #[test]
    fn refs_default_to_files_when_unprefixed() {
        assert_eq!(parse_ref("file:notes/a.md").kind, "file");
        assert_eq!(parse_ref("file:notes/a.md").path, "notes/a.md");
        assert_eq!(parse_ref("skill:triage").kind, "skill");
        assert_eq!(parse_ref("notes/a.md").kind, "file");
        assert_eq!(parse_ref("notes/a.md").path, "notes/a.md");
    }

    #[test]
    fn a_grant_makes_a_file_reachable_as_a_shared_handle() {
        let s = store();
        let grantee = ScopeId::personal("u2");
        s.grant(&grant(
            "u1",
            "file:notes/plan.md",
            grantee.clone(),
            Permission::Read,
        ))
        .unwrap();

        let handles = s.handles_for(&[grantee]).unwrap();
        assert_eq!(handles.len(), 1);
        assert_eq!(handles[0].handle_path, "shared/plan.md");
        assert_eq!(handles[0].owner_path, "notes/plan.md");
        assert_eq!(handles[0].owner_scope_id, ScopeId::personal("u1"));
        assert_eq!(handles[0].permission, Permission::Read);
    }

    #[test]
    fn ungranted_scopes_see_nothing() {
        let s = store();
        s.grant(&grant(
            "u1",
            "file:notes/plan.md",
            ScopeId::personal("u2"),
            Permission::Read,
        ))
        .unwrap();
        assert!(s
            .handles_for(&[ScopeId::personal("u3")])
            .unwrap()
            .is_empty());
        assert!(s.handles_for(&[]).unwrap().is_empty());
    }

    #[test]
    fn colliding_basenames_get_distinct_handle_paths() {
        let s = store();
        let grantee = ScopeId::personal("u3");
        s.grant(&grant(
            "u1",
            "file:notes/plan.md",
            grantee.clone(),
            Permission::Read,
        ))
        .unwrap();
        s.grant(&grant(
            "u2",
            "file:docs/plan.md",
            grantee.clone(),
            Permission::Read,
        ))
        .unwrap();

        let handles = s.handles_for(&[grantee]).unwrap();
        assert_eq!(handles.len(), 2);
        let paths: Vec<&str> = handles.iter().map(|h| h.handle_path.as_str()).collect();
        assert_eq!(
            paths.len(),
            paths.iter().collect::<std::collections::HashSet<_>>().len(),
            "handles must not shadow each other: {paths:?}"
        );
    }

    #[test]
    fn colliding_basenames_from_the_same_owner_also_stay_distinct() {
        let s = store();
        let grantee = ScopeId::personal("u2");
        s.grant(&grant(
            "u1",
            "file:a/plan.md",
            grantee.clone(),
            Permission::Read,
        ))
        .unwrap();
        s.grant(&grant(
            "u1",
            "file:b/plan.md",
            grantee.clone(),
            Permission::Read,
        ))
        .unwrap();
        let handles = s.handles_for(&[grantee]).unwrap();
        let paths: std::collections::HashSet<&str> =
            handles.iter().map(|h| h.handle_path.as_str()).collect();
        assert_eq!(paths.len(), 2, "got {paths:?}");
    }

    #[test]
    fn re_granting_raises_the_permission_in_place() {
        let s = store();
        let grantee = ScopeId::personal("u2");
        s.grant(&grant("u1", "file:a.md", grantee.clone(), Permission::Read))
            .unwrap();
        s.grant(&grant(
            "u1",
            "file:a.md",
            grantee.clone(),
            Permission::Write,
        ))
        .unwrap();

        let grants = s.grants_for(std::slice::from_ref(&grantee)).unwrap();
        assert_eq!(grants.len(), 1, "re-granting must not duplicate the row");
        assert_eq!(grants[0].permission, Permission::Write);
        assert_eq!(
            s.permission_on(&ScopeId::personal("u1"), "file:a.md", &[grantee])
                .unwrap(),
            Some(Permission::Write)
        );
    }

    #[test]
    fn write_wins_when_a_scope_is_reached_two_ways() {
        let s = store();
        let personal = ScopeId::personal("u2");
        let channel = ScopeId::channel("eng");
        s.grant(&grant(
            "u1",
            "file:a.md",
            personal.clone(),
            Permission::Read,
        ))
        .unwrap();
        s.grant(&grant(
            "u1",
            "file:a.md",
            channel.clone(),
            Permission::Write,
        ))
        .unwrap();
        assert_eq!(
            s.permission_on(&ScopeId::personal("u1"), "file:a.md", &[personal, channel])
                .unwrap(),
            Some(Permission::Write)
        );
    }

    #[test]
    fn revoking_removes_reachability() {
        let s = store();
        let grantee = ScopeId::personal("u2");
        s.grant(&grant("u1", "file:a.md", grantee.clone(), Permission::Read))
            .unwrap();
        assert!(s
            .revoke(&ScopeId::personal("u1"), "file:a.md", &grantee)
            .unwrap());
        assert!(s
            .handles_for(std::slice::from_ref(&grantee))
            .unwrap()
            .is_empty());
        assert!(
            !s.revoke(&ScopeId::personal("u1"), "file:a.md", &grantee)
                .unwrap(),
            "revoking twice reports nothing removed"
        );
    }

    #[test]
    fn non_file_grants_are_kept_out_of_the_file_handles() {
        let s = store();
        let grantee = ScopeId::personal("u2");
        s.grant(&grant(
            "u1",
            "skill:triage",
            grantee.clone(),
            Permission::Read,
        ))
        .unwrap();
        s.grant(&grant("u1", "file:a.md", grantee.clone(), Permission::Read))
            .unwrap();

        assert_eq!(
            s.handles_for(std::slice::from_ref(&grantee)).unwrap().len(),
            1
        );
        let skills = s.grants_of_kind("skill", &[grantee]).unwrap();
        assert_eq!(skills.len(), 1);
        assert_eq!(skills[0].reference, "skill:triage");
    }

    #[test]
    fn self_grants_and_empty_refs_are_rejected() {
        let s = store();
        let me = ScopeId::personal("u1");
        assert!(s
            .grant(&grant("u1", "file:a.md", me, Permission::Read))
            .is_err());
        assert!(s
            .grant(&grant(
                "u1",
                "   ",
                ScopeId::personal("u2"),
                Permission::Read
            ))
            .is_err());
    }

    #[test]
    fn owners_can_see_what_they_have_shared() {
        let s = store();
        s.grant(&grant(
            "u1",
            "file:a.md",
            ScopeId::personal("u2"),
            Permission::Read,
        ))
        .unwrap();
        s.grant(&grant(
            "u1",
            "file:b.md",
            ScopeId::channel("eng"),
            Permission::Write,
        ))
        .unwrap();
        assert_eq!(
            s.grants_by_owner(&ScopeId::personal("u1")).unwrap().len(),
            2
        );
        assert!(s
            .grants_by_owner(&ScopeId::personal("u2"))
            .unwrap()
            .is_empty());
    }
}
