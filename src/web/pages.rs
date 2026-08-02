//! Server-rendered pages.

use axum::extract::{Form, Path, Query, RawForm, State};
use axum::http::header;
use axum::response::{IntoResponse, Redirect, Response};
use serde::Deserialize;
use tera::Context;

use super::{render, AppState};
use crate::auth::CurrentUser;
use crate::cron::schedule::CronSchedule;
use crate::error::{AppError, AppResult};
use crate::skills::SkillManifest;
use crate::store::crons::NewCron;
use crate::store::skills::SkillStatus;
use crate::types::{ApprovalDecision, ApprovalScope, ScopeId, SessionType, TurnRequest};

/// Fields every page's chrome needs.
///
/// The actor comes from [`CurrentUser`], which every handler takes as an
/// argument — a page cannot render without having authenticated first.
fn base_context(
    state: &AppState,
    user: &CurrentUser,
    nav: &str,
    title: &str,
) -> AppResult<(Context, String)> {
    let actor = user.id().to_string();
    let mut ctx = Context::new();
    ctx.insert("page_title", title);
    ctx.insert("active_nav", nav);
    ctx.insert("actor", &actor);
    ctx.insert("actor_name", user.principal.label());
    ctx.insert("actor_email", &user.principal.email);
    ctx.insert("is_admin", &user.is_admin(&state.config));
    ctx.insert("org_name", &state.config.org.name);
    Ok((ctx, actor))
}

#[derive(Deserialize)]
pub struct FlashQuery {
    #[serde(default)]
    flash: Option<String>,
}

fn with_flash(ctx: &mut Context, flash: &Option<String>) {
    if let Some(message) = flash {
        ctx.insert("flash", message);
    }
}

// ---------------------------------------------------------------------------
// Dashboard
// ---------------------------------------------------------------------------

pub async fn dashboard(
    State(state): State<AppState>,
    user: CurrentUser,
) -> AppResult<impl IntoResponse> {
    let (mut ctx, actor) = base_context(&state, &user, "dashboard", "Dashboard")?;
    let scopes = state.scopes_for(&actor)?;

    let sessions = state.stores.sessions.list_for_scopes(&scopes, false)?;
    let crons = state.stores.crons.list_for_scopes(&scopes, false)?;
    let skills = state.stores.skills.list_for_scopes(&scopes)?;

    let cron_rows: Vec<serde_json::Value> = crons
        .iter()
        .take(6)
        .map(|c| {
            serde_json::json!({
                "id": c.id,
                "title": c.display_title(),
                "schedule": c.schedule.describe(),
                "enabled": c.enabled,
                "next": c.next_fire_at.map(|t| t.to_rfc3339()),
            })
        })
        .collect();

    ctx.insert("session_count", &sessions.len());
    ctx.insert(
        "recent_sessions",
        &sessions
            .iter()
            .take(8)
            .map(|s| {
                serde_json::json!({
                    "id": s.id,
                    "title": s.display_title(),
                    "scope": s.scope_id.as_str(),
                    "surface": s.surface,
                    "last_activity_at": s.last_activity_at,
                })
            })
            .collect::<Vec<_>>(),
    );
    ctx.insert("cron_rows", &cron_rows);
    ctx.insert("cron_count", &crons.len());
    ctx.insert(
        "skill_count",
        &skills.iter().filter(|s| s.status.is_visible()).count(),
    );
    ctx.insert(
        "scopes",
        &scopes.iter().map(|s| s.to_string()).collect::<Vec<_>>(),
    );
    ctx.insert("memory_index", &memory_rows(&state, &scopes)?);
    ctx.insert("harness", &state.orchestrator.harness.name());
    ctx.insert("posture", &state.config.org.security_posture);
    ctx.insert("telegram_enabled", &state.config.telegram.enabled);
    render(&state, "dashboard.html", &ctx)
}

fn memory_rows(state: &AppState, scopes: &[ScopeId]) -> AppResult<Vec<serde_json::Value>> {
    Ok(state
        .stores
        .memory
        .index()?
        .into_iter()
        .filter(|(scope, _, _)| scopes.contains(scope))
        .map(|(scope, bytes, updated)| {
            serde_json::json!({ "scope": scope.as_str(), "bytes": bytes, "updated_at": updated })
        })
        .collect())
}

// ---------------------------------------------------------------------------
// Sessions
// ---------------------------------------------------------------------------

pub async fn sessions(
    State(state): State<AppState>,
    user: CurrentUser,
    Query(query): Query<FlashQuery>,
) -> AppResult<impl IntoResponse> {
    let (mut ctx, actor) = base_context(&state, &user, "sessions", "Sessions")?;
    let scopes = state.scopes_for(&actor)?;
    let sessions = state.stores.sessions.list_for_scopes(&scopes, true)?;
    ctx.insert(
        "sessions",
        &sessions
            .iter()
            .map(|s| {
                serde_json::json!({
                    "id": s.id,
                    "title": s.display_title(),
                    "scope": s.scope_id.as_str(),
                    "surface": s.surface,
                    "archived": s.archived,
                    "last_activity_at": s.last_activity_at,
                })
            })
            .collect::<Vec<_>>(),
    );
    ctx.insert(
        "scopes",
        &scopes.iter().map(|s| s.to_string()).collect::<Vec<_>>(),
    );
    with_flash(&mut ctx, &query.flash);
    render(&state, "sessions.html", &ctx)
}

#[derive(Deserialize)]
pub struct NewSessionForm {
    scope: String,
    #[serde(default)]
    title: Option<String>,
}

pub async fn new_session(
    State(state): State<AppState>,
    user: CurrentUser,
    Form(form): Form<NewSessionForm>,
) -> AppResult<Redirect> {
    let actor = user.id().to_string();
    let scope = ScopeId::from_raw(form.scope.trim());
    if scope.kind().is_none() {
        return Err(AppError::bad_request("pick a scope"));
    }
    // Only open a session in a scope this principal can actually reach.
    if !state.stores.directory.entitled(&actor, &scope)? && scope.owner() != Some(actor.as_str()) {
        return Err(AppError::forbidden(format!(
            "you cannot open a session in {scope}"
        )));
    }

    let thread_ref = format!("web:{}", crate::db::new_id());
    let session_type = if scope.is_shared() {
        SessionType::Channel
    } else {
        SessionType::Dm
    };
    let session = state
        .stores
        .sessions
        .ensure("web", &thread_ref, &scope, session_type, None)?;
    if let Some(title) = form
        .title
        .as_deref()
        .map(str::trim)
        .filter(|t| !t.is_empty())
    {
        state.stores.sessions.set_title(&session.id, title)?;
    }
    Ok(Redirect::to(&format!("/sessions/{}", session.id)))
}

pub async fn session_detail(
    State(state): State<AppState>,
    user: CurrentUser,
    Path(id): Path<String>,
) -> AppResult<impl IntoResponse> {
    let (mut ctx, actor) = base_context(&state, &user, "sessions", "Session")?;
    let session = state.stores.sessions.require(&id)?;
    let scopes = state.scopes_for(&actor)?;
    if !scopes.contains(&session.scope_id) {
        return Err(AppError::forbidden(
            "that session is in a scope you cannot read",
        ));
    }

    let entries: Vec<serde_json::Value> = state
        .stores
        .sessions
        .history(&id)?
        .into_iter()
        .map(|e| {
            serde_json::json!({
                "seq": e.seq,
                "type": e.entry_type.as_str(),
                "text": e.text(),
                "tool": e.payload.get("tool").and_then(|t| t.as_str()),
                "author": e.author(),
                "created_at": e.created_at,
            })
        })
        .collect();

    ctx.insert("page_title", &session.display_title());
    ctx.insert("session", &session);
    ctx.insert("session_title", &session.display_title());
    ctx.insert("entries", &entries);
    ctx.insert(
        "pending_approvals",
        &state.stores.approvals.pending_for_session(&id)?,
    );
    render(&state, "session.html", &ctx)
}

#[derive(Deserialize)]
pub struct MessageForm {
    text: String,
}

pub async fn send_message(
    State(state): State<AppState>,
    user: CurrentUser,
    Path(id): Path<String>,
    Form(form): Form<MessageForm>,
) -> AppResult<Redirect> {
    let actor = user.id().to_string();
    let session = state.stores.sessions.require(&id)?;
    if form.text.trim().is_empty() {
        return Ok(Redirect::to(&format!("/sessions/{id}")));
    }

    let request = TurnRequest::new(
        &session.surface,
        &actor,
        session.scope_id.clone(),
        &session.thread_ref,
        form.text,
    )
    .with_session_type(session.session_type);
    state.orchestrator.handle_turn(request).await?;
    Ok(Redirect::to(&format!("/sessions/{id}")))
}

#[derive(Deserialize)]
pub struct ApprovalForm {
    request_id: String,
    decision: String,
    #[serde(default)]
    scope: Option<String>,
}

pub async fn resolve_approval(
    State(state): State<AppState>,
    user: CurrentUser,
    Path(id): Path<String>,
    Form(form): Form<ApprovalForm>,
) -> AppResult<Redirect> {
    let actor = user.id().to_string();
    let session = state.stores.sessions.require(&id)?;
    let mut request = TurnRequest::new(
        &session.surface,
        &actor,
        session.scope_id.clone(),
        &session.thread_ref,
        "",
    );
    request.approval = Some(ApprovalDecision {
        request_id: form.request_id,
        approved: form.decision == "approve",
        scope: ApprovalScope::parse(form.scope.as_deref().unwrap_or("once")),
    });
    state.orchestrator.handle_turn(request).await?;
    Ok(Redirect::to(&format!("/sessions/{id}")))
}

pub async fn archive_session(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> AppResult<Redirect> {
    let session = state.stores.sessions.require(&id)?;
    state.stores.sessions.set_archived(&id, !session.archived)?;
    Ok(Redirect::to("/sessions?flash=Session+updated"))
}

// ---------------------------------------------------------------------------
// Memory
// ---------------------------------------------------------------------------

pub async fn memory_index(
    State(state): State<AppState>,
    user: CurrentUser,
) -> AppResult<impl IntoResponse> {
    let (mut ctx, actor) = base_context(&state, &user, "memory", "Memory")?;
    let scopes = state.scopes_for(&actor)?;
    ctx.insert("rows", &memory_rows(&state, &scopes)?);
    ctx.insert(
        "scopes",
        &scopes.iter().map(|s| s.to_string()).collect::<Vec<_>>(),
    );
    render(&state, "memory_index.html", &ctx)
}

pub async fn memory_edit(
    State(state): State<AppState>,
    user: CurrentUser,
    Path(scope): Path<String>,
    Query(query): Query<FlashQuery>,
) -> AppResult<impl IntoResponse> {
    let (mut ctx, actor) = base_context(&state, &user, "memory", "Memory")?;
    let scope = ScopeId::from_raw(scope);
    require_scope_access(&state, &actor, &scope)?;

    let head = state.stores.memory.head(&scope)?;
    ctx.insert("scope", scope.as_str());
    ctx.insert("content", &head.content);
    ctx.insert("revision", &head.revision);
    ctx.insert("history", &history_rows(&state, &scope)?);
    with_flash(&mut ctx, &query.flash);
    render(&state, "memory_edit.html", &ctx)
}

fn history_rows(state: &AppState, scope: &ScopeId) -> AppResult<Vec<serde_json::Value>> {
    Ok(state
        .stores
        .memory
        .history(scope, 20)?
        .into_iter()
        .map(|r| {
            serde_json::json!({
                "revision": r.revision,
                "short": r.revision.chars().take(8).collect::<String>(),
                "operation": r.operation,
                "author": r.author,
                "at": r.at,
            })
        })
        .collect())
}

#[derive(Deserialize)]
pub struct MemoryForm {
    content: String,
    revision: String,
    #[serde(default)]
    restore: Option<String>,
}

pub async fn memory_save(
    State(state): State<AppState>,
    user: CurrentUser,
    Path(scope): Path<String>,
    Form(form): Form<MemoryForm>,
) -> AppResult<Redirect> {
    let actor = user.id().to_string();
    let scope = ScopeId::from_raw(scope);
    require_scope_access(&state, &actor, &scope)?;

    // Both paths are compare-and-swap on the revision the editor was showing,
    // so a concurrent edit is reported rather than silently overwritten.
    let saved = match form.restore.as_deref().filter(|r| !r.is_empty()) {
        Some(revision) => {
            state
                .stores
                .memory
                .restore(&scope, revision, &form.revision, Some(&actor))?
        }
        None => state.stores.memory.replace_if_revision(
            &scope,
            &form.content,
            &form.revision,
            Some(&actor),
        )?,
    };

    let flash = if saved {
        "Saved"
    } else {
        "Not+saved:+someone+else+edited+this+first.+Reload+and+reapply+your+change."
    };
    Ok(Redirect::to(&format!("/memory/{scope}?flash={flash}")))
}

/// A scope is reachable if the principal is entitled to it, or it is their own.
fn require_scope_access(state: &AppState, actor: &str, scope: &ScopeId) -> AppResult<()> {
    if scope.owner() == Some(actor) || state.stores.directory.entitled(actor, scope)? {
        return Ok(());
    }
    Err(AppError::forbidden(format!("{scope} is not yours to read")))
}

// ---------------------------------------------------------------------------
// Skills
// ---------------------------------------------------------------------------

pub async fn skills(
    State(state): State<AppState>,
    user: CurrentUser,
    Query(query): Query<FlashQuery>,
) -> AppResult<impl IntoResponse> {
    let (mut ctx, actor) = base_context(&state, &user, "skills", "Skills")?;
    let scopes = state.scopes_for(&actor)?;
    let rows: Vec<serde_json::Value> = state
        .stores
        .skills
        .list_for_scopes(&scopes)?
        .into_iter()
        .map(|s| {
            let verified = state.stores.skills.verify(&s);
            serde_json::json!({
                "id": s.id,
                "name": s.manifest.name,
                "description": s.manifest.description,
                "scope": s.scope_id.as_str(),
                "status": s.status.as_str(),
                "version": s.version,
                "verified": verified,
                "unmet": s.unmet_capabilities(),
                "updated_at": s.updated_at,
            })
        })
        .collect();
    ctx.insert("skills", &rows);
    ctx.insert(
        "scopes",
        &scopes.iter().map(|s| s.to_string()).collect::<Vec<_>>(),
    );
    with_flash(&mut ctx, &query.flash);
    render(&state, "skills.html", &ctx)
}

#[derive(Deserialize)]
pub struct SkillForm {
    scope: String,
    source: String,
}

pub async fn create_skill(
    State(state): State<AppState>,
    user: CurrentUser,
    Form(form): Form<SkillForm>,
) -> AppResult<Redirect> {
    let actor = user.id().to_string();
    let scope = ScopeId::from_raw(form.scope.trim());
    require_scope_access(&state, &actor, &scope)?;
    let manifest = SkillManifest::from_markdown(&form.source)?;
    let skill = state.stores.skills.create(&scope, manifest, &actor)?;
    Ok(Redirect::to(&format!("/skills/{}", skill.id)))
}

pub async fn skill_detail(
    State(state): State<AppState>,
    user: CurrentUser,
    Path(id): Path<String>,
    Query(query): Query<FlashQuery>,
) -> AppResult<impl IntoResponse> {
    let (mut ctx, actor) = base_context(&state, &user, "skills", "Skill")?;
    let skill = state.stores.skills.require(&id)?;
    require_scope_access(&state, &actor, &skill.scope_id)?;

    ctx.insert("page_title", &skill.manifest.name);
    ctx.insert("skill_id", &skill.id);
    ctx.insert("name", &skill.manifest.name);
    ctx.insert("scope", skill.scope_id.as_str());
    ctx.insert("status", skill.status.as_str());
    ctx.insert("version", &skill.version);
    ctx.insert("verified", &state.stores.skills.verify(&skill));
    ctx.insert("unmet", &skill.unmet_capabilities());
    ctx.insert("source", &skill.manifest.to_markdown());
    with_flash(&mut ctx, &query.flash);
    render(&state, "skill.html", &ctx)
}

#[derive(Deserialize)]
pub struct SkillSourceForm {
    source: String,
}

pub async fn update_skill(
    State(state): State<AppState>,
    user: CurrentUser,
    Path(id): Path<String>,
    Form(form): Form<SkillSourceForm>,
) -> AppResult<Redirect> {
    let actor = user.id().to_string();
    let skill = state.stores.skills.require(&id)?;
    require_scope_access(&state, &actor, &skill.scope_id)?;
    state
        .stores
        .skills
        .update(&id, SkillManifest::from_markdown(&form.source)?)?;
    Ok(Redirect::to(&format!(
        "/skills/{id}?flash=Saved.+Editing+returns+a+skill+to+draft."
    )))
}

#[derive(Deserialize)]
pub struct StatusForm {
    status: String,
}

pub async fn set_skill_status(
    State(state): State<AppState>,
    user: CurrentUser,
    Path(id): Path<String>,
    Form(form): Form<StatusForm>,
) -> AppResult<Redirect> {
    let actor = user.id().to_string();
    let skill = state.stores.skills.require(&id)?;
    require_scope_access(&state, &actor, &skill.scope_id)?;
    state
        .stores
        .skills
        .set_status(&id, SkillStatus::parse(&form.status))?;
    state.stores.audit.record(
        &actor,
        "skill.status",
        Some(&skill.scope_id),
        Some(&id),
        Some(serde_json::json!({ "status": form.status })),
        true,
    );
    Ok(Redirect::to(&format!("/skills/{id}")))
}

pub async fn delete_skill(
    State(state): State<AppState>,
    user: CurrentUser,
    Path(id): Path<String>,
) -> AppResult<Redirect> {
    let actor = user.id().to_string();
    let skill = state.stores.skills.require(&id)?;
    require_scope_access(&state, &actor, &skill.scope_id)?;
    state.stores.skills.delete(&id)?;
    Ok(Redirect::to("/skills?flash=Skill+deleted"))
}

// ---------------------------------------------------------------------------
// Crons
// ---------------------------------------------------------------------------

pub async fn crons(
    State(state): State<AppState>,
    user: CurrentUser,
    Query(query): Query<FlashQuery>,
) -> AppResult<impl IntoResponse> {
    let (mut ctx, actor) = base_context(&state, &user, "crons", "Crons")?;
    let scopes = state.scopes_for(&actor)?;
    let rows: Vec<serde_json::Value> = state
        .stores
        .crons
        .list_for_scopes(&scopes, true)?
        .into_iter()
        .map(|c| {
            let fires = state.stores.crons.fires(&c.id, 5).unwrap_or_default();
            serde_json::json!({
                "id": c.id,
                "title": c.display_title(),
                "message": c.message,
                "scope": c.owner_scope_id.as_str(),
                "schedule": c.schedule.describe(),
                "enabled": c.enabled,
                "archived": c.archived,
                "next": c.next_fire_at.map(|t| t.to_rfc3339()),
                "last_fired_at": c.last_fired_at,
                "fires": fires.iter().map(|f| serde_json::json!({
                    "fired_at": f.fired_at,
                    "status": f.status,
                    "reply": f.reply.as_deref().map(|r| r.chars().take(200).collect::<String>()),
                    "session_id": f.session_id,
                })).collect::<Vec<_>>(),
            })
        })
        .collect();
    ctx.insert("crons", &rows);
    ctx.insert(
        "scopes",
        &scopes.iter().map(|s| s.to_string()).collect::<Vec<_>>(),
    );
    ctx.insert("default_timezone", &state.config.cron.default_timezone);
    with_flash(&mut ctx, &query.flash);
    render(&state, "crons.html", &ctx)
}

#[derive(Deserialize)]
pub struct CronForm {
    scope: String,
    message: String,
    #[serde(default)]
    title: Option<String>,
    #[serde(default)]
    cron: Option<String>,
    #[serde(default)]
    timezone: Option<String>,
    #[serde(default)]
    every_secs: Option<String>,
}

pub async fn create_cron(
    State(state): State<AppState>,
    user: CurrentUser,
    Form(form): Form<CronForm>,
) -> AppResult<Redirect> {
    let actor = user.id().to_string();
    let scope = ScopeId::from_raw(form.scope.trim());
    require_scope_access(&state, &actor, &scope)?;

    let expression = form
        .cron
        .as_deref()
        .map(str::trim)
        .filter(|c| !c.is_empty());
    let interval = form
        .every_secs
        .as_deref()
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .map(|v| {
            v.parse::<i64>()
                .map_err(|_| AppError::bad_request("interval must be a whole number of seconds"))
        })
        .transpose()?;

    let schedule = CronSchedule {
        cron: expression.map(str::to_string),
        // A timezone only means anything alongside a cron expression;
        // attaching one to an interval would make `normalize` reject it.
        timezone: expression.map(|_| {
            form.timezone
                .as_deref()
                .map(str::trim)
                .filter(|t| !t.is_empty())
                .unwrap_or(&state.config.cron.default_timezone)
                .to_string()
        }),
        every_secs: interval,
        first_fire_at: None,
    };

    state.stores.crons.create(
        NewCron {
            owner_scope_id: scope.clone(),
            owner: actor.clone(),
            created_by: actor.clone(),
            title: form.title.filter(|t| !t.trim().is_empty()),
            message: form.message,
            schedule,
            destination: None,
            run_as: "owner".into(),
        },
        chrono::Utc::now(),
    )?;
    Ok(Redirect::to("/crons?flash=Cron+created"))
}

pub async fn toggle_cron(
    State(state): State<AppState>,
    user: CurrentUser,
    Path(id): Path<String>,
) -> AppResult<Redirect> {
    let actor = user.id().to_string();
    let cron = state.stores.crons.require(&id)?;
    require_scope_access(&state, &actor, &cron.owner_scope_id)?;
    state
        .stores
        .crons
        .set_enabled(&id, !cron.enabled, chrono::Utc::now())?;
    Ok(Redirect::to("/crons?flash=Cron+updated"))
}

pub async fn delete_cron(
    State(state): State<AppState>,
    user: CurrentUser,
    Path(id): Path<String>,
) -> AppResult<Redirect> {
    let actor = user.id().to_string();
    let cron = state.stores.crons.require(&id)?;
    require_scope_access(&state, &actor, &cron.owner_scope_id)?;
    state.stores.crons.delete(&id)?;
    Ok(Redirect::to("/crons?flash=Cron+deleted"))
}

// ---------------------------------------------------------------------------
// Files
// ---------------------------------------------------------------------------

pub async fn files(
    State(state): State<AppState>,
    user: CurrentUser,
) -> AppResult<impl IntoResponse> {
    let (mut ctx, actor) = base_context(&state, &user, "files", "Files")?;
    let scopes = state.scopes_for(&actor)?;
    ctx.insert("artifacts", &{
        let rows: Vec<serde_json::Value> = state
            .stores
            .files
            .list_for_scopes(&scopes)?
            .into_iter()
            .map(|f| {
                serde_json::json!({
                    "id": f.id, "name": f.name, "scope": f.scope_id.as_str(),
                    "mimetype": f.mimetype, "size_bytes": f.size_bytes,
                    "created_at": f.created_at,
                })
            })
            .collect();
        rows
    });

    // Files reachable through a grant, and the grants this principal has made.
    let handles = state.stores.acl.handles_for(&scopes)?;
    ctx.insert(
        "handles",
        &handles
            .iter()
            .map(|h| {
                serde_json::json!({
                    "path": h.handle_path, "owner": h.owner_scope_id.as_str(),
                    "owner_path": h.owner_path, "permission": h.permission.as_str(),
                })
            })
            .collect::<Vec<_>>(),
    );
    ctx.insert(
        "shared_by_me",
        &state
            .stores
            .acl
            .grants_by_owner(&ScopeId::personal(&actor))?
            .iter()
            .map(|g| {
                serde_json::json!({
                    "ref": g.reference, "with": g.grantee_scope_id.as_str(),
                    "permission": g.permission.as_str(), "created_at": g.created_at,
                })
            })
            .collect::<Vec<_>>(),
    );
    render(&state, "files.html", &ctx)
}

pub async fn download_file(
    State(state): State<AppState>,
    user: CurrentUser,
    Path(id): Path<String>,
) -> AppResult<Response> {
    let actor = user.id().to_string();
    let artifact = state.stores.files.require(&id)?;
    if !state.scopes_for(&actor)?.contains(&artifact.scope_id) {
        return Err(AppError::forbidden(
            "that file is in a scope you cannot read",
        ));
    }
    let data = state.stores.files.read(&id)?;
    Ok((
        [
            (header::CONTENT_TYPE, artifact.mimetype.clone()),
            (
                header::CONTENT_DISPOSITION,
                // The filename is quoted and stripped of quotes and control
                // characters so it cannot inject extra header parameters.
                format!(
                    "attachment; filename=\"{}\"",
                    artifact
                        .name
                        .chars()
                        .filter(|c| !c.is_control() && *c != '"' && *c != '\\')
                        .collect::<String>()
                ),
            ),
        ],
        data,
    )
        .into_response())
}

// ---------------------------------------------------------------------------
// Keychain
// ---------------------------------------------------------------------------

pub async fn keychain(
    State(state): State<AppState>,
    user: CurrentUser,
    Query(query): Query<FlashQuery>,
) -> AppResult<impl IntoResponse> {
    let (mut ctx, actor) = base_context(&state, &user, "keychain", "Keychain")?;
    let scopes = state.scopes_for(&actor)?;
    ctx.insert(
        "entries",
        &state
            .stores
            .keychain
            .list(&scopes)?
            .iter()
            .map(|e| {
                serde_json::json!({
                    "scope": e.scope_id.as_str(), "key": e.key,
                    "description": e.description, "created_by": e.created_by,
                    "created_at": e.created_at,
                })
            })
            .collect::<Vec<_>>(),
    );
    ctx.insert(
        "scopes",
        &scopes.iter().map(|s| s.to_string()).collect::<Vec<_>>(),
    );
    with_flash(&mut ctx, &query.flash);
    render(&state, "keychain.html", &ctx)
}

#[derive(Deserialize)]
pub struct KeychainForm {
    scope: String,
    key: String,
    value: String,
    #[serde(default)]
    description: Option<String>,
}

pub async fn put_keychain(
    State(state): State<AppState>,
    user: CurrentUser,
    Form(form): Form<KeychainForm>,
) -> AppResult<Redirect> {
    let actor = user.id().to_string();
    let scope = ScopeId::from_raw(form.scope.trim());
    require_scope_access(&state, &actor, &scope)?;
    state.stores.keychain.put(
        &scope,
        form.key.trim(),
        &form.value,
        form.description.as_deref().filter(|d| !d.trim().is_empty()),
        &actor,
    )?;
    // The value never reaches the audit detail.
    state.stores.audit.record(
        &actor,
        "keychain.put",
        Some(&scope),
        Some(form.key.trim()),
        None,
        true,
    );
    Ok(Redirect::to("/keychain?flash=Secret+stored"))
}

#[derive(Deserialize)]
pub struct KeychainDeleteForm {
    scope: String,
    key: String,
}

pub async fn delete_keychain(
    State(state): State<AppState>,
    user: CurrentUser,
    Form(form): Form<KeychainDeleteForm>,
) -> AppResult<Redirect> {
    let actor = user.id().to_string();
    let scope = ScopeId::from_raw(form.scope.trim());
    require_scope_access(&state, &actor, &scope)?;
    state.stores.keychain.delete(&scope, form.key.trim())?;
    state.stores.audit.record(
        &actor,
        "keychain.delete",
        Some(&scope),
        Some(form.key.trim()),
        None,
        true,
    );
    Ok(Redirect::to("/keychain?flash=Secret+removed"))
}

// ---------------------------------------------------------------------------
// Admin
// ---------------------------------------------------------------------------

pub async fn admin(
    State(state): State<AppState>,
    user: CurrentUser,
) -> AppResult<impl IntoResponse> {
    // The admin page exposes the audit log, the plugin roster and the schema
    // state. Now that identity is authenticated rather than asserted, it can
    // actually be restricted.
    if !user.is_admin(&state.config) {
        return Err(AppError::forbidden(
            "the admin page is limited to the org administrator",
        ));
    }
    let (mut ctx, _actor) = base_context(&state, &user, "admin", "Admin")?;

    ctx.insert(
        "migrations",
        &crate::db::MIGRATIONS
            .iter()
            .map(|(v, _)| v.to_string())
            .collect::<Vec<_>>(),
    );
    ctx.insert(
        "applied",
        &crate::db::applied_migrations(&state.stores.pool)?
            .into_iter()
            .map(|(version, at)| serde_json::json!({ "version": version, "applied_at": at }))
            .collect::<Vec<_>>(),
    );
    ctx.insert("plugins", &state.orchestrator.plugins.describe());
    ctx.insert("plugins_active", &state.orchestrator.plugins.is_active());
    ctx.insert("harness", &state.orchestrator.harness.name());
    ctx.insert("posture", &state.config.org.security_posture);
    ctx.insert("org_id", &state.config.org.id);
    ctx.insert("db_path", &state.config.database.path);
    ctx.insert("telegram_enabled", &state.config.telegram.enabled);
    ctx.insert("cron_enabled", &state.config.cron.enabled);
    ctx.insert(
        "command_rules",
        &crate::policy::default_org_policy()
            .rules
            .iter()
            .map(|r| {
                serde_json::json!({
                    "pattern": r.pattern, "decision": r.decision.as_str(), "reason": r.reason,
                })
            })
            .collect::<Vec<_>>(),
    );
    ctx.insert(
        "audit",
        &state
            .stores
            .audit
            .recent(60)?
            .iter()
            .map(|e| {
                serde_json::json!({
                    "at": e.at, "actor": e.actor, "action": e.action,
                    "scope": e.scope_id, "target": e.target, "ok": e.ok,
                })
            })
            .collect::<Vec<_>>(),
    );
    render(&state, "admin.html", &ctx)
}

// ---------------------------------------------------------------------------
// Admin · people and groups
// ---------------------------------------------------------------------------

/// Admin-only, and said once here rather than repeated in every handler below.
fn require_admin(state: &AppState, user: &CurrentUser) -> AppResult<()> {
    if user.is_admin(&state.config) {
        return Ok(());
    }
    Err(AppError::forbidden(
        "this page is limited to the org administrator",
    ))
}

pub async fn admin_people(
    State(state): State<AppState>,
    user: CurrentUser,
    Query(query): Query<FlashQuery>,
) -> AppResult<impl IntoResponse> {
    require_admin(&state, &user)?;
    let (mut ctx, _actor) = base_context(&state, &user, "admin", "People")?;

    let identities = state.stores.directory.list_identities()?;
    let people: Vec<serde_json::Value> = state
        .stores
        .directory
        .list_principals()?
        .into_iter()
        .map(|p| {
            let links: Vec<serde_json::Value> = identities
                .iter()
                .filter(|i| i.principal_id == p.id)
                .map(|i| {
                    serde_json::json!({
                        "surface": i.surface, "external_id": i.external_id, "label": i.label,
                    })
                })
                .collect();
            serde_json::json!({
                "id": p.id,
                "name": p.display_name,
                "email": p.email,
                "kind": p.kind.as_str(),
                "active": p.active,
                "created_at": p.created_at,
                "links": links,
            })
        })
        .collect();

    ctx.insert("people", &people);
    ctx.insert("membership_mode", &state.config.auth.membership_mode);
    ctx.insert("is_denylist", &state.config.auth.is_denylist());
    ctx.insert("allowed_domains", &state.config.auth.allowed_domains);
    ctx.insert("telegram_enabled", &state.config.telegram.enabled);
    ctx.insert("slack_enabled", &state.config.slack.enabled);
    with_flash(&mut ctx, &query.flash);
    render(&state, "admin_people.html", &ctx)
}

#[derive(Deserialize)]
pub struct InviteForm {
    email: String,
    #[serde(default)]
    display_name: Option<String>,
    #[serde(default)]
    principal_id: Option<String>,
}

/// Add someone to the directory.
///
/// Under `allowlist` this is what lets them sign in at all; under `denylist`
/// it just gives them a stable principal id and display name ahead of time.
/// Either way there is no separate invite record — the principal *is* the
/// invitation, which is why offboarding is `set_active(false)` rather than a
/// second table to keep in sync.
pub async fn admin_invite(
    State(state): State<AppState>,
    user: CurrentUser,
    Form(form): Form<InviteForm>,
) -> AppResult<Redirect> {
    require_admin(&state, &user)?;
    let email = form.email.trim().to_ascii_lowercase();
    if !email.contains('@') || email.starts_with('@') || email.ends_with('@') {
        return Err(AppError::bad_request("that is not an email address"));
    }
    if let Some(existing) = state.stores.directory.principal_by_email(&email)? {
        return Ok(Redirect::to(&format!(
            "/admin/people?flash={}+already+has+an+account",
            existing.id
        )));
    }

    let directory = state.stores.directory.clone();
    let id = match form
        .principal_id
        .as_deref()
        .map(str::trim)
        .filter(|id| !id.is_empty())
    {
        Some(requested) => {
            if directory.principal(requested)?.is_some() {
                return Err(AppError::bad_request(format!(
                    "the id {requested:?} is already taken"
                )));
            }
            requested.to_string()
        }
        None => crate::auth::principal_id_for(&email, |candidate| {
            directory.principal(candidate).ok().flatten().is_some()
        }),
    };

    state.stores.directory.upsert_principal(
        &id,
        crate::types::PrincipalKind::Internal,
        form.display_name
            .as_deref()
            .map(str::trim)
            .filter(|n| !n.is_empty()),
        Some(&email),
    )?;
    state.stores.audit.record(
        user.id(),
        "admin.person.add",
        None,
        Some(&id),
        Some(serde_json::json!({ "email": email })),
        true,
    );
    Ok(Redirect::to(&format!(
        "/admin/people?flash=Added+{id}.+They+can+sign+in+with+their+email."
    )))
}

#[derive(Deserialize)]
pub struct PersonActiveForm {
    principal_id: String,
    active: String,
}

/// Deactivate or restore someone.
///
/// Deactivating is the offboarding verb in both membership modes: it refuses
/// their sign-in and invalidates every live session and API key they hold.
pub async fn admin_set_active(
    State(state): State<AppState>,
    user: CurrentUser,
    Form(form): Form<PersonActiveForm>,
) -> AppResult<Redirect> {
    require_admin(&state, &user)?;
    let active = form.active == "true";
    if !active && form.principal_id == state.config.org.admin {
        return Err(AppError::bad_request(
            "the org administrator cannot deactivate themselves — nobody would be left to undo it",
        ));
    }
    state
        .stores
        .directory
        .set_active(&form.principal_id, active)?;
    if !active {
        // Their sessions would otherwise keep working until they expired.
        state.stores.auth.revoke_all_sessions(&form.principal_id)?;
    }
    state.stores.audit.record(
        user.id(),
        if active {
            "admin.person.restore"
        } else {
            "admin.person.deactivate"
        },
        None,
        Some(&form.principal_id),
        None,
        true,
    );
    Ok(Redirect::to("/admin/people?flash=Updated"))
}

#[derive(Deserialize)]
pub struct LinkIdentityForm {
    principal_id: String,
    surface: String,
    external_id: String,
    #[serde(default)]
    label: Option<String>,
}

pub async fn admin_link_identity(
    State(state): State<AppState>,
    user: CurrentUser,
    Form(form): Form<LinkIdentityForm>,
) -> AppResult<Redirect> {
    require_admin(&state, &user)?;
    state.stores.directory.link_identity(
        &form.surface,
        &form.external_id,
        &form.principal_id,
        form.label.as_deref(),
        user.id(),
    )?;
    state.stores.audit.record(
        user.id(),
        "admin.identity.link",
        None,
        Some(&form.principal_id),
        Some(serde_json::json!({ "surface": form.surface, "external_id": form.external_id })),
        true,
    );
    Ok(Redirect::to("/admin/people?flash=Account+linked"))
}

#[derive(Deserialize)]
pub struct UnlinkIdentityForm {
    surface: String,
    external_id: String,
}

pub async fn admin_unlink_identity(
    State(state): State<AppState>,
    user: CurrentUser,
    Form(form): Form<UnlinkIdentityForm>,
) -> AppResult<Redirect> {
    require_admin(&state, &user)?;
    state
        .stores
        .directory
        .unlink_identity(&form.surface, &form.external_id)?;
    Ok(Redirect::to("/admin/people?flash=Account+unlinked"))
}

// ---- groups ---------------------------------------------------------------

pub async fn admin_groups(
    State(state): State<AppState>,
    user: CurrentUser,
    Query(query): Query<FlashQuery>,
) -> AppResult<impl IntoResponse> {
    require_admin(&state, &user)?;
    let (mut ctx, _actor) = base_context(&state, &user, "admin", "Groups")?;

    let bindings = state.stores.directory.list_channel_links()?;
    let groups: Vec<serde_json::Value> = state
        .stores
        .directory
        .list_groups()?
        .into_iter()
        .map(|g| {
            let scope = ScopeId::new(crate::types::ScopeKind::Group, &g.id);
            let members = state
                .stores
                .directory
                .group_members(&g.id)
                .unwrap_or_default();
            let links: Vec<serde_json::Value> = bindings
                .iter()
                .filter(|b| b.scope_id == scope.as_str())
                .map(|b| {
                    serde_json::json!({
                        "surface": b.surface, "external_id": b.external_id, "label": b.label,
                    })
                })
                .collect();
            serde_json::json!({
                "id": g.id,
                "name": g.name,
                "scope": scope.as_str(),
                "members": members,
                "created_at": g.created_at,
                "links": links,
            })
        })
        .collect();

    ctx.insert("groups", &groups);
    ctx.insert(
        "people",
        &state
            .stores
            .directory
            .list_principals()?
            .into_iter()
            .filter(|p| p.active)
            .map(|p| serde_json::json!({ "id": p.id, "name": p.display_name, "email": p.email }))
            .collect::<Vec<_>>(),
    );
    ctx.insert("telegram_enabled", &state.config.telegram.enabled);
    ctx.insert("slack_enabled", &state.config.slack.enabled);
    with_flash(&mut ctx, &query.flash);
    render(&state, "admin_groups.html", &ctx)
}

/// Read a form body that repeats a key, which is how a checkbox group posts.
///
/// axum's `Form` extractor goes through `serde_urlencoded`, which cannot
/// deserialize a repeated key into a `Vec` — it fails outright with
/// `invalid type: string "ada", expected a sequence`. The member picker on the
/// group form is exactly that shape, so it is parsed from the raw body instead.
fn form_fields(body: &[u8]) -> Vec<(String, String)> {
    form_urlencoded::parse(body)
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect()
}

fn field<'a>(fields: &'a [(String, String)], name: &str) -> Option<&'a str> {
    fields
        .iter()
        .find(|(k, _)| k == name)
        .map(|(_, v)| v.trim())
        .filter(|v| !v.is_empty())
}

fn repeated(fields: &[(String, String)], name: &str) -> Vec<String> {
    fields
        .iter()
        .filter(|(k, _)| k == name)
        .map(|(_, v)| v.trim().to_string())
        .filter(|v| !v.is_empty())
        .collect()
}

pub async fn admin_create_group(
    State(state): State<AppState>,
    user: CurrentUser,
    RawForm(body): RawForm,
) -> AppResult<Redirect> {
    require_admin(&state, &user)?;
    let fields = form_fields(&body);
    let name = field(&fields, "name")
        .ok_or_else(|| AppError::bad_request("a group needs a name"))?
        .to_string();
    let members = repeated(&fields, "members");
    let id = field(&fields, "id").unwrap_or(&name).to_string();

    let group_id = state
        .stores
        .directory
        .upsert_group(&id, &name, &members, user.id())?;
    state.stores.audit.record(
        user.id(),
        "admin.group.upsert",
        Some(&ScopeId::new(crate::types::ScopeKind::Group, &group_id)),
        Some(&group_id),
        Some(serde_json::json!({ "members": members })),
        true,
    );
    Ok(Redirect::to(&format!(
        "/admin/groups?flash=Group+{group_id}+saved"
    )))
}

#[derive(Deserialize)]
pub struct GroupIdForm {
    id: String,
}

pub async fn admin_delete_group(
    State(state): State<AppState>,
    user: CurrentUser,
    Form(form): Form<GroupIdForm>,
) -> AppResult<Redirect> {
    require_admin(&state, &user)?;
    state.stores.directory.delete_group(&form.id)?;
    Ok(Redirect::to("/admin/groups?flash=Group+deleted"))
}

#[derive(Deserialize)]
pub struct LinkChannelForm {
    scope: String,
    surface: String,
    external_id: String,
    #[serde(default)]
    label: Option<String>,
}

/// Bind an external conversation to a group, so a Telegram group or a Slack
/// channel shares one scope with the web UI.
pub async fn admin_link_channel(
    State(state): State<AppState>,
    user: CurrentUser,
    Form(form): Form<LinkChannelForm>,
) -> AppResult<Redirect> {
    require_admin(&state, &user)?;
    let scope = ScopeId::from_raw(form.scope.trim());
    state.stores.directory.link_channel(
        &form.surface,
        &form.external_id,
        &scope,
        form.label.as_deref(),
        user.id(),
    )?;
    state.stores.audit.record(
        user.id(),
        "admin.channel.link",
        Some(&scope),
        Some(&form.external_id),
        Some(serde_json::json!({ "surface": form.surface })),
        true,
    );
    Ok(Redirect::to("/admin/groups?flash=Conversation+linked"))
}

#[derive(Deserialize)]
pub struct UnlinkChannelForm {
    surface: String,
    external_id: String,
}

pub async fn admin_unlink_channel(
    State(state): State<AppState>,
    user: CurrentUser,
    Form(form): Form<UnlinkChannelForm>,
) -> AppResult<Redirect> {
    require_admin(&state, &user)?;
    state
        .stores
        .directory
        .unlink_channel(&form.surface, &form.external_id)?;
    Ok(Redirect::to("/admin/groups?flash=Conversation+unlinked"))
}
