//! The JSON API and the live event stream.

use std::convert::Infallible;

use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::{Deserialize, Serialize};
use tokio_stream::wrappers::BroadcastStream;
use tokio_stream::{Stream, StreamExt};

use super::AppState;
use crate::auth::CurrentUser;
use crate::error::{AppError, AppResult};
use crate::types::{
    ApprovalDecision, ApprovalScope, ScopeId, SessionType, TurnRequest, TurnResult,
};

/// Live turn events, for the chat view.
pub async fn events(
    State(state): State<AppState>,
    _user: CurrentUser,
) -> Sse<impl Stream<Item = Result<Event, Infallible>>> {
    let stream = BroadcastStream::new(state.orchestrator.events.subscribe()).filter_map(|event| {
        // A lagged receiver just missed some frames; the page re-reads on the
        // next `done` event, so dropping them is correct.
        let event = event.ok()?;
        let json = serde_json::to_string(&event).ok()?;
        Some(Ok(Event::default().event(event.kind.clone()).data(json)))
    });
    Sse::new(stream).keep_alive(KeepAlive::default())
}

#[derive(Debug, Deserialize)]
pub struct TurnBody {
    /// Run as someone else. Honoured **only** for the org admin, and audited;
    /// for everyone else the actor is the authenticated principal regardless of
    /// what the body says.
    #[serde(default)]
    pub actor: Option<String>,
    /// Scope id. Defaults to the actor's personal scope.
    #[serde(default)]
    pub scope: Option<String>,
    /// Thread to continue. A new one is opened when absent.
    #[serde(default)]
    pub thread_ref: Option<String>,
    #[serde(default)]
    pub surface: Option<String>,
    #[serde(default)]
    pub text: String,
    #[serde(default)]
    pub model: Option<String>,
    /// Resolve a pending approval instead of sending new work.
    #[serde(default)]
    pub approval: Option<ApprovalBody>,
}

#[derive(Debug, Deserialize)]
pub struct ApprovalBody {
    pub request_id: String,
    pub approved: bool,
    #[serde(default)]
    pub scope: Option<String>,
}

/// Run a turn. The same pipeline the web UI and Telegram use.
pub async fn turn(
    State(state): State<AppState>,
    user: CurrentUser,
    Json(body): Json<TurnBody>,
) -> AppResult<Json<TurnResult>> {
    let requested = body
        .actor
        .as_deref()
        .map(str::trim)
        .filter(|a| !a.is_empty());
    let actor = match requested {
        Some(other) if other != user.id() => {
            if !user.is_admin(&state.config) {
                return Err(AppError::forbidden(
                    "only the org admin may run a turn as another principal",
                ));
            }
            state
                .stores
                .audit
                .record(user.id(), "turn.impersonate", None, Some(other), None, true);
            other.to_string()
        }
        _ => user.id().to_string(),
    };

    let scope = match body
        .scope
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        Some(raw) => {
            let scope = ScopeId::from_raw(raw);
            if scope.kind().is_none() {
                return Err(AppError::bad_request(format!(
                    "{raw:?} is not a scope id — use `personal:<id>`, `channel:<name>` or `org:<id>`"
                )));
            }
            scope
        }
        None => ScopeId::personal(&actor),
    };

    if body.approval.is_none() && body.text.trim().is_empty() {
        return Err(AppError::bad_request("`text` is required"));
    }

    let thread_ref = body
        .thread_ref
        .as_deref()
        .map(str::trim)
        .filter(|t| !t.is_empty())
        .map(str::to_string)
        .unwrap_or_else(|| format!("api:{}", crate::db::new_id()));

    let mut request = TurnRequest::new(
        body.surface.as_deref().unwrap_or("api"),
        &actor,
        scope.clone(),
        thread_ref,
        body.text,
    )
    .with_origin(crate::types::TurnOrigin::Direct)
    .with_session_type(if scope.is_shared() {
        SessionType::Channel
    } else {
        SessionType::Dm
    });
    request.model = body.model;
    if let Some(approval) = body.approval {
        request.approval = Some(ApprovalDecision {
            request_id: approval.request_id,
            approved: approval.approved,
            scope: ApprovalScope::parse(approval.scope.as_deref().unwrap_or("once")),
        });
    }

    Ok(Json(state.orchestrator.handle_turn(request).await?))
}

#[derive(Serialize)]
pub struct SessionJson {
    pub id: String,
    pub title: String,
    pub scope: String,
    pub surface: String,
    pub thread_ref: String,
    pub archived: bool,
    pub entries: Vec<EntryJson>,
    pub pending_approvals: Vec<crate::types::PendingApproval>,
}

#[derive(Serialize)]
pub struct EntryJson {
    pub seq: i64,
    #[serde(rename = "type")]
    pub entry_type: String,
    pub text: String,
    pub author: Option<String>,
    pub created_at: String,
}

pub async fn session_json(
    State(state): State<AppState>,
    user: CurrentUser,
    Path(id): Path<String>,
) -> AppResult<Json<SessionJson>> {
    let session = state.stores.sessions.require(&id)?;
    if !state.scopes_for(user.id())?.contains(&session.scope_id) {
        return Err(AppError::forbidden(
            "that session is in a scope you cannot read",
        ));
    }
    let entries = state
        .stores
        .sessions
        .history(&id)?
        .into_iter()
        .map(|e| EntryJson {
            seq: e.seq,
            entry_type: e.entry_type.as_str().to_string(),
            text: e.text().to_string(),
            author: e.author().map(str::to_string),
            created_at: e.created_at,
        })
        .collect();

    Ok(Json(SessionJson {
        title: session.display_title(),
        id: session.id.clone(),
        scope: session.scope_id.to_string(),
        surface: session.surface,
        thread_ref: session.thread_ref,
        archived: session.archived,
        entries,
        pending_approvals: state.stores.approvals.pending_for_session(&id)?,
    }))
}

#[derive(Serialize)]
pub struct Health {
    pub ok: bool,
    pub harness: String,
    pub sessions: i64,
    pub plugins_active: bool,
    pub migrations: usize,
}

pub async fn health(State(state): State<AppState>) -> AppResult<Json<Health>> {
    Ok(Json(Health {
        ok: true,
        harness: state.orchestrator.harness.name().to_string(),
        sessions: state.stores.sessions.count()?,
        plugins_active: state.orchestrator.plugins.is_active(),
        migrations: crate::db::MIGRATIONS.len(),
    }))
}

// ---------------------------------------------------------------------------
// Slack Events API
// ---------------------------------------------------------------------------

/// Receive a Slack event over HTTP.
///
/// This route is deliberately outside the cookie-authenticated set: Slack has
/// no session with us. It authenticates by **request signature** instead, and
/// nothing in the body is looked at until that verifies — so an unsigned or
/// stale request never reaches the orchestrator.
pub async fn slack_events(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let Some(slack) = state.slack.clone() else {
        return (
            StatusCode::NOT_FOUND,
            "the Slack Events API is not enabled on this instance",
        )
            .into_response();
    };
    let Some(secret) = state.config.slack.resolve_signing_secret() else {
        tracing::error!("a slack event arrived but no signing secret is configured");
        return (StatusCode::INTERNAL_SERVER_ERROR, "slack is misconfigured").into_response();
    };

    let timestamp = headers
        .get("x-slack-request-timestamp")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();
    let signature = headers
        .get("x-slack-signature")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();
    let raw = String::from_utf8_lossy(&body);

    if !crate::connectors::slack::verify_signature(
        &secret,
        timestamp,
        &raw,
        signature,
        chrono::Utc::now().timestamp(),
    ) {
        tracing::warn!("rejected a slack event with a bad or stale signature");
        return (StatusCode::UNAUTHORIZED, "bad signature").into_response();
    }

    let Ok(envelope) = serde_json::from_str::<crate::connectors::slack::SlackEventEnvelope>(&raw)
    else {
        return (StatusCode::BAD_REQUEST, "malformed event").into_response();
    };

    // The one-off URL verification handshake echoes the challenge back.
    if let Some(challenge) = envelope.challenge.clone() {
        return challenge.into_response();
    }

    // Ack immediately and do the work in the background: Slack retries
    // anything unacked within three seconds, and a turn takes longer than
    // that. The event-id dedupe is what makes an early ack safe.
    tokio::spawn(async move {
        if let Err(e) = slack.handle_event(&envelope).await {
            tracing::warn!(error = %e, "could not handle a slack event");
        }
    });

    StatusCode::OK.into_response()
}
