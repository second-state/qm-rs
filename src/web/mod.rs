//! The web surface: server-rendered Tera pages plus a small JSON API.
//!
//! Upstream ships the web UI as a Vite + Lit single-page app over the core's
//! HTTP API. This port renders on the server with Tera instead. CSS and JS are
//! themselves Tera templates served from `/assets/*`, so there is no static
//! directory and no build step.
//!
//! # Authentication
//!
//! Every page and API handler takes a [`crate::auth::CurrentUser`], so a
//! handler cannot forget to check — it will not compile without one. Browsers
//! authenticate with an email magic link and a session cookie; programs send a
//! bearer API key. The only unauthenticated routes are the sign-in flow itself,
//! the Slack events webhook (which authenticates by request signature instead),
//! and the health check.

pub mod api;
pub mod pages;

use std::sync::Arc;

use axum::extract::State;
use axum::http::header;
use axum::response::{Html, IntoResponse};
use axum::routing::{get, post};

use crate::auth::routes as auth_routes;
use axum::Router;
use tera::{Context, Tera};

use crate::auth::email::Mailer;
use crate::config::Config;
use crate::connectors::SlackClient;
use crate::error::AppResult;
use crate::orchestrator::Orchestrator;
use crate::store::Stores;
use crate::types::ScopeId;

#[derive(Clone)]
pub struct AppState {
    pub orchestrator: Arc<Orchestrator>,
    pub templates: Arc<Tera>,
    pub config: Arc<Config>,
    pub stores: Stores,
    pub mailer: Arc<Mailer>,
    /// Present only when Slack runs in Events API mode; Socket Mode needs no
    /// inbound route.
    pub slack: Option<Arc<SlackClient>>,
}

impl AppState {
    pub fn org_scope(&self) -> ScopeId {
        ScopeId::org(&self.config.org.id)
    }

    /// Scopes the given principal may read: their own, every channel they
    /// belong to, and the org.
    pub fn scopes_for(&self, actor: &str) -> AppResult<Vec<ScopeId>> {
        let mut scopes = vec![ScopeId::personal(actor)];
        scopes.extend(self.stores.directory.reachable_channel_scopes(actor)?);
        scopes.push(self.org_scope());
        Ok(scopes)
    }
}

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/", get(pages::dashboard))
        .route("/sessions", get(pages::sessions).post(pages::new_session))
        .route("/sessions/:id", get(pages::session_detail))
        .route("/sessions/:id/message", post(pages::send_message))
        .route("/sessions/:id/approve", post(pages::resolve_approval))
        .route("/sessions/:id/archive", post(pages::archive_session))
        .route("/memory", get(pages::memory_index))
        .route(
            "/memory/:scope",
            get(pages::memory_edit).post(pages::memory_save),
        )
        .route("/skills", get(pages::skills).post(pages::create_skill))
        .route(
            "/skills/:id",
            get(pages::skill_detail).post(pages::update_skill),
        )
        .route("/skills/:id/status", post(pages::set_skill_status))
        .route("/skills/:id/delete", post(pages::delete_skill))
        .route("/crons", get(pages::crons).post(pages::create_cron))
        .route("/crons/:id/toggle", post(pages::toggle_cron))
        .route("/crons/:id/delete", post(pages::delete_cron))
        .route("/files", get(pages::files))
        .route("/files/:id", get(pages::download_file))
        .route("/keychain", get(pages::keychain).post(pages::put_keychain))
        .route("/keychain/delete", post(pages::delete_keychain))
        .route("/admin", get(pages::admin))
        // Sign-in. These are the routes a signed-out browser may reach.
        .route("/auth/login", get(auth_routes::login_form))
        .route("/auth/request", post(auth_routes::request_link))
        .route("/auth/callback", get(auth_routes::callback))
        .route("/auth/logout", post(auth_routes::logout))
        .route(
            "/auth/logout-everywhere",
            post(auth_routes::logout_everywhere),
        )
        .route("/account", get(auth_routes::account))
        .route("/account/keys", post(auth_routes::create_key))
        .route("/account/keys/revoke", post(auth_routes::revoke_key))
        // Slack Events API. Unauthenticated by cookie on purpose: it
        // authenticates by verifying Slack's request signature instead.
        .route("/slack/events", post(api::slack_events))
        // SSE is offered on both verbs: EventSource uses GET, and a fetch
        // stream traverses some proxies reliably only as POST.
        .route("/api/events", get(api::events).post(api::events))
        .route("/api/turn", post(api::turn))
        .route("/api/sessions/:id", get(api::session_json))
        .route("/api/health", get(api::health))
        .route("/assets/style.css", get(render_css))
        .route("/assets/app.js", get(render_js))
        .with_state(state)
}

pub fn render(state: &AppState, name: &str, ctx: &Context) -> AppResult<Html<String>> {
    Ok(Html(state.templates.render(name, ctx)?))
}

async fn render_css(State(state): State<AppState>) -> AppResult<impl IntoResponse> {
    Ok((
        [(header::CONTENT_TYPE, "text/css; charset=utf-8")],
        state
            .templates
            .render("static/style.css", &Context::new())?,
    ))
}

async fn render_js(State(state): State<AppState>) -> AppResult<impl IntoResponse> {
    Ok((
        [(
            header::CONTENT_TYPE,
            "application/javascript; charset=utf-8",
        )],
        state.templates.render("static/app.js", &Context::new())?,
    ))
}

/// Register the filters templates rely on.
pub fn build_templates(glob: &str) -> AppResult<Tera> {
    let mut tera = Tera::new(glob).map_err(|e| {
        crate::error::AppError::internal(format!("could not load templates from {glob}: {e}"))
    })?;
    tera.register_filter("relative_time", relative_time);
    tera.register_filter("mask_secret", mask_secret);
    Ok(tera)
}

/// `2026-08-01T09:00:00Z` → `3h ago`. Unparseable input passes through, so a
/// malformed timestamp shows as itself rather than blanking the cell.
fn relative_time(
    value: &tera::Value,
    _args: &std::collections::HashMap<String, tera::Value>,
) -> tera::Result<tera::Value> {
    let Some(raw) = value.as_str() else {
        return Ok(value.clone());
    };
    let Ok(parsed) = chrono::DateTime::parse_from_rfc3339(raw) else {
        return Ok(value.clone());
    };
    let delta = chrono::Utc::now().signed_duration_since(parsed.with_timezone(&chrono::Utc));
    let seconds = delta.num_seconds();
    let rendered = match seconds {
        s if s < 0 => format!("in {}", humanize(-s)),
        s if s < 45 => "just now".to_string(),
        s => format!("{} ago", humanize(s)),
    };
    Ok(tera::Value::String(rendered))
}

fn humanize(seconds: i64) -> String {
    match seconds {
        s if s < 90 => "a minute".to_string(),
        s if s < 3_600 => format!("{}m", s / 60),
        s if s < 86_400 => format!("{}h", s / 3_600),
        s if s < 2_592_000 => format!("{}d", s / 86_400),
        s => format!("{}mo", s / 2_592_000),
    }
}

fn mask_secret(
    value: &tera::Value,
    _args: &std::collections::HashMap<String, tera::Value>,
) -> tera::Result<tera::Value> {
    let Some(raw) = value.as_str() else {
        return Ok(value.clone());
    };
    Ok(tera::Value::String(crate::store::misc::mask(raw)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn call_relative(raw: &str) -> String {
        relative_time(&tera::Value::String(raw.into()), &HashMap::new())
            .unwrap()
            .as_str()
            .unwrap()
            .to_string()
    }

    #[test]
    fn relative_time_renders_recent_and_old_timestamps() {
        let now = chrono::Utc::now();
        assert_eq!(call_relative(&now.to_rfc3339()), "just now");
        assert_eq!(
            call_relative(&(now - chrono::Duration::hours(3)).to_rfc3339()),
            "3h ago"
        );
        assert_eq!(
            call_relative(&(now - chrono::Duration::days(2)).to_rfc3339()),
            "2d ago"
        );
        assert!(call_relative(&(now + chrono::Duration::hours(2)).to_rfc3339()).starts_with("in "));
    }

    #[test]
    fn an_unparseable_timestamp_passes_through_rather_than_blanking() {
        assert_eq!(call_relative("not a date"), "not a date");
        assert_eq!(
            relative_time(&tera::Value::Null, &HashMap::new()).unwrap(),
            tera::Value::Null
        );
    }

    #[test]
    fn the_mask_filter_never_renders_a_whole_secret() {
        let masked = mask_secret(
            &tera::Value::String("ghp_supersecretvalue".into()),
            &HashMap::new(),
        )
        .unwrap();
        assert!(!masked.as_str().unwrap().contains("supersecret"));
    }

    #[test]
    fn every_template_the_router_renders_parses() {
        // Catches a syntax error or a missing `{% endblock %}` at build time
        // rather than on the request that first hits the page.
        let tera = build_templates("templates/**/*").expect("templates load");
        let names: Vec<&str> = tera.get_template_names().collect();
        for expected in [
            "base.html",
            "dashboard.html",
            "sessions.html",
            "session.html",
            "memory_index.html",
            "memory_edit.html",
            "skills.html",
            "skill.html",
            "crons.html",
            "files.html",
            "keychain.html",
            "admin.html",
            "login.html",
            "account.html",
            "static/style.css",
            "static/app.js",
        ] {
            assert!(names.contains(&expected), "missing template {expected}");
        }
    }
}
