//! Sign-in routes: the login form, the link request, the callback, sign-out.

use axum::extract::{Form, Query, RawQuery, State};
use axum::http::header::{self, HeaderMap};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Redirect, Response};
use serde::Deserialize;
use tera::Context;

use super::{
    clear_session_cookie, email_allowed, principal_id_for, safe_next, session_cookie, urlencode,
    CurrentUser, SESSION_COOKIE,
};
use crate::error::{AppError, AppResult};
use crate::types::PrincipalKind;
use crate::web::{render, AppState};

#[derive(Deserialize)]
pub struct LoginQuery {
    #[serde(default)]
    next: Option<String>,
    #[serde(default)]
    sent: Option<String>,
    #[serde(default)]
    error: Option<String>,
}

/// The sign-in form.
pub async fn login_form(
    State(state): State<AppState>,
    Query(query): Query<LoginQuery>,
) -> AppResult<Response> {
    let mut ctx = Context::new();
    ctx.insert("page_title", "Sign in");
    ctx.insert("org_name", &state.config.org.name);
    ctx.insert("next", &safe_next(query.next.as_deref()));
    ctx.insert("sent", &query.sent.is_some());
    ctx.insert("console_mode", &!state.mailer.sends_mail());
    if let Some(error) = &query.error {
        ctx.insert("error", error);
    }
    Ok(render(&state, "login.html", &ctx)?.into_response())
}

#[derive(Deserialize)]
pub struct RequestForm {
    email: String,
    #[serde(default)]
    next: Option<String>,
}

/// Send a sign-in link.
///
/// The response is identical whether or not the address is allowed to sign in.
/// Telling the difference would turn this form into a membership oracle for
/// the organization.
pub async fn request_link(
    State(state): State<AppState>,
    Form(form): Form<RequestForm>,
) -> AppResult<Response> {
    let email = form.email.trim().to_ascii_lowercase();
    let next = safe_next(form.next.as_deref());
    let landing = format!("/auth/login?sent=1&next={}", urlencode(&next));

    if !email_allowed(&state.config.auth, &email) {
        tracing::info!(
            email,
            "sign-in requested for an address that is not allowed"
        );
        state
            .stores
            .audit
            .record(&email, "auth.request.rejected", None, None, None, false);
        return Ok(Redirect::to(&landing).into_response());
    }

    // Rate limit per address, so the form cannot be used to mail-bomb someone
    // who is allowed to sign in.
    let recent = state
        .stores
        .auth
        .recent_login_requests(&email, state.config.auth.request_window_secs)?;
    if recent >= state.config.auth.max_requests_per_window {
        tracing::warn!(email, recent, "sign-in link rate limit hit");
        state
            .stores
            .audit
            .record(&email, "auth.request.throttled", None, None, None, false);
        return Ok(Redirect::to(&landing).into_response());
    }

    // Find or create the principal behind this address.
    let principal_id = match state.stores.directory.principal_by_email(&email)? {
        Some(existing) => existing.id,
        None => {
            let directory = state.stores.directory.clone();
            let id = principal_id_for(&email, |candidate| {
                directory.principal(candidate).ok().flatten().is_some()
            });
            state.stores.directory.upsert_principal(
                &id,
                PrincipalKind::Internal,
                None,
                Some(&email),
            )?;
            tracing::info!(principal = %id, email, "registered a new principal from sign-in");
            id
        }
    };

    let token = state.stores.auth.create_login_token(
        &email,
        &principal_id,
        state.config.auth.login_token_ttl_secs,
    )?;
    let link = format!(
        "{}/auth/callback?token={}&next={}",
        state.config.auth.public_url.trim_end_matches('/'),
        token,
        urlencode(&next)
    );

    match state.mailer.send_login_link(&email, &link).await {
        Ok(delivery) => {
            state.stores.audit.record(
                &principal_id,
                "auth.request",
                None,
                Some(&email),
                Some(serde_json::json!({ "delivery": format!("{delivery:?}") })),
                true,
            );
        }
        Err(e) => {
            // Log the real reason; show the sender the same page regardless.
            tracing::error!(error = %e, email, "could not deliver the sign-in link");
            state.stores.audit.record(
                &principal_id,
                "auth.request.failed",
                None,
                Some(&email),
                None,
                false,
            );
        }
    }

    Ok(Redirect::to(&landing).into_response())
}

#[derive(Deserialize)]
pub struct CallbackQuery {
    #[serde(default)]
    token: Option<String>,
    #[serde(default)]
    next: Option<String>,
}

/// Consume a sign-in link and start a session.
pub async fn callback(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<CallbackQuery>,
) -> AppResult<Response> {
    let next = safe_next(query.next.as_deref());
    let Some(token) = query
        .token
        .as_deref()
        .map(str::trim)
        .filter(|t| !t.is_empty())
    else {
        return Ok(login_error("That sign-in link was incomplete.", &next));
    };

    let Some(principal_id) = state.stores.auth.consume_login_token(token)? else {
        return Ok(login_error(
            "That sign-in link has expired or was already used. Request a new one.",
            &next,
        ));
    };

    let session = state.stores.auth.create_session(
        &principal_id,
        state.config.auth.session_ttl_secs,
        headers
            .get(header::USER_AGENT)
            .and_then(|v| v.to_str().ok()),
    )?;

    state
        .stores
        .audit
        .record(&principal_id, "auth.signin", None, None, None, true);

    let secure = header_says_https(&headers);
    Ok((
        [
            (
                header::SET_COOKIE,
                session_cookie(&session, state.config.auth.session_ttl_secs, secure),
            ),
            (header::LOCATION, next),
        ],
        StatusCode::SEE_OTHER,
    )
        .into_response())
}

/// End the session this request is holding.
pub async fn logout(
    State(state): State<AppState>,
    headers: HeaderMap,
    user: CurrentUser,
) -> AppResult<Response> {
    if let Some(token) = cookie_from_headers(&headers, SESSION_COOKIE) {
        state.stores.auth.revoke_session(&token)?;
    }
    state
        .stores
        .audit
        .record(user.id(), "auth.signout", None, None, None, true);

    Ok((
        [
            (
                header::SET_COOKIE,
                clear_session_cookie(header_says_https(&headers)),
            ),
            (header::LOCATION, "/auth/login".to_string()),
        ],
        StatusCode::SEE_OTHER,
    )
        .into_response())
}

/// Sign out everywhere — the "I lost my laptop" button.
pub async fn logout_everywhere(
    State(state): State<AppState>,
    headers: HeaderMap,
    user: CurrentUser,
) -> AppResult<Response> {
    let revoked = state.stores.auth.revoke_all_sessions(user.id())?;
    state.stores.audit.record(
        user.id(),
        "auth.signout.all",
        None,
        None,
        Some(serde_json::json!({ "sessions": revoked })),
        true,
    );
    Ok((
        [
            (
                header::SET_COOKIE,
                clear_session_cookie(header_says_https(&headers)),
            ),
            (header::LOCATION, "/auth/login".to_string()),
        ],
        StatusCode::SEE_OTHER,
    )
        .into_response())
}

// ---------------------------------------------------------------------------
// Account page
// ---------------------------------------------------------------------------

pub async fn account(
    State(state): State<AppState>,
    user: CurrentUser,
    RawQuery(raw): RawQuery,
) -> AppResult<Response> {
    let mut ctx = Context::new();
    ctx.insert("page_title", "Account");
    ctx.insert("active_nav", "account");
    ctx.insert("org_name", &state.config.org.name);
    ctx.insert("actor", user.id());
    ctx.insert("email", &user.principal.email);
    ctx.insert("display_name", &user.principal.display_name);
    ctx.insert("is_admin", &user.is_admin(&state.config));
    ctx.insert(
        "keys",
        &state
            .stores
            .auth
            .list_api_keys(user.id())?
            .iter()
            .map(|k| {
                serde_json::json!({
                    "id": k.id, "prefix": k.prefix, "name": k.name,
                    "created_at": k.created_at, "last_used_at": k.last_used_at,
                    "revoked": k.revoked_at.is_some(),
                })
            })
            .collect::<Vec<_>>(),
    );
    ctx.insert(
        "sessions",
        &state
            .stores
            .auth
            .sessions_for(user.id())?
            .iter()
            .map(|s| {
                serde_json::json!({
                    "created_at": s.created_at, "last_seen_at": s.last_seen_at,
                    "expires_at": s.expires_at, "user_agent": s.user_agent,
                })
            })
            .collect::<Vec<_>>(),
    );

    // A freshly minted key is passed back once through the query string; it is
    // never stored anywhere it could be read again.
    if let Some(key) = raw
        .as_deref()
        .and_then(|q| {
            q.split('&').find_map(|pair| {
                let (k, v) = pair.split_once('=')?;
                (k == "new_key").then_some(v)
            })
        })
        .filter(|k| !k.is_empty())
    {
        ctx.insert("new_key", key);
    }

    Ok(render(&state, "account.html", &ctx)?.into_response())
}

#[derive(Deserialize)]
pub struct KeyForm {
    #[serde(default)]
    name: Option<String>,
}

pub async fn create_key(
    State(state): State<AppState>,
    user: CurrentUser,
    Form(form): Form<KeyForm>,
) -> AppResult<Redirect> {
    if user.via != super::AuthMethod::Session {
        // A key that could mint more keys would turn one leaked key into
        // permanent access that revoking the original does not undo.
        return Err(AppError::forbidden(
            "API keys can only be created from a signed-in browser session",
        ));
    }
    let (id, key) = state
        .stores
        .auth
        .create_api_key(user.id(), form.name.as_deref())?;
    state
        .stores
        .audit
        .record(user.id(), "auth.key.create", None, Some(&id), None, true);
    Ok(Redirect::to(&format!(
        "/account?new_key={}",
        urlencode(&key)
    )))
}

#[derive(Deserialize)]
pub struct RevokeForm {
    id: String,
}

pub async fn revoke_key(
    State(state): State<AppState>,
    user: CurrentUser,
    Form(form): Form<RevokeForm>,
) -> AppResult<Redirect> {
    state.stores.auth.revoke_api_key(&form.id, user.id())?;
    state.stores.audit.record(
        user.id(),
        "auth.key.revoke",
        None,
        Some(&form.id),
        None,
        true,
    );
    Ok(Redirect::to("/account"))
}

// ---------------------------------------------------------------------------

fn login_error(message: &str, next: &str) -> Response {
    Redirect::to(&format!(
        "/auth/login?error={}&next={}",
        urlencode(message),
        urlencode(next)
    ))
    .into_response()
}

fn header_says_https(headers: &HeaderMap) -> bool {
    headers
        .get("x-forwarded-proto")
        .and_then(|v| v.to_str().ok())
        .is_some_and(|proto| proto.split(',').next().unwrap_or("").trim() == "https")
}

fn cookie_from_headers(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get(header::COOKIE)?
        .to_str()
        .ok()?
        .split(';')
        .find_map(|c| {
            let (key, value) = c.split_once('=')?;
            (key.trim() == name).then(|| value.trim().to_string())
        })
        .filter(|v| !v.is_empty())
}
