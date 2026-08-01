//! Sign-in.
//!
//! Email magic links for people, bearer keys for programs. Upstream QM puts
//! this in an `auth` plugin that emails a one-time link; the shape here is the
//! same, minus the pluggable identity-provider path.
//!
//! # What is stored
//!
//! Nothing that can be replayed. Session cookies, login links and API keys are
//! all high-entropy random strings shown to the holder exactly once and stored
//! only as a SHA-256 hash. Read access to the database therefore does not hand
//! an attacker a live session — the same reasoning that makes the skills table
//! store a signature rather than trusting its own rows.

pub mod email;
pub mod routes;
pub mod store;

use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Redirect, Response};
use rand::RngCore;
use sha2::{Digest, Sha256};

use crate::types::Principal;
use crate::web::AppState;

/// Name of the session cookie.
pub const SESSION_COOKIE: &str = "qm_session";
/// Bytes of entropy in a session token, login token or API key.
const TOKEN_BYTES: usize = 32;
/// Prefix that makes an API key recognisable in a log or a paste.
pub const API_KEY_PREFIX: &str = "qmk_";

/// A fresh random token, URL-safe.
///
/// `OsRng` rather than a seeded generator: these are credentials, and a
/// predictable one is a session anybody can mint.
pub fn generate_token() -> String {
    let mut bytes = [0u8; TOKEN_BYTES];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    hex_encode(&bytes)
}

pub fn generate_api_key() -> String {
    format!("{API_KEY_PREFIX}{}", generate_token())
}

/// What goes in the database. The token itself never does.
pub fn hash_token(token: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    hex_encode(&hasher.finalize())
}

pub fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(char::from_digit((byte >> 4) as u32, 16).unwrap_or('0'));
        out.push(char::from_digit((byte & 0x0f) as u32, 16).unwrap_or('0'));
    }
    out
}

/// Read one cookie out of a `Cookie` header.
pub fn cookie_value(parts: &Parts, name: &str) -> Option<String> {
    parts
        .headers
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

/// Whether an email may sign in at all.
///
/// An empty allowlist admits **only** the configured admin. Defaulting to
/// "anyone with an email address" would make a public deployment an open door,
/// so the safe reading is the one that requires an explicit decision.
pub fn email_allowed(config: &crate::config::AuthConfig, email: &str) -> bool {
    let email = email.trim().to_ascii_lowercase();
    // Both halves must be non-empty: `@acme.test` would otherwise match a
    // domain rule with no local part at all.
    match email.split_once('@') {
        Some((local, domain)) if !local.is_empty() && domain.contains('.') => {}
        _ => return false,
    }
    if config
        .admin_email
        .as_deref()
        .is_some_and(|a| a.trim().eq_ignore_ascii_case(&email))
    {
        return true;
    }
    if config
        .allowed_emails
        .iter()
        .any(|a| a.trim().eq_ignore_ascii_case(&email))
    {
        return true;
    }
    match email.split_once('@') {
        Some((_, domain)) => config.allowed_domains.iter().any(|d| {
            d.trim()
                .trim_start_matches('@')
                .eq_ignore_ascii_case(domain)
        }),
        None => false,
    }
}

/// Derive a principal id from an email address: `ada@acme.test` → `ada`, with
/// a disambiguating suffix when two domains share a local part.
pub fn principal_id_for(email: &str, taken: impl Fn(&str) -> bool) -> String {
    let local = email.split('@').next().unwrap_or(email);
    let base: String = local
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .collect();
    let base = base.trim_matches('-').to_string();
    let base = if base.is_empty() {
        "user".to_string()
    } else {
        base
    };

    if !taken(&base) {
        return base;
    }
    for n in 2..1000 {
        let candidate = format!("{base}-{n}");
        if !taken(&candidate) {
            return candidate;
        }
    }
    format!("{base}-{}", &generate_token()[..8])
}

// ---------------------------------------------------------------------------
// Extractors
// ---------------------------------------------------------------------------

/// An authenticated principal. Every page and API handler takes one, so a
/// handler cannot forget to check: the type system will not build without it.
#[derive(Debug, Clone)]
pub struct CurrentUser {
    pub principal: Principal,
    /// How this request authenticated — a browser session or an API key.
    pub via: AuthMethod,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthMethod {
    Session,
    ApiKey,
}

impl CurrentUser {
    pub fn id(&self) -> &str {
        &self.principal.id
    }

    /// Whether this principal is the org administrator.
    pub fn is_admin(&self, config: &crate::config::Config) -> bool {
        self.principal.id == config.org.admin
    }
}

/// Rejection for a page request: send the browser to the login form, carrying
/// where it was going so the round trip lands back there.
pub struct RedirectToLogin(pub String);

impl IntoResponse for RedirectToLogin {
    fn into_response(self) -> Response {
        let target = urlencode(&self.0);
        Redirect::to(&format!("/auth/login?next={target}")).into_response()
    }
}

pub enum AuthRejection {
    Page(RedirectToLogin),
    Api(StatusCode, &'static str),
}

impl IntoResponse for AuthRejection {
    fn into_response(self) -> Response {
        match self {
            Self::Page(redirect) => redirect.into_response(),
            Self::Api(status, message) => (status, message).into_response(),
        }
    }
}

#[async_trait::async_trait]
impl FromRequestParts<AppState> for CurrentUser {
    type Rejection = AuthRejection;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let is_api = parts.uri.path().starts_with("/api/");

        // A bearer key first: a program that sends one wants that identity even
        // if a stale browser cookie is also present.
        if let Some(key) = bearer_token(parts) {
            return match state.stores.auth.principal_for_api_key(&key) {
                Ok(Some(principal)) => Ok(Self {
                    principal,
                    via: AuthMethod::ApiKey,
                }),
                _ => Err(reject(is_api, parts, "invalid or revoked API key")),
            };
        }

        if let Some(token) = cookie_value(parts, SESSION_COOKIE) {
            if let Ok(Some(principal)) = state.stores.auth.principal_for_session(&token) {
                return Ok(Self {
                    principal,
                    via: AuthMethod::Session,
                });
            }
        }

        Err(reject(is_api, parts, "sign in first"))
    }
}

fn reject(is_api: bool, parts: &Parts, message: &'static str) -> AuthRejection {
    if is_api {
        AuthRejection::Api(StatusCode::UNAUTHORIZED, message)
    } else {
        AuthRejection::Page(RedirectToLogin(
            parts
                .uri
                .path_and_query()
                .map(|p| p.as_str().to_string())
                .unwrap_or_else(|| "/".into()),
        ))
    }
}

fn bearer_token(parts: &Parts) -> Option<String> {
    let raw = parts.headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    let token = raw
        .strip_prefix("Bearer ")
        .or_else(|| raw.strip_prefix("bearer "))?
        .trim();
    (!token.is_empty()).then(|| token.to_string())
}

/// Percent-encode everything outside the unreserved set. Used on the `next`
/// parameter, which is attacker-influenced.
pub fn urlencode(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(byte as char)
            }
            _ => out.push_str(&format!("%{byte:02X}")),
        }
    }
    out
}

/// Only a local path is a safe redirect target. A protocol-relative `//host`
/// or an absolute URL would make the login form an open redirect.
pub fn safe_next(next: Option<&str>) -> String {
    next.map(str::trim)
        .filter(|n| n.starts_with('/') && !n.starts_with("//") && !n.contains('\\'))
        .unwrap_or("/")
        .to_string()
}

/// The `Set-Cookie` value for a session.
///
/// `Secure` is set when the request arrived over HTTPS, so a plain-HTTP
/// localhost run still works while any real deployment is `Secure`
/// automatically. `HttpOnly` keeps it away from scripts; `SameSite=Lax` blocks
/// it on cross-site form posts.
pub fn session_cookie(token: &str, max_age_secs: i64, secure: bool) -> String {
    let mut cookie =
        format!("{SESSION_COOKIE}={token}; Path=/; HttpOnly; SameSite=Lax; Max-Age={max_age_secs}");
    if secure {
        cookie.push_str("; Secure");
    }
    cookie
}

pub fn clear_session_cookie(secure: bool) -> String {
    let mut cookie = format!("{SESSION_COOKIE}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0");
    if secure {
        cookie.push_str("; Secure");
    }
    cookie
}

/// Whether this request reached us over HTTPS, honouring a proxy's
/// `X-Forwarded-Proto`.
pub fn request_is_secure(parts: &Parts) -> bool {
    if parts.uri.scheme_str() == Some("https") {
        return true;
    }
    parts
        .headers
        .get("x-forwarded-proto")
        .and_then(|v| v.to_str().ok())
        .is_some_and(|proto| proto.split(',').next().unwrap_or("").trim() == "https")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::AuthConfig;

    #[test]
    fn tokens_are_long_random_and_distinct() {
        let a = generate_token();
        let b = generate_token();
        assert_eq!(a.len(), TOKEN_BYTES * 2);
        assert_ne!(a, b);
        assert!(a.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn api_keys_carry_a_recognisable_prefix() {
        let key = generate_api_key();
        assert!(key.starts_with(API_KEY_PREFIX));
        assert!(key.len() > 32);
    }

    #[test]
    fn hashing_is_stable_and_hides_the_token() {
        let token = generate_token();
        assert_eq!(hash_token(&token), hash_token(&token));
        assert_ne!(hash_token(&token), token);
        assert_eq!(hash_token("a").len(), 64);
        assert_ne!(hash_token("a"), hash_token("b"));
    }

    fn config(admin: Option<&str>, emails: &[&str], domains: &[&str]) -> AuthConfig {
        AuthConfig {
            admin_email: admin.map(str::to_string),
            allowed_emails: emails.iter().map(|e| e.to_string()).collect(),
            allowed_domains: domains.iter().map(|d| d.to_string()).collect(),
            ..AuthConfig::default()
        }
    }

    #[test]
    fn an_empty_allowlist_admits_only_the_admin() {
        let c = config(Some("ada@acme.test"), &[], &[]);
        assert!(email_allowed(&c, "ada@acme.test"));
        assert!(email_allowed(&c, "ADA@ACME.TEST"), "case-insensitive");
        assert!(
            !email_allowed(&c, "stranger@acme.test"),
            "an empty allowlist must not admit the world"
        );
    }

    #[test]
    fn allowlists_admit_by_address_and_by_domain() {
        let c = config(None, &["bob@other.test"], &["acme.test"]);
        assert!(email_allowed(&c, "bob@other.test"));
        assert!(email_allowed(&c, "anyone@acme.test"));
        assert!(!email_allowed(&c, "anyone@elsewhere.test"));

        // A leading @ on a configured domain is tolerated.
        let with_at = config(None, &[], &["@acme.test"]);
        assert!(email_allowed(&with_at, "x@acme.test"));
    }

    #[test]
    fn a_domain_rule_does_not_match_a_lookalike_suffix() {
        let c = config(None, &[], &["acme.test"]);
        assert!(
            !email_allowed(&c, "x@evil-acme.test"),
            "domain matching must be exact, not a suffix check"
        );
        assert!(!email_allowed(&c, "x@acme.test.evil.com"));
    }

    #[test]
    fn malformed_addresses_are_refused() {
        let c = config(Some("ada@acme.test"), &[], &["acme.test"]);
        for bad in ["", "   ", "not-an-email", "@acme.test", "ada@"] {
            assert!(!email_allowed(&c, bad), "{bad:?} should be refused");
        }
    }

    #[test]
    fn principal_ids_are_derived_and_disambiguated() {
        assert_eq!(principal_id_for("ada@acme.test", |_| false), "ada");
        assert_eq!(
            principal_id_for("Ada.Lovelace@acme.test", |_| false),
            "ada-lovelace"
        );
        assert_eq!(principal_id_for("a+tag@acme.test", |_| false), "a-tag");

        // A collision gets a suffix rather than merging two people.
        assert_eq!(
            principal_id_for("ada@other.test", |id| id == "ada"),
            "ada-2"
        );
        assert_eq!(
            principal_id_for("ada@third.test", |id| id == "ada" || id == "ada-2"),
            "ada-3"
        );
    }

    #[test]
    fn a_degenerate_local_part_still_yields_a_usable_id() {
        assert_eq!(principal_id_for("...@acme.test", |_| false), "user");
        assert_eq!(principal_id_for("@acme.test", |_| false), "user");
    }

    #[test]
    fn only_local_paths_survive_the_next_parameter() {
        assert_eq!(safe_next(Some("/sessions/abc")), "/sessions/abc");
        assert_eq!(safe_next(Some("/a?b=c")), "/a?b=c");
        assert_eq!(safe_next(None), "/");
        for hostile in [
            "//evil.test",
            "https://evil.test",
            "http://evil.test",
            "/\\evil.test",
            "evil.test",
        ] {
            assert_eq!(
                safe_next(Some(hostile)),
                "/",
                "{hostile:?} must not be a redirect target"
            );
        }
    }

    #[test]
    fn urlencoding_escapes_everything_outside_the_unreserved_set() {
        assert_eq!(urlencode("/a/b"), "%2Fa%2Fb");
        assert_eq!(urlencode("a-b_c.d~e"), "a-b_c.d~e");
        assert_eq!(urlencode("a b"), "a%20b");
        assert_eq!(urlencode("\"><script>"), "%22%3E%3Cscript%3E");
    }

    #[test]
    fn the_session_cookie_is_hardened_and_secure_only_over_https() {
        let plain = session_cookie("abc", 3600, false);
        assert!(plain.contains("HttpOnly"));
        assert!(plain.contains("SameSite=Lax"));
        assert!(plain.contains("Max-Age=3600"));
        assert!(
            !plain.contains("Secure"),
            "plain HTTP localhost must still work"
        );

        assert!(session_cookie("abc", 3600, true).contains("; Secure"));
        assert!(clear_session_cookie(false).contains("Max-Age=0"));
    }

    #[test]
    fn hex_encoding_round_trips_through_known_values() {
        assert_eq!(hex_encode(&[0x00, 0x0f, 0xff]), "000fff");
        assert_eq!(hex_encode(&[]), "");
    }
}
