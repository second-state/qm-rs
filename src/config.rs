//! Configuration, loaded from `config.toml` (path overridable via `QM_CONFIG`).
//!
//! Everything optional: a missing file yields defaults and the server still
//! boots. Secrets can be supplied via `QM_*` env vars, which take precedence
//! over the file, so `config.toml` never has to hold a credential.

use std::path::PathBuf;

use serde::Deserialize;

#[derive(Debug, Clone, Deserialize, Default)]
pub struct Config {
    #[serde(default)]
    pub server: ServerConfig,
    #[serde(default)]
    pub database: DatabaseConfig,
    #[serde(default)]
    pub org: OrgConfig,
    #[serde(default)]
    pub harness: HarnessConfig,
    #[serde(default)]
    pub sandbox: SandboxConfig,
    #[serde(default)]
    pub memory: MemoryConfig,
    #[serde(default)]
    pub cron: CronConfig,
    #[serde(default)]
    pub telegram: TelegramConfig,
    #[serde(default)]
    pub slack: SlackConfig,
    #[serde(default)]
    pub auth: AuthConfig,
    #[serde(default)]
    pub plugins: PluginsConfig,
}

/// Web sign-in: email magic links for people, bearer keys for programs.
#[derive(Debug, Clone, Deserialize)]
pub struct AuthConfig {
    /// Base URL sign-in links point back at. Must be reachable by whoever
    /// clicks the link — set this whenever the server is not on localhost.
    #[serde(default = "default_public_url")]
    pub public_url: String,
    /// Name used in the sign-in email.
    #[serde(default = "default_product_name")]
    pub product_name: String,

    /// How membership is decided.
    ///
    /// * `allowlist` (default) — only a listed or invited address may sign in.
    /// * `denylist` — any well-formed address may sign in unless its principal
    ///   has been deactivated. This is upstream QM's model, where being in the
    ///   Slack workspace *is* the membership and the admin offboards rather
    ///   than invites. Only appropriate when something else bounds who can
    ///   reach the server — an SSO proxy, a private network, or
    ///   `allowed_domains`.
    #[serde(default = "default_membership_mode")]
    pub membership_mode: String,

    /// The one address that may always sign in. Under `allowlist` with nothing
    /// else configured, this is the *only* address that may.
    #[serde(default)]
    pub admin_email: Option<String>,
    #[serde(default)]
    pub allowed_emails: Vec<String>,
    /// Bare domains, e.g. `acme.test`. Matched exactly, never as a suffix.
    #[serde(default)]
    pub allowed_domains: Vec<String>,

    /// `console` writes the link to the log; `resend` posts to the Resend API.
    #[serde(default = "default_email_mode")]
    pub email_mode: String,
    #[serde(default)]
    pub email_api_key: Option<String>,
    #[serde(default = "default_email_key_env")]
    pub email_api_key_env: String,
    /// Verified sender address, required for `resend`.
    #[serde(default)]
    pub from_address: Option<String>,

    #[serde(default = "default_login_ttl")]
    pub login_token_ttl_secs: i64,
    #[serde(default = "default_session_ttl")]
    pub session_ttl_secs: i64,
    /// Sign-in links allowed per address per window.
    #[serde(default = "default_max_requests")]
    pub max_requests_per_window: i64,
    #[serde(default = "default_request_window")]
    pub request_window_secs: i64,

    /// Adopted as an API key for the org admin on first boot, when no key
    /// exists yet. Lets a fresh install be driven by script before anyone has
    /// signed in. Prefer the `QM_BOOTSTRAP_API_KEY` env var.
    #[serde(default)]
    pub bootstrap_api_key: Option<String>,
}

fn default_public_url() -> String {
    "http://127.0.0.1:8080".to_string()
}
fn default_product_name() -> String {
    "QM".to_string()
}
fn default_membership_mode() -> String {
    "allowlist".to_string()
}
fn default_email_mode() -> String {
    "console".to_string()
}
fn default_email_key_env() -> String {
    "QM_EMAIL_API_KEY".to_string()
}
fn default_login_ttl() -> i64 {
    900
}
fn default_session_ttl() -> i64 {
    60 * 60 * 24 * 14
}
fn default_max_requests() -> i64 {
    5
}
fn default_request_window() -> i64 {
    600
}

impl Default for AuthConfig {
    fn default() -> Self {
        Self {
            public_url: default_public_url(),
            product_name: default_product_name(),
            membership_mode: default_membership_mode(),
            admin_email: None,
            allowed_emails: Vec::new(),
            allowed_domains: Vec::new(),
            email_mode: default_email_mode(),
            email_api_key: None,
            email_api_key_env: default_email_key_env(),
            from_address: None,
            login_token_ttl_secs: default_login_ttl(),
            session_ttl_secs: default_session_ttl(),
            max_requests_per_window: default_max_requests(),
            request_window_secs: default_request_window(),
            bootstrap_api_key: None,
        }
    }
}

impl AuthConfig {
    /// Whether membership is decided by deactivation rather than by a list.
    pub fn is_denylist(&self) -> bool {
        self.membership_mode.trim().eq_ignore_ascii_case("denylist")
    }

    /// True when `denylist` is set with nothing bounding who may reach the
    /// server — the configuration an operator most needs warning about.
    pub fn is_unbounded_denylist(&self) -> bool {
        self.is_denylist() && self.allowed_domains.is_empty()
    }

    pub fn resolve_email_api_key(&self) -> Option<String> {
        self.email_api_key
            .clone()
            .filter(|k| !k.trim().is_empty())
            .or_else(|| {
                std::env::var(&self.email_api_key_env)
                    .ok()
                    .filter(|k| !k.trim().is_empty())
            })
    }

    pub fn resolve_bootstrap_key(&self) -> Option<String> {
        self.bootstrap_api_key
            .clone()
            .filter(|k| !k.trim().is_empty())
            .or_else(|| {
                std::env::var("QM_BOOTSTRAP_API_KEY")
                    .ok()
                    .filter(|k| !k.trim().is_empty())
            })
    }
}

/// The Slack connector.
///
/// Socket Mode is the default: an outbound WebSocket, no public URL, mirroring
/// how the Telegram connector works. The Events API path exists for
/// deployments that already terminate HTTPS and would rather receive webhooks.
#[derive(Debug, Clone, Deserialize)]
pub struct SlackConfig {
    #[serde(default)]
    pub enabled: bool,
    /// Bot token, `xoxb-…`. Used for every Web API call.
    #[serde(default)]
    pub bot_token: Option<String>,
    #[serde(default = "default_slack_bot_env")]
    pub bot_token_env: String,
    /// App-level token, `xapp-…`, with `connections:write`. Required for
    /// Socket Mode.
    #[serde(default)]
    pub app_token: Option<String>,
    #[serde(default = "default_slack_app_env")]
    pub app_token_env: String,
    /// Signing secret, required to verify Events API requests.
    #[serde(default)]
    pub signing_secret: Option<String>,
    #[serde(default = "default_slack_signing_env")]
    pub signing_secret_env: String,

    /// `socket` (default) or `events`.
    #[serde(default = "default_slack_mode")]
    pub mode: String,
    #[serde(default = "default_slack_api")]
    pub api_base: String,

    /// When non-empty, only these channel ids are served.
    #[serde(default)]
    pub allowed_channels: Vec<String>,
    /// Slack user ids mapped to principal ids. An unmapped sender becomes a
    /// guest principal `slack:<user_id>`.
    #[serde(default)]
    pub principals: std::collections::HashMap<String, String>,
    /// Require an @mention before answering in a channel.
    #[serde(default = "default_true")]
    pub require_mention_in_channels: bool,
}

fn default_slack_bot_env() -> String {
    "QM_SLACK_BOT_TOKEN".to_string()
}
fn default_slack_app_env() -> String {
    "QM_SLACK_APP_TOKEN".to_string()
}
fn default_slack_signing_env() -> String {
    "QM_SLACK_SIGNING_SECRET".to_string()
}
fn default_slack_mode() -> String {
    "socket".to_string()
}
fn default_slack_api() -> String {
    "https://slack.com/api".to_string()
}

impl Default for SlackConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            bot_token: None,
            bot_token_env: default_slack_bot_env(),
            app_token: None,
            app_token_env: default_slack_app_env(),
            signing_secret: None,
            signing_secret_env: default_slack_signing_env(),
            mode: default_slack_mode(),
            api_base: default_slack_api(),
            allowed_channels: Vec::new(),
            principals: std::collections::HashMap::new(),
            require_mention_in_channels: true,
        }
    }
}

impl SlackConfig {
    pub fn resolve_bot_token(&self) -> Option<String> {
        resolve(&self.bot_token, &self.bot_token_env)
    }

    pub fn resolve_app_token(&self) -> Option<String> {
        resolve(&self.app_token, &self.app_token_env)
    }

    pub fn resolve_signing_secret(&self) -> Option<String> {
        resolve(&self.signing_secret, &self.signing_secret_env)
    }

    pub fn uses_socket_mode(&self) -> bool {
        !self.mode.trim().eq_ignore_ascii_case("events")
    }
}

fn resolve(value: &Option<String>, env_var: &str) -> Option<String> {
    value
        .clone()
        .filter(|v| !v.trim().is_empty())
        .or_else(|| std::env::var(env_var).ok().filter(|v| !v.trim().is_empty()))
}

#[derive(Debug, Clone, Deserialize)]
pub struct ServerConfig {
    #[serde(default = "default_host")]
    pub host: String,
    #[serde(default = "default_port")]
    pub port: u16,
}

fn default_host() -> String {
    "127.0.0.1".to_string()
}
fn default_port() -> u16 {
    8080
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            host: default_host(),
            port: default_port(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct DatabaseConfig {
    #[serde(default = "default_db_path")]
    pub path: String,
}

fn default_db_path() -> String {
    "data/qm.db".to_string()
}

impl Default for DatabaseConfig {
    fn default() -> Self {
        Self {
            path: default_db_path(),
        }
    }
}

/// Org-level floor. Narrower scopes may only tighten the security posture,
/// never loosen it — see `policy::security::compose_posture`.
#[derive(Debug, Clone, Deserialize)]
pub struct OrgConfig {
    #[serde(default = "default_org_id")]
    pub id: String,
    #[serde(default = "default_org_name")]
    pub name: String,
    /// strict | auto | dangerous. Defaults to `auto`, as upstream does.
    #[serde(default = "default_posture")]
    pub security_posture: String,
    /// Prepended to every resolved system prompt.
    #[serde(default)]
    pub system_prompt: Option<String>,
    #[serde(default = "default_timezone")]
    pub timezone: String,
    /// Principal id treated as the org administrator.
    #[serde(default = "default_admin")]
    pub admin: String,
}

fn default_org_id() -> String {
    "local".to_string()
}
fn default_org_name() -> String {
    "QM".to_string()
}
fn default_posture() -> String {
    "auto".to_string()
}
fn default_timezone() -> String {
    "UTC".to_string()
}
fn default_admin() -> String {
    "admin".to_string()
}

impl Default for OrgConfig {
    fn default() -> Self {
        Self {
            id: default_org_id(),
            name: default_org_name(),
            security_posture: default_posture(),
            system_prompt: None,
            timezone: default_timezone(),
            admin: default_admin(),
        }
    }
}

/// The model backend that drives a turn. `kind = "mock"` runs the
/// deterministic in-process harness used by the tests and the smoke script —
/// it needs no network and no credentials.
#[derive(Debug, Clone, Deserialize)]
pub struct HarnessConfig {
    #[serde(default = "default_harness_kind")]
    pub kind: String,
    /// OpenAI-compatible base URL, including the `/v1` suffix.
    #[serde(default)]
    pub endpoint: Option<String>,
    #[serde(default)]
    pub api_key: Option<String>,
    /// Name of the env var holding the key when `api_key` is unset.
    #[serde(default = "default_api_key_env")]
    pub api_key_env: String,
    #[serde(default = "default_model")]
    pub model: String,
    /// Cheaper model for the utility calls: titles, security screening.
    #[serde(default)]
    pub utility_model: Option<String>,
    /// Wall-clock cap for one turn.
    #[serde(default = "default_turn_timeout")]
    pub timeout_secs: u64,
    /// Cap on model round-trips in a single turn — the tool-loop bound.
    #[serde(default = "default_max_steps")]
    pub max_steps: u32,
    #[serde(default = "default_max_tokens")]
    pub max_tokens: u32,
}

fn default_harness_kind() -> String {
    "mock".to_string()
}
fn default_api_key_env() -> String {
    "QM_HARNESS_API_KEY".to_string()
}
fn default_model() -> String {
    "openai/gpt-5.4".to_string()
}
fn default_turn_timeout() -> u64 {
    600
}
fn default_max_steps() -> u32 {
    24
}
fn default_max_tokens() -> u32 {
    8192
}

impl Default for HarnessConfig {
    fn default() -> Self {
        Self {
            kind: default_harness_kind(),
            endpoint: None,
            api_key: None,
            api_key_env: default_api_key_env(),
            model: default_model(),
            utility_model: None,
            timeout_secs: default_turn_timeout(),
            max_steps: default_max_steps(),
            max_tokens: default_max_tokens(),
        }
    }
}

impl HarnessConfig {
    /// Key from the file if present, else from the configured env var.
    pub fn resolve_api_key(&self) -> Option<String> {
        self.api_key
            .clone()
            .filter(|k| !k.trim().is_empty())
            .or_else(|| {
                std::env::var(&self.api_key_env)
                    .ok()
                    .filter(|k| !k.trim().is_empty())
            })
    }
}

/// The scope's durable computer: where `execute` runs.
#[derive(Debug, Clone, Deserialize)]
pub struct SandboxConfig {
    /// Root under which each scope gets its own workspace directory.
    #[serde(default = "default_sandbox_root")]
    pub root_dir: PathBuf,
    #[serde(default = "default_exec_timeout")]
    pub exec_timeout_secs: u64,
    /// Bytes of combined stdout+stderr returned to the model per call.
    #[serde(default = "default_exec_output_cap")]
    pub max_output_bytes: usize,
}

fn default_sandbox_root() -> PathBuf {
    PathBuf::from("data/scopes")
}
fn default_exec_timeout() -> u64 {
    120
}
fn default_exec_output_cap() -> usize {
    32_000
}

impl Default for SandboxConfig {
    fn default() -> Self {
        Self {
            root_dir: default_sandbox_root(),
            exec_timeout_secs: default_exec_timeout(),
            max_output_bytes: default_exec_output_cap(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct MemoryConfig {
    /// off | writable | visible
    #[serde(default = "default_recall")]
    pub recall: String,
    /// off | writable
    #[serde(default = "default_capture")]
    pub capture: String,
}

fn default_recall() -> String {
    "visible".to_string()
}
fn default_capture() -> String {
    "writable".to_string()
}

impl Default for MemoryConfig {
    fn default() -> Self {
        Self {
            recall: default_recall(),
            capture: default_capture(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct CronConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// How often the scheduler wakes to look for due crons.
    #[serde(default = "default_cron_tick")]
    pub tick_seconds: u64,
    #[serde(default = "default_timezone")]
    pub default_timezone: String,
    /// A fire scheduled more than this far in the past is skipped rather than
    /// run late — a restart after a long outage must not stampede.
    #[serde(default = "default_cron_catchup")]
    pub max_catchup_secs: i64,
}

fn default_true() -> bool {
    true
}
fn default_cron_tick() -> u64 {
    30
}
fn default_cron_catchup() -> i64 {
    3600
}

impl Default for CronConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            tick_seconds: default_cron_tick(),
            default_timezone: default_timezone(),
            max_catchup_secs: default_cron_catchup(),
        }
    }
}

/// Telegram connector: long-polls `getUpdates` with a bot token. No webhook,
/// no public URL, no inbound port — it dials out only.
#[derive(Debug, Clone, Deserialize)]
pub struct TelegramConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub bot_token: Option<String>,
    #[serde(default = "default_telegram_token_env")]
    pub bot_token_env: String,
    #[serde(default = "default_telegram_api")]
    pub api_base: String,
    /// `getUpdates` long-poll seconds. Telegram holds the request open until a
    /// message arrives or this elapses.
    #[serde(default = "default_telegram_poll")]
    pub poll_timeout_secs: u64,
    /// When non-empty, only these chat ids are served. Every other chat is
    /// ignored — the connector is exposed to the open internet by virtue of
    /// the bot being addressable by anyone who knows its handle.
    #[serde(default)]
    pub allowed_chat_ids: Vec<i64>,
    /// Telegram user ids mapped to principal ids. An unmapped sender becomes a
    /// guest principal `telegram:<user_id>`.
    #[serde(default)]
    pub principals: std::collections::HashMap<String, String>,
    /// Require the bot to be @-mentioned in group chats before it answers.
    #[serde(default = "default_true")]
    pub require_mention_in_groups: bool,
}

fn default_telegram_token_env() -> String {
    "QM_TELEGRAM_BOT_TOKEN".to_string()
}
fn default_telegram_api() -> String {
    "https://api.telegram.org".to_string()
}
fn default_telegram_poll() -> u64 {
    50
}

impl Default for TelegramConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            bot_token: None,
            bot_token_env: default_telegram_token_env(),
            api_base: default_telegram_api(),
            poll_timeout_secs: default_telegram_poll(),
            allowed_chat_ids: Vec::new(),
            principals: std::collections::HashMap::new(),
            require_mention_in_groups: true,
        }
    }
}

impl TelegramConfig {
    pub fn resolve_token(&self) -> Option<String> {
        self.bot_token
            .clone()
            .filter(|t| !t.trim().is_empty())
            .or_else(|| {
                std::env::var(&self.bot_token_env)
                    .ok()
                    .filter(|t| !t.trim().is_empty())
            })
    }
}

/// WasmEdge extension points. Modules are `.wasm` files under `dir`, selected
/// per hook and per scope. Requires the `wasm` cargo feature; without it the
/// native no-op host is used and any configured module is reported as inert.
#[derive(Debug, Clone, Deserialize)]
pub struct PluginsConfig {
    #[serde(default = "default_plugins_dir")]
    pub dir: PathBuf,
    /// Middleware applied to every turn, in order, before the org/scope chain.
    #[serde(default)]
    pub turn_middleware: Vec<String>,
    /// Module answering the `screen` hook; falls back to the model screener.
    #[serde(default)]
    pub screener: Option<String>,
    /// Custom agent tools: `[[plugins.tools]]` entries.
    #[serde(default)]
    pub tools: Vec<PluginToolConfig>,
    /// Per-call wall-clock cap for a module.
    #[serde(default = "default_plugin_timeout")]
    pub timeout_ms: u64,
}

#[derive(Debug, Clone, Deserialize)]
pub struct PluginToolConfig {
    /// Tool name as the model sees it.
    pub name: String,
    pub description: String,
    /// `.wasm` filename under `plugins.dir`.
    pub module: String,
    /// JSON Schema for the tool's arguments, as a TOML-inlined JSON string.
    #[serde(default)]
    pub parameters: Option<String>,
    /// When set, the tool is offered only to these scope ids.
    #[serde(default)]
    pub scopes: Vec<String>,
}

fn default_plugins_dir() -> PathBuf {
    PathBuf::from("plugins/modules")
}
fn default_plugin_timeout() -> u64 {
    5_000
}

impl Default for PluginsConfig {
    fn default() -> Self {
        Self {
            dir: default_plugins_dir(),
            turn_middleware: Vec::new(),
            screener: None,
            tools: Vec::new(),
            timeout_ms: default_plugin_timeout(),
        }
    }
}

impl Config {
    /// Load from `QM_CONFIG` or `./config.toml`. A missing or unparseable file
    /// yields defaults so the server always boots.
    pub fn load() -> Self {
        let path = std::env::var("QM_CONFIG").unwrap_or_else(|_| "config.toml".to_string());
        let mut cfg = match std::fs::read_to_string(&path) {
            Ok(text) => match toml::from_str::<Config>(&text) {
                Ok(cfg) => cfg,
                Err(e) => {
                    tracing::error!(error = %e, path, "config.toml parse error — using defaults");
                    Config::default()
                }
            },
            Err(_) => {
                tracing::info!(path, "no config file found — using defaults");
                Config::default()
            }
        };
        cfg.apply_env_overrides();
        cfg
    }

    /// Env vars override file values so secrets stay out of `config.toml`.
    fn apply_env_overrides(&mut self) {
        if let Ok(v) = std::env::var("QM_HARNESS_KIND") {
            self.harness.kind = v;
        }
        if let Ok(v) = std::env::var("QM_HARNESS_ENDPOINT") {
            self.harness.endpoint = Some(v);
        }
        if let Ok(v) = std::env::var("QM_HARNESS_API_KEY") {
            self.harness.api_key = Some(v);
        }
        if let Ok(v) = std::env::var("QM_HARNESS_MODEL") {
            self.harness.model = v;
        }
        if let Ok(v) = std::env::var("QM_DATABASE_PATH") {
            self.database.path = v;
        }
        if let Ok(v) = std::env::var("QM_SECURITY_POSTURE") {
            self.org.security_posture = v;
        }
        if let Ok(v) = std::env::var("QM_TELEGRAM_BOT_TOKEN") {
            self.telegram.bot_token = Some(v);
            self.telegram.enabled = true;
        }
        if let Ok(v) = std::env::var("QM_SLACK_BOT_TOKEN") {
            self.slack.bot_token = Some(v);
            self.slack.enabled = true;
        }
        if let Ok(v) = std::env::var("QM_SLACK_APP_TOKEN") {
            self.slack.app_token = Some(v);
        }
        if let Ok(v) = std::env::var("QM_SLACK_SIGNING_SECRET") {
            self.slack.signing_secret = Some(v);
        }
        if let Ok(v) = std::env::var("QM_PUBLIC_URL") {
            self.auth.public_url = v;
        }
        if let Ok(v) = std::env::var("QM_ADMIN_EMAIL") {
            self.auth.admin_email = Some(v);
        }
        if let Ok(v) = std::env::var("QM_PORT") {
            match v.parse() {
                Ok(port) => self.server.port = port,
                Err(e) => tracing::warn!(error = %e, value = %v, "QM_PORT is not a port number"),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_config_gives_defaults() {
        let cfg: Config = toml::from_str("").unwrap();
        assert_eq!(cfg.server.port, 8080);
        assert_eq!(cfg.org.security_posture, "auto");
        assert_eq!(cfg.harness.kind, "mock");
        assert!(!cfg.telegram.enabled);
        assert!(cfg.plugins.tools.is_empty());
    }

    #[test]
    fn partial_config_parses_and_keeps_section_defaults() {
        let cfg: Config = toml::from_str(
            r#"
            [server]
            port = 9000

            [telegram]
            enabled = true
            bot_token = "123:abc"

            [[plugins.tools]]
            name = "lookup_order"
            description = "Look up an order"
            module = "orders.wasm"
            "#,
        )
        .unwrap();
        assert_eq!(cfg.server.port, 9000);
        assert_eq!(cfg.server.host, "127.0.0.1");
        assert_eq!(cfg.telegram.poll_timeout_secs, 50);
        assert!(cfg.telegram.require_mention_in_groups);
        assert_eq!(cfg.plugins.tools.len(), 1);
        assert_eq!(cfg.plugins.tools[0].name, "lookup_order");
    }

    #[test]
    fn api_key_falls_back_to_env_var() {
        let cfg = HarnessConfig {
            api_key: None,
            api_key_env: "QM_TEST_KEY_LOOKUP".to_string(),
            ..HarnessConfig::default()
        };
        assert!(cfg.resolve_api_key().is_none());
        std::env::set_var("QM_TEST_KEY_LOOKUP", "k");
        assert_eq!(cfg.resolve_api_key().as_deref(), Some("k"));
        std::env::remove_var("QM_TEST_KEY_LOOKUP");
    }

    #[test]
    fn blank_api_key_in_file_does_not_shadow_the_env_var() {
        let cfg = HarnessConfig {
            api_key: Some("   ".to_string()),
            api_key_env: "QM_TEST_KEY_BLANK".to_string(),
            ..HarnessConfig::default()
        };
        std::env::set_var("QM_TEST_KEY_BLANK", "real");
        assert_eq!(cfg.resolve_api_key().as_deref(), Some("real"));
        std::env::remove_var("QM_TEST_KEY_BLANK");
    }
}
