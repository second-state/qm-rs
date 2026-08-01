//! The Slack connector.
//!
//! Two ways in, one way through:
//!
//! * **Socket Mode** (default) — `apps.connections.open` returns a WebSocket
//!   URL; events arrive over that outbound connection. No public URL, no
//!   inbound port, same shape as the Telegram connector.
//! * **Events API** — Slack POSTs to `/slack/events`. Every request is
//!   signature-verified before it is looked at.
//!
//! Both paths converge on [`SlackClient::handle_and_reply`], so routing,
//! dedupe and posting behave identically whichever transport a deployment
//! picks.
//!
//! # Mapping
//!
//! * a DM (`channel_type: "im"`) → the sender's **personal** scope;
//! * a channel or group → `channel:slack-<channel_id>`, so what the agent
//!   learns in a channel belongs to the channel;
//! * a Slack user id → the principal named in `[slack.principals]`, or a guest
//!   principal `slack:<user_id>`.

use std::sync::Arc;

use hmac::{Hmac, Mac};
use serde::Deserialize;
use sha2::Sha256;
use tokio::time::{sleep, Duration};

use crate::auth::hex_encode;
use crate::config::SlackConfig;
use crate::error::{AppError, AppResult};
use crate::orchestrator::Orchestrator;
use crate::store::Stores;
use crate::types::{PrincipalKind, ScopeId, SessionType, TurnRequest, TurnStatus};

type HmacSha256 = Hmac<Sha256>;

/// Slack truncates a message past this; longer replies are split.
const MAX_MESSAGE_CHARS: usize = 3000;
/// Requests older than this are refused even with a valid signature, which is
/// what stops a captured request being replayed later.
const MAX_SIGNATURE_AGE_SECS: i64 = 60 * 5;

// ---------------------------------------------------------------------------
// Wire types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Deserialize)]
pub struct SlackEventEnvelope {
    #[serde(default)]
    pub event_id: Option<String>,
    #[serde(default)]
    pub event: Option<SlackEvent>,
    /// Present on the one-off URL verification handshake.
    #[serde(default)]
    pub challenge: Option<String>,
    #[serde(rename = "type", default)]
    pub kind: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct SlackEvent {
    #[serde(rename = "type", default)]
    pub kind: String,
    #[serde(default)]
    pub text: Option<String>,
    #[serde(default)]
    pub user: Option<String>,
    #[serde(default)]
    pub channel: Option<String>,
    #[serde(default)]
    pub channel_type: Option<String>,
    #[serde(default)]
    pub ts: Option<String>,
    #[serde(default)]
    pub thread_ts: Option<String>,
    /// Set on messages the bot itself posted.
    #[serde(default)]
    pub bot_id: Option<String>,
    /// `message_changed`, `message_deleted`, …
    #[serde(default)]
    pub subtype: Option<String>,
}

/// A reply the connector decided to send, before it is posted.
///
/// Deciding and posting are separate so the decision logic — filtering,
/// routing, dedupe, running the turn — is exercisable without a network round
/// trip, and so a delivery failure cannot be mistaken for a turn failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutboundReply {
    pub channel: String,
    pub text: String,
    pub thread_ts: Option<String>,
}

/// Where one inbound message should run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Routing {
    pub scope: ScopeId,
    pub principal: String,
    pub session_type: SessionType,
    pub thread_ref: String,
    pub channel_name: Option<String>,
}

// ---------------------------------------------------------------------------
// Client
// ---------------------------------------------------------------------------

pub struct SlackClient {
    config: SlackConfig,
    bot_token: String,
    client: reqwest::Client,
    orchestrator: Arc<Orchestrator>,
    stores: Stores,
    bot_user_id: Option<String>,
}

/// Hand-written so a derived `Debug` cannot print the bot token.
impl std::fmt::Debug for SlackClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SlackClient")
            .field("mode", &self.config.mode)
            .field("bot_token", &"<redacted>")
            .field("bot_user_id", &self.bot_user_id)
            .field("allowed_channels", &self.config.allowed_channels)
            .finish()
    }
}

impl SlackClient {
    pub fn new(config: SlackConfig, orchestrator: Arc<Orchestrator>) -> AppResult<Self> {
        let bot_token = config.resolve_bot_token().ok_or_else(|| {
            AppError::bad_request(format!(
                "[slack].enabled is true but no bot token is set — put it in \
                 [slack].bot_token or the {} env var",
                config.bot_token_env
            ))
        })?;
        if config.uses_socket_mode() && config.resolve_app_token().is_none() {
            return Err(AppError::bad_request(format!(
                "Socket Mode needs an app-level token with connections:write — put it in \
                 [slack].app_token or the {} env var, or set mode = \"events\"",
                config.app_token_env
            )));
        }
        if !config.uses_socket_mode() && config.resolve_signing_secret().is_none() {
            return Err(AppError::bad_request(format!(
                "the Events API needs a signing secret to verify requests — put it in \
                 [slack].signing_secret or the {} env var",
                config.signing_secret_env
            )));
        }

        let stores = orchestrator.stores.clone();
        Ok(Self {
            client: reqwest::Client::builder()
                .timeout(Duration::from_secs(30))
                .build()?,
            config,
            bot_token,
            orchestrator,
            stores,
            bot_user_id: None,
        })
    }

    fn url(&self, method: &str) -> String {
        format!("{}/{method}", self.config.api_base.trim_end_matches('/'))
    }

    /// Learn the bot's own user id, needed to detect mentions and to ignore
    /// the bot's own messages.
    pub async fn authenticate(&mut self) -> AppResult<()> {
        #[derive(Deserialize)]
        struct AuthTest {
            #[serde(default)]
            ok: bool,
            #[serde(default)]
            user_id: Option<String>,
            #[serde(default)]
            error: Option<String>,
        }
        let response: AuthTest = self
            .client
            .post(self.url("auth.test"))
            .bearer_auth(&self.bot_token)
            .send()
            .await?
            .json()
            .await?;
        if !response.ok {
            return Err(AppError::bad_request(format!(
                "Slack rejected the bot token: {}",
                response.error.unwrap_or_else(|| "unknown error".into())
            )));
        }
        self.bot_user_id = response.user_id;
        tracing::info!(
            bot_user_id = self.bot_user_id.as_deref().unwrap_or("unknown"),
            "slack connector authenticated"
        );
        Ok(())
    }

    pub fn bot_user_id(&self) -> Option<&str> {
        self.bot_user_id.as_deref()
    }

    /// Handle one event envelope and post whatever it produced.
    ///
    /// Returns whether a turn actually ran.
    pub async fn handle_and_reply(&self, envelope: &SlackEventEnvelope) -> AppResult<bool> {
        let Some(reply) = self.handle_event(envelope).await? else {
            return Ok(false);
        };
        if !reply.text.trim().is_empty() {
            self.post_message(&reply.channel, &reply.text, reply.thread_ts.as_deref())
                .await?;
        }
        Ok(true)
    }

    /// Decide what this event should produce, running the turn if it warrants
    /// one. `None` means the event was deliberately ignored.
    pub async fn handle_event(
        &self,
        envelope: &SlackEventEnvelope,
    ) -> AppResult<Option<OutboundReply>> {
        // Slack redelivers on a slow ack, and Socket Mode redelivers on
        // reconnect. One row per event id makes a retry a no-op.
        if let Some(event_id) = envelope.event_id.as_deref() {
            if !self.stores.slack_dedupe.claim(event_id)? {
                tracing::debug!(event_id, "ignoring a redelivered slack event");
                return Ok(None);
            }
        }

        let Some(event) = &envelope.event else {
            return Ok(None);
        };
        if !matches!(event.kind.as_str(), "message" | "app_mention") {
            return Ok(None);
        }
        // An edit or a deletion is not a new question.
        if event.subtype.is_some() {
            return Ok(None);
        }
        // Never answer ourselves, or any other bot: two bots in a channel
        // would talk to each other indefinitely.
        if event.bot_id.is_some() {
            return Ok(None);
        }
        let Some(user) = event.user.as_deref().filter(|u| !u.is_empty()) else {
            return Ok(None);
        };
        if self.bot_user_id.as_deref() == Some(user) {
            return Ok(None);
        }

        let Some(text) = event
            .text
            .as_deref()
            .map(str::trim)
            .filter(|t| !t.is_empty())
        else {
            return Ok(None);
        };
        let Some(channel) = event.channel.as_deref().filter(|c| !c.is_empty()) else {
            return Ok(None);
        };

        if !self.config.allowed_channels.is_empty()
            && !self.config.allowed_channels.iter().any(|c| c == channel)
        {
            tracing::debug!(channel, "ignoring a channel outside the allowlist");
            return Ok(None);
        }

        let is_dm = event.channel_type.as_deref() == Some("im");
        let addressed = self.is_addressed(text) || event.kind == "app_mention";
        if !is_dm && self.config.require_mention_in_channels && !addressed {
            return Ok(None);
        }

        let routing = self.route(event, user, is_dm);
        self.stores.directory.upsert_principal(
            &routing.principal,
            if self.config.principals.contains_key(user) {
                PrincipalKind::Internal
            } else {
                PrincipalKind::Guest
            },
            None,
            None,
        )?;
        if routing.scope.is_shared() {
            self.stores.directory.upsert_channel(
                routing.scope.reference(),
                routing
                    .channel_name
                    .as_deref()
                    .unwrap_or(routing.scope.reference()),
                "channel",
                true,
            )?;
            self.stores
                .directory
                .add_channel_member(routing.scope.reference(), &routing.principal)?;
        }

        let request = TurnRequest {
            channel_name: routing.channel_name.clone(),
            ..TurnRequest::new(
                "slack",
                &routing.principal,
                routing.scope.clone(),
                &routing.thread_ref,
                strip_mention(text, self.bot_user_id.as_deref()),
            )
            .with_session_type(routing.session_type)
        };

        let result = self.orchestrator.handle_turn(request).await?;
        let reply = match result.status {
            TurnStatus::Silent => {
                return Ok(Some(OutboundReply {
                    channel: channel.to_string(),
                    text: String::new(),
                    thread_ts: None,
                }))
            }
            TurnStatus::PendingApproval => format!(
                "That needs approval before I run it: `{}`. Approve it in the web UI.",
                result
                    .pending_approvals
                    .first()
                    .map(|a| a.command.as_str())
                    .unwrap_or("(unknown command)")
            ),
            TurnStatus::Refused | TurnStatus::Failed => result
                .reason
                .unwrap_or_else(|| "I couldn't do that.".to_string()),
            TurnStatus::Ok => result.reply,
        };

        // Reply in-thread when the message was already in one, so a busy
        // channel does not get flooded at top level.
        let thread_ts =
            event
                .thread_ts
                .clone()
                .or_else(|| if is_dm { None } else { event.ts.clone() });

        Ok(Some(OutboundReply {
            channel: channel.to_string(),
            text: reply,
            thread_ts,
        }))
    }

    fn is_addressed(&self, text: &str) -> bool {
        match &self.bot_user_id {
            Some(id) => text.contains(&format!("<@{id}>")),
            None => false,
        }
    }

    fn route(&self, event: &SlackEvent, user: &str, is_dm: bool) -> Routing {
        let principal = self
            .config
            .principals
            .get(user)
            .cloned()
            .unwrap_or_else(|| format!("slack:{user}"));
        let channel = event.channel.clone().unwrap_or_default();

        if is_dm {
            Routing {
                scope: ScopeId::personal(&principal),
                principal,
                session_type: SessionType::Dm,
                thread_ref: format!("slack:{channel}"),
                channel_name: None,
            }
        } else {
            let reference = format!("slack-{channel}");
            // One session per Slack thread, so two conversations in the same
            // channel do not interleave into one transcript.
            let thread_ref = match event.thread_ts.as_deref() {
                Some(ts) => format!("slack:{channel}:{ts}"),
                None => format!("slack:{channel}"),
            };
            Routing {
                scope: ScopeId::channel(&reference),
                principal,
                session_type: SessionType::Channel,
                thread_ref,
                channel_name: Some(reference),
            }
        }
    }

    /// Post a reply, splitting anything past Slack's practical length limit.
    pub async fn post_message(
        &self,
        channel: &str,
        text: &str,
        thread_ts: Option<&str>,
    ) -> AppResult<()> {
        #[derive(Deserialize)]
        struct PostResponse {
            #[serde(default)]
            ok: bool,
            #[serde(default)]
            error: Option<String>,
        }

        for chunk in split_message(text) {
            let mut body = serde_json::json!({ "channel": channel, "text": chunk });
            if let Some(ts) = thread_ts {
                body["thread_ts"] = serde_json::json!(ts);
            }
            let response: PostResponse = self
                .client
                .post(self.url("chat.postMessage"))
                .bearer_auth(&self.bot_token)
                .json(&body)
                .send()
                .await?
                .json()
                .await?;
            if !response.ok {
                return Err(AppError::internal(format!(
                    "chat.postMessage failed: {}",
                    response.error.unwrap_or_else(|| "unknown error".into())
                )));
            }
        }
        Ok(())
    }

    // -- Socket Mode --------------------------------------------------------

    /// Open a Socket Mode connection and serve it until it drops.
    async fn connect_socket(&self) -> AppResult<String> {
        #[derive(Deserialize)]
        struct OpenResponse {
            #[serde(default)]
            ok: bool,
            #[serde(default)]
            url: Option<String>,
            #[serde(default)]
            error: Option<String>,
        }
        let app_token = self
            .config
            .resolve_app_token()
            .ok_or_else(|| AppError::bad_request("Socket Mode needs an app-level token"))?;

        let response: OpenResponse = self
            .client
            .post(self.url("apps.connections.open"))
            .bearer_auth(&app_token)
            .send()
            .await?
            .json()
            .await?;
        if !response.ok {
            return Err(AppError::bad_request(format!(
                "apps.connections.open failed: {}",
                response.error.unwrap_or_else(|| "unknown error".into())
            )));
        }
        response
            .url
            .ok_or_else(|| AppError::internal("apps.connections.open returned no url"))
    }

    /// Run the Socket Mode loop forever, reconnecting with backoff.
    pub async fn run_socket_mode(mut self) {
        if let Err(e) = self.authenticate().await {
            tracing::error!(error = %e, "slack connector could not start");
            return;
        }

        let mut backoff = Duration::from_secs(1);
        loop {
            match self.serve_one_socket().await {
                Ok(()) => {
                    // A clean disconnect is normal: Slack cycles connections.
                    tracing::info!("slack socket closed; reconnecting");
                    backoff = Duration::from_secs(1);
                }
                Err(e) => {
                    tracing::warn!(error = %e, backoff = ?backoff, "slack socket failed");
                    sleep(backoff).await;
                    backoff = (backoff * 2).min(Duration::from_secs(60));
                }
            }
        }
    }

    async fn serve_one_socket(&self) -> AppResult<()> {
        use futures_util::{SinkExt, StreamExt};
        use tokio_tungstenite::tungstenite::Message;

        let url = self.connect_socket().await?;
        let (stream, _) = tokio_tungstenite::connect_async(&url)
            .await
            .map_err(|e| AppError::internal(format!("slack websocket connect failed: {e}")))?;
        tracing::info!("slack socket mode connected");
        let (mut write, mut read) = stream.split();

        while let Some(message) = read.next().await {
            let message =
                message.map_err(|e| AppError::internal(format!("slack websocket error: {e}")))?;
            let Message::Text(payload) = message else {
                continue;
            };

            let Ok(frame) = serde_json::from_str::<SocketFrame>(&payload) else {
                tracing::debug!("ignoring an unparseable socket frame");
                continue;
            };

            // Ack first, then work. Slack redelivers anything unacked within
            // three seconds, and the dedupe table is what makes that safe.
            if let Some(envelope_id) = &frame.envelope_id {
                let ack = serde_json::json!({ "envelope_id": envelope_id }).to_string();
                if let Err(e) = write.send(Message::Text(ack)).await {
                    return Err(AppError::internal(format!("slack ack failed: {e}")));
                }
            }

            match frame.kind.as_deref() {
                Some("hello") => tracing::debug!("slack socket hello"),
                Some("disconnect") => {
                    tracing::info!(reason = ?frame.reason, "slack asked us to reconnect");
                    return Ok(());
                }
                Some("events_api") => {
                    if let Some(envelope) = frame.payload {
                        if let Err(e) = self.handle_and_reply(&envelope).await {
                            tracing::warn!(error = %e, "could not handle a slack event");
                        }
                    }
                }
                _ => {}
            }
        }
        Ok(())
    }
}

#[derive(Debug, Deserialize)]
struct SocketFrame {
    #[serde(rename = "type", default)]
    kind: Option<String>,
    #[serde(default)]
    envelope_id: Option<String>,
    #[serde(default)]
    payload: Option<SlackEventEnvelope>,
    #[serde(default)]
    reason: Option<String>,
}

// ---------------------------------------------------------------------------
// Events API signature verification
// ---------------------------------------------------------------------------

/// Verify an Events API request.
///
/// `v0:<timestamp>:<body>` signed with the app's signing secret. Both halves
/// matter: the HMAC proves Slack sent it, and the timestamp bound stops a
/// captured request being replayed later. Comparison is constant-time.
pub fn verify_signature(
    signing_secret: &str,
    timestamp: &str,
    body: &str,
    signature: &str,
    now_unix: i64,
) -> bool {
    let Ok(sent_at) = timestamp.parse::<i64>() else {
        return false;
    };
    if (now_unix - sent_at).abs() > MAX_SIGNATURE_AGE_SECS {
        return false;
    }
    let Some(provided) = signature.strip_prefix("v0=") else {
        return false;
    };
    let Ok(provided) = decode_hex(provided) else {
        return false;
    };

    let mut mac = match HmacSha256::new_from_slice(signing_secret.as_bytes()) {
        Ok(mac) => mac,
        Err(_) => return false,
    };
    mac.update(format!("v0:{timestamp}:{body}").as_bytes());
    mac.verify_slice(&provided).is_ok()
}

/// The signature Slack would send for this body — used by the tests.
pub fn sign_request(signing_secret: &str, timestamp: &str, body: &str) -> String {
    let mut mac = HmacSha256::new_from_slice(signing_secret.as_bytes()).expect("any key length");
    mac.update(format!("v0:{timestamp}:{body}").as_bytes());
    format!("v0={}", hex_encode(&mac.finalize().into_bytes()))
}

fn decode_hex(value: &str) -> Result<Vec<u8>, ()> {
    if !value.len().is_multiple_of(2) {
        return Err(());
    }
    (0..value.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&value[i..i + 2], 16).map_err(|_| ()))
        .collect()
}

// ---------------------------------------------------------------------------
// Text helpers
// ---------------------------------------------------------------------------

/// Remove the bot's own `<@U123>` mention so the model does not see it.
pub fn strip_mention(text: &str, bot_user_id: Option<&str>) -> String {
    let Some(id) = bot_user_id else {
        return text.trim().to_string();
    };
    let cleaned = text.replace(&format!("<@{id}>"), " ");
    let cleaned = cleaned.split_whitespace().collect::<Vec<_>>().join(" ");
    if cleaned.is_empty() {
        text.trim().to_string()
    } else {
        cleaned
    }
}

/// Split on line boundaries where possible, so a long reply stays readable.
pub fn split_message(text: &str) -> Vec<String> {
    if text.chars().count() <= MAX_MESSAGE_CHARS {
        return vec![text.to_string()];
    }
    let mut chunks = Vec::new();
    let mut current = String::new();
    for line in text.split_inclusive('\n') {
        if current.chars().count() + line.chars().count() > MAX_MESSAGE_CHARS {
            if !current.is_empty() {
                chunks.push(std::mem::take(&mut current));
            }
            if line.chars().count() > MAX_MESSAGE_CHARS {
                let mut buffer = String::new();
                for c in line.chars() {
                    buffer.push(c);
                    if buffer.chars().count() == MAX_MESSAGE_CHARS {
                        chunks.push(std::mem::take(&mut buffer));
                    }
                }
                current = buffer;
                continue;
            }
        }
        current.push_str(line);
    }
    if !current.is_empty() {
        chunks.push(current);
    }
    chunks
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use crate::db::test_pool;
    use crate::harness::mock::MockHarness;
    use crate::plugin::native::NativeHost;
    use crate::sandbox::LocalSandbox;

    fn orchestrator() -> Arc<Orchestrator> {
        let (events, _) = tokio::sync::broadcast::channel(16);
        Arc::new(Orchestrator {
            config: Arc::new(Config::default()),
            stores: Stores::new(test_pool()).unwrap(),
            sandbox: Arc::new(LocalSandbox::new(
                std::env::temp_dir().join("qm-slack-test"),
                5,
                1000,
            )),
            harness: Arc::new(MockHarness::new()),
            plugins: Arc::new(NativeHost::new(&crate::config::PluginsConfig::default())),
            events,
        })
    }

    fn client(config: SlackConfig) -> SlackClient {
        let orchestrator = orchestrator();
        let stores = orchestrator.stores.clone();
        SlackClient {
            config,
            bot_token: "xoxb-test".into(),
            client: reqwest::Client::new(),
            orchestrator,
            stores,
            bot_user_id: Some("UBOT".into()),
        }
    }

    fn base_config() -> SlackConfig {
        SlackConfig {
            enabled: true,
            bot_token: Some("xoxb-test".into()),
            app_token: Some("xapp-test".into()),
            signing_secret: Some("s3cret".into()),
            ..SlackConfig::default()
        }
    }

    fn event(channel: &str, channel_type: &str, user: &str, text: &str) -> SlackEvent {
        SlackEvent {
            kind: "message".into(),
            text: Some(text.into()),
            user: Some(user.into()),
            channel: Some(channel.into()),
            channel_type: Some(channel_type.into()),
            ts: Some("1700000000.000100".into()),
            thread_ts: None,
            bot_id: None,
            subtype: None,
        }
    }

    // -- construction -------------------------------------------------------

    #[test]
    fn socket_mode_requires_an_app_token_and_events_mode_a_signing_secret() {
        let no_app = SlackConfig {
            app_token: None,
            app_token_env: "QM_SLACK_APP_TOKEN_ABSENT_FOR_TEST".into(),
            ..base_config()
        };
        let err = SlackClient::new(no_app, orchestrator()).unwrap_err();
        assert!(err.to_string().contains("connections:write"), "{err}");

        let no_secret = SlackConfig {
            mode: "events".into(),
            signing_secret: None,
            signing_secret_env: "QM_SLACK_SIGNING_ABSENT_FOR_TEST".into(),
            ..base_config()
        };
        let err = SlackClient::new(no_secret, orchestrator()).unwrap_err();
        assert!(err.to_string().contains("signing secret"), "{err}");
    }

    #[test]
    fn a_missing_bot_token_is_a_refusal() {
        let config = SlackConfig {
            bot_token: None,
            bot_token_env: "QM_SLACK_BOT_ABSENT_FOR_TEST".into(),
            ..base_config()
        };
        let err = SlackClient::new(config, orchestrator()).unwrap_err();
        assert!(err.to_string().contains("no bot token is set"));
    }

    #[test]
    fn debug_never_prints_the_bot_token() {
        let rendered = format!("{:?}", client(base_config()));
        assert!(!rendered.contains("xoxb-test"));
        assert!(rendered.contains("redacted"));
    }

    // -- routing ------------------------------------------------------------

    #[test]
    fn a_dm_maps_to_the_senders_personal_scope() {
        let c = client(base_config());
        let e = event("D123", "im", "U1", "hi");
        let routing = c.route(&e, "U1", true);
        assert_eq!(routing.scope, ScopeId::personal("slack:U1"));
        assert_eq!(routing.session_type, SessionType::Dm);
        assert_eq!(routing.thread_ref, "slack:D123");
    }

    #[test]
    fn a_channel_maps_to_a_channel_scope_shared_by_everyone_in_it() {
        let c = client(base_config());
        let a = c.route(&event("C123", "channel", "U1", "hi"), "U1", false);
        let b = c.route(&event("C123", "channel", "U2", "hi"), "U2", false);

        assert_eq!(a.scope, ScopeId::channel("slack-C123"));
        assert_eq!(a.scope, b.scope, "one channel, one scope");
        assert_ne!(a.principal, b.principal, "distinct principals");
        assert_eq!(a.session_type, SessionType::Channel);
    }

    #[test]
    fn each_slack_thread_gets_its_own_session() {
        let c = client(base_config());
        let mut threaded = event("C123", "channel", "U1", "hi");
        threaded.thread_ts = Some("1700000000.000001".into());

        let top_level = c.route(&event("C123", "channel", "U1", "hi"), "U1", false);
        let in_thread = c.route(&threaded, "U1", false);
        assert_ne!(
            top_level.thread_ref, in_thread.thread_ref,
            "two conversations in one channel must not interleave"
        );
        assert_eq!(
            in_thread.scope, top_level.scope,
            "but share the channel scope"
        );
    }

    #[test]
    fn a_configured_slack_user_maps_to_a_named_principal() {
        let mut config = base_config();
        config.principals.insert("U1".into(), "ada".into());
        let c = client(config);
        assert_eq!(
            c.route(&event("D1", "im", "U1", "hi"), "U1", true)
                .principal,
            "ada"
        );
        assert_eq!(
            c.route(&event("D1", "im", "U9", "hi"), "U9", true)
                .principal,
            "slack:U9"
        );
    }

    // -- addressing ---------------------------------------------------------

    #[test]
    fn mentions_are_detected_and_stripped() {
        let c = client(base_config());
        assert!(c.is_addressed("hey <@UBOT> can you look"));
        assert!(!c.is_addressed("no mention"));
        assert!(!c.is_addressed("<@UOTHER> hello"));

        assert_eq!(strip_mention("<@UBOT> check CI", Some("UBOT")), "check CI");
        assert_eq!(strip_mention("check CI <@UBOT>", Some("UBOT")), "check CI");
        assert_eq!(strip_mention("check CI", Some("UBOT")), "check CI");
        assert_eq!(strip_mention("  spaced  ", None), "spaced");
        // A message that is only a mention keeps its text rather than becoming
        // empty, which would be rejected as a blank turn.
        assert_eq!(strip_mention("<@UBOT>", Some("UBOT")), "<@UBOT>");
    }

    // -- event filtering ----------------------------------------------------

    /// These drive `handle_event`, which decides *what* to say without
    /// posting it, so the whole filtering and routing path is exercised with
    /// no network round trip.
    #[tokio::test]
    async fn the_bot_never_answers_itself_or_another_bot() {
        let c = client(base_config());

        let mut own = event("C1", "channel", "UBOT", "<@UBOT> hello");
        own.user = Some("UBOT".into());
        assert!(c
            .handle_event(&envelope("e1", own))
            .await
            .unwrap()
            .is_none());

        let mut from_bot = event("C1", "channel", "U1", "<@UBOT> hello");
        from_bot.bot_id = Some("B123".into());
        assert!(c
            .handle_event(&envelope("e2", from_bot))
            .await
            .unwrap()
            .is_none());
    }

    #[tokio::test]
    async fn edits_and_deletions_are_not_new_questions() {
        let c = client(base_config());
        let mut edited = event("C1", "channel", "U1", "<@UBOT> hello");
        edited.subtype = Some("message_changed".into());
        assert!(c
            .handle_event(&envelope("e1", edited))
            .await
            .unwrap()
            .is_none());
    }

    #[tokio::test]
    async fn a_channel_message_without_a_mention_is_ignored_by_default() {
        let c = client(base_config());
        assert!(c
            .handle_event(&envelope(
                "e1",
                event("C1", "channel", "U1", "just chatting")
            ))
            .await
            .unwrap()
            .is_none());
    }

    #[tokio::test]
    async fn a_mentioned_channel_message_is_answered_in_thread() {
        let c = client(base_config());
        let reply = c
            .handle_event(&envelope(
                "e1",
                event("C1", "channel", "U1", "<@UBOT> status"),
            ))
            .await
            .unwrap()
            .expect("a mention should produce a reply");
        assert_eq!(reply.channel, "C1");
        assert!(reply.text.contains("status"));
        assert_eq!(
            reply.thread_ts.as_deref(),
            Some("1700000000.000100"),
            "a channel reply threads off the triggering message"
        );
    }

    #[tokio::test]
    async fn a_dm_reply_is_not_threaded() {
        let c = client(base_config());
        let reply = c
            .handle_event(&envelope("e1", event("D1", "im", "U1", "hello")))
            .await
            .unwrap()
            .unwrap();
        assert!(reply.thread_ts.is_none());
    }

    #[tokio::test]
    async fn a_channel_outside_the_allowlist_is_ignored() {
        let mut config = base_config();
        config.allowed_channels = vec!["C_ALLOWED".into()];
        let c = client(config);
        assert!(c
            .handle_event(&envelope(
                "e1",
                event("C_OTHER", "channel", "U1", "<@UBOT> hi")
            ))
            .await
            .unwrap()
            .is_none());
    }

    #[tokio::test]
    async fn a_redelivered_event_does_not_run_the_turn_twice() {
        let c = client(base_config());
        assert!(
            c.handle_event(&envelope("evt_same", event("D1", "im", "U1", "hello")))
                .await
                .unwrap()
                .is_some(),
            "the first delivery runs"
        );
        assert!(
            c.handle_event(&envelope("evt_same", event("D1", "im", "U1", "hello")))
                .await
                .unwrap()
                .is_none(),
            "a redelivery must be a no-op"
        );

        // And exactly one turn reached the transcript.
        let sessions = c
            .stores
            .sessions
            .list_for_scopes(&[ScopeId::personal("slack:U1")], true)
            .unwrap();
        let history = c.stores.sessions.history(&sessions[0].id).unwrap();
        assert_eq!(
            history
                .iter()
                .filter(|e| e.entry_type == crate::types::EntryType::User)
                .count(),
            1
        );
    }

    #[tokio::test]
    async fn a_dm_runs_a_turn_and_records_the_transcript() {
        let c = client(base_config());
        let reply = c
            .handle_event(&envelope("e1", event("D1", "im", "U1", "hello there")))
            .await
            .unwrap()
            .unwrap();
        assert!(reply.text.contains("hello there"));

        let session = c
            .stores
            .sessions
            .list_for_scopes(&[ScopeId::personal("slack:U1")], true)
            .unwrap();
        assert_eq!(session.len(), 1);
        assert_eq!(session[0].surface, "slack");
        let history = c.stores.sessions.history(&session[0].id).unwrap();
        assert_eq!(history[0].text(), "hello there");
    }

    #[tokio::test]
    async fn a_channel_turn_writes_to_the_channel_scope() {
        let c = client(base_config());
        c.handle_event(&envelope(
            "e1",
            event(
                "C1",
                "channel",
                "U1",
                "<@UBOT> !remember we ship on Fridays",
            ),
        ))
        .await
        .unwrap();

        assert!(c
            .stores
            .memory
            .read(&ScopeId::channel("slack-C1"))
            .unwrap()
            .contains("Fridays"));
        assert!(!c
            .stores
            .memory
            .read(&ScopeId::personal("slack:U1"))
            .unwrap()
            .contains("Fridays"));
    }

    fn envelope(event_id: &str, event: SlackEvent) -> SlackEventEnvelope {
        SlackEventEnvelope {
            event_id: Some(event_id.into()),
            event: Some(event),
            challenge: None,
            kind: Some("event_callback".into()),
        }
    }

    // -- signature verification ---------------------------------------------

    #[test]
    fn a_correctly_signed_request_verifies() {
        let body = r#"{"type":"event_callback"}"#;
        let ts = "1700000000";
        let signature = sign_request("s3cret", ts, body);
        assert!(verify_signature(
            "s3cret",
            ts,
            body,
            &signature,
            1_700_000_010
        ));
    }

    #[test]
    fn a_tampered_body_or_wrong_secret_fails() {
        let body = r#"{"type":"event_callback"}"#;
        let ts = "1700000000";
        let signature = sign_request("s3cret", ts, body);

        assert!(!verify_signature(
            "s3cret",
            ts,
            r#"{"evil":true}"#,
            &signature,
            1_700_000_010
        ));
        assert!(!verify_signature(
            "wrong",
            ts,
            body,
            &signature,
            1_700_000_010
        ));
        assert!(!verify_signature(
            "s3cret",
            "1700000001",
            body,
            &signature,
            1_700_000_010
        ));
    }

    #[test]
    fn an_old_request_is_refused_even_with_a_valid_signature() {
        let body = "{}";
        let ts = "1700000000";
        let signature = sign_request("s3cret", ts, body);
        // Ten minutes later.
        assert!(
            !verify_signature("s3cret", ts, body, &signature, 1_700_000_000 + 600),
            "a captured request must not be replayable"
        );
        // And a request from the future is equally suspect.
        assert!(!verify_signature(
            "s3cret",
            ts,
            body,
            &signature,
            1_700_000_000 - 600
        ));
    }

    #[test]
    fn malformed_signatures_are_refused_rather_than_panicking() {
        let body = "{}";
        for bad in ["", "v0=", "v0=zz", "nothex", "v1=abcd", "abcd"] {
            assert!(
                !verify_signature("s3cret", "1700000000", body, bad, 1_700_000_000),
                "{bad:?} should be refused"
            );
        }
        assert!(!verify_signature(
            "s3cret",
            "not-a-number",
            body,
            "v0=ab",
            1_700_000_000
        ));
    }

    // -- message splitting --------------------------------------------------

    #[test]
    fn short_replies_are_sent_whole() {
        assert_eq!(split_message("hello"), vec!["hello"]);
    }

    #[test]
    fn long_replies_split_within_the_limit_without_losing_text() {
        let text = format!("{}\n", "x".repeat(200)).repeat(40);
        let chunks = split_message(&text);
        assert!(chunks.len() > 1);
        for chunk in &chunks {
            assert!(chunk.chars().count() <= MAX_MESSAGE_CHARS);
        }
        assert_eq!(chunks.concat(), text);
    }

    #[test]
    fn a_single_over_long_line_is_still_cut() {
        let text = "y".repeat(MAX_MESSAGE_CHARS * 2 + 10);
        let chunks = split_message(&text);
        assert_eq!(chunks.len(), 3);
        assert_eq!(chunks.concat(), text);
    }

    #[test]
    fn multibyte_replies_split_without_slicing_a_character() {
        let text = "日本語のテキスト。".repeat(900);
        let chunks = split_message(&text);
        assert!(chunks.len() > 1);
        assert_eq!(chunks.concat(), text);
    }
}
