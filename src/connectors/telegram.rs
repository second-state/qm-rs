//! The Telegram connector.
//!
//! Long-polls `getUpdates` with a bot token and runs each message through the
//! orchestrator, the same pipeline the web UI uses. There is no webhook: the
//! connector only dials out, so it needs no public URL and no inbound port.
//!
//! # Mapping
//!
//! * a private chat → the sender's **personal** scope;
//! * a group or supergroup → a **channel** scope, `channel:tg-<chat_id>`, so
//!   what the agent learns in a group belongs to the group rather than to
//!   whoever happened to speak;
//! * a Telegram user id → the principal named in `[telegram.principals]`, or a
//!   guest principal `telegram:<user_id>`.
//!
//! # Exposure
//!
//! A bot is addressable by anyone who knows its handle, so every inbound chat
//! is untrusted by default. `allowed_chat_ids` is the allowlist; leaving it
//! empty serves everyone, which is only appropriate for a private bot.

use std::sync::Arc;

use serde::Deserialize;
use tokio::time::{sleep, Duration};

use crate::config::TelegramConfig;
use crate::error::{AppError, AppResult};
use crate::orchestrator::Orchestrator;
use crate::store::DirectoryStore;
use crate::types::{PrincipalKind, ScopeId, SessionType, TurnRequest, TurnStatus};

/// Telegram rejects messages longer than this.
const MAX_MESSAGE_CHARS: usize = 4096;
/// Setting key under which the update cursor is persisted.
const OFFSET_KEY: &str = "telegram.offset";

#[derive(Debug, Deserialize)]
struct UpdatesResponse {
    #[serde(default)]
    ok: bool,
    #[serde(default)]
    result: Vec<Update>,
    #[serde(default)]
    description: Option<String>,
}

#[derive(Debug, Deserialize)]
struct Update {
    update_id: i64,
    #[serde(default)]
    message: Option<Message>,
}

#[derive(Debug, Deserialize)]
struct Message {
    #[serde(default)]
    text: Option<String>,
    chat: Chat,
    #[serde(default)]
    from: Option<User>,
    #[serde(default)]
    message_id: Option<i64>,
}

#[derive(Debug, Deserialize)]
struct Chat {
    id: i64,
    #[serde(rename = "type")]
    kind: String,
    #[serde(default)]
    title: Option<String>,
}

#[derive(Debug, Deserialize)]
struct User {
    id: i64,
    #[serde(default)]
    username: Option<String>,
    #[serde(default)]
    first_name: Option<String>,
    #[serde(default)]
    is_bot: bool,
}

/// Where one inbound message should run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Routing {
    pub scope: ScopeId,
    pub principal: String,
    pub display_name: Option<String>,
    pub session_type: SessionType,
    pub thread_ref: String,
    pub channel_name: Option<String>,
}

pub struct TelegramConnector {
    config: TelegramConfig,
    token: String,
    client: reqwest::Client,
    orchestrator: Arc<Orchestrator>,
    directory: DirectoryStore,
    bot_username: Option<String>,
}

/// Written by hand rather than derived: the bot token is a bearer credential
/// that appears in every API URL, and a derived `Debug` would print it into
/// any log line or panic message that formats the connector.
impl std::fmt::Debug for TelegramConnector {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TelegramConnector")
            .field("api_base", &self.config.api_base)
            .field("token", &"<redacted>")
            .field("bot_username", &self.bot_username)
            .field("allowed_chat_ids", &self.config.allowed_chat_ids)
            .finish()
    }
}

impl TelegramConnector {
    /// Build the connector, refusing to start without a token.
    pub fn new(config: TelegramConfig, orchestrator: Arc<Orchestrator>) -> AppResult<Self> {
        let token = config.resolve_token().ok_or_else(|| {
            AppError::bad_request(format!(
                "[telegram].enabled is true but no bot token is set — put it in \
                 [telegram].bot_token or the {} env var",
                config.bot_token_env
            ))
        })?;
        let directory = orchestrator.stores.directory.clone();
        Ok(Self {
            client: reqwest::Client::builder()
                // Comfortably longer than the long-poll, so the poll itself is
                // what times out rather than the HTTP client.
                .timeout(Duration::from_secs(config.poll_timeout_secs + 30))
                .build()?,
            config,
            token,
            orchestrator,
            directory,
            bot_username: None,
        })
    }

    fn url(&self, method: &str) -> String {
        format!(
            "{}/bot{}/{method}",
            self.config.api_base.trim_end_matches('/'),
            self.token
        )
    }

    /// Learn the bot's own @username, needed to detect mentions in groups.
    async fn fetch_username(&mut self) -> AppResult<()> {
        #[derive(Deserialize)]
        struct MeResponse {
            #[serde(default)]
            ok: bool,
            #[serde(default)]
            result: Option<User>,
        }
        let response: MeResponse = self
            .client
            .get(self.url("getMe"))
            .send()
            .await?
            .json()
            .await?;
        if !response.ok {
            return Err(AppError::bad_request(
                "Telegram rejected the bot token — check [telegram].bot_token",
            ));
        }
        self.bot_username = response.result.and_then(|u| u.username);
        tracing::info!(
            username = self.bot_username.as_deref().unwrap_or("unknown"),
            "telegram connector authenticated"
        );
        Ok(())
    }

    /// Poll forever. Network errors back off and retry rather than exiting:
    /// a connector that dies on the first blip is worse than a slow one.
    pub async fn run(mut self) {
        if let Err(e) = self.fetch_username().await {
            tracing::error!(error = %e, "telegram connector could not start");
            return;
        }

        let mut backoff = Duration::from_secs(1);
        loop {
            match self.poll_once().await {
                Ok(handled) => {
                    backoff = Duration::from_secs(1);
                    if handled == 0 {
                        // `getUpdates` already blocked for the long-poll
                        // window, so there is nothing to sleep off here.
                        continue;
                    }
                }
                Err(e) => {
                    tracing::warn!(error = %e, backoff = ?backoff, "telegram poll failed");
                    sleep(backoff).await;
                    backoff = (backoff * 2).min(Duration::from_secs(60));
                }
            }
        }
    }

    /// One `getUpdates` round. Returns how many messages were handled.
    pub async fn poll_once(&self) -> AppResult<usize> {
        let offset = self.stored_offset()?;
        let mut request = self
            .client
            .get(self.url("getUpdates"))
            .query(&[("timeout", self.config.poll_timeout_secs.to_string())]);
        if let Some(offset) = offset {
            request = request.query(&[("offset", offset.to_string())]);
        }

        let response: UpdatesResponse = request.send().await?.json().await?;
        if !response.ok {
            return Err(AppError::internal(format!(
                "getUpdates failed: {}",
                response
                    .description
                    .unwrap_or_else(|| "unknown error".into())
            )));
        }

        let mut handled = 0;
        for update in &response.result {
            // Advance the cursor before doing the work: an update that makes
            // the connector fail must not be retried forever, which would wedge
            // every later message behind it.
            self.store_offset(update.update_id + 1)?;
            if let Some(message) = &update.message {
                match self.handle(message).await {
                    Ok(true) => handled += 1,
                    Ok(false) => {}
                    Err(e) => tracing::warn!(error = %e, "could not handle a telegram message"),
                }
            }
        }
        Ok(handled)
    }

    fn stored_offset(&self) -> AppResult<Option<i64>> {
        Ok(self
            .directory
            .setting(OFFSET_KEY)?
            .and_then(|v| v.parse::<i64>().ok()))
    }

    fn store_offset(&self, offset: i64) -> AppResult<()> {
        self.directory.put_setting(OFFSET_KEY, &offset.to_string())
    }

    /// Handle one message. `false` means it was deliberately ignored.
    async fn handle(&self, message: &Message) -> AppResult<bool> {
        let Some(text) = message
            .text
            .as_deref()
            .map(str::trim)
            .filter(|t| !t.is_empty())
        else {
            return Ok(false);
        };
        let Some(from) = &message.from else {
            return Ok(false);
        };
        // Never answer another bot: two bots in one group would talk to each
        // other indefinitely.
        if from.is_bot {
            return Ok(false);
        }
        if !self.config.allowed_chat_ids.is_empty()
            && !self.config.allowed_chat_ids.contains(&message.chat.id)
        {
            tracing::debug!(
                chat = message.chat.id,
                "ignoring a chat outside the allowlist"
            );
            return Ok(false);
        }

        let is_group = message.chat.kind != "private";
        let addressed = self.is_addressed(text);
        if is_group && self.config.require_mention_in_groups && !addressed {
            return Ok(false);
        }

        let routing = self.route(message, from);
        self.directory.upsert_principal(
            &routing.principal,
            if self.config.principals.contains_key(&from.id.to_string()) {
                PrincipalKind::Internal
            } else {
                PrincipalKind::Guest
            },
            routing.display_name.as_deref(),
            None,
        )?;
        // In a group scope the sender must be a member for entitlement checks
        // elsewhere to hold.
        if routing.scope.is_shared() {
            self.directory.upsert_channel(
                routing.scope.reference(),
                routing
                    .channel_name
                    .as_deref()
                    .unwrap_or(routing.scope.reference()),
                "channel",
                true,
            )?;
            self.directory
                .add_channel_member(routing.scope.reference(), &routing.principal)?;
        }

        let request = TurnRequest::new(
            "telegram",
            &routing.principal,
            routing.scope.clone(),
            &routing.thread_ref,
            strip_mention(text, self.bot_username.as_deref()),
        )
        .with_session_type(routing.session_type);
        let request = TurnRequest {
            channel_name: routing.channel_name.clone(),
            ..request
        };

        let result = self.orchestrator.handle_turn(request).await?;
        let reply = match result.status {
            TurnStatus::Silent => return Ok(true),
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

        if !reply.trim().is_empty() {
            self.send(message.chat.id, &reply, message.message_id)
                .await?;
        }
        Ok(true)
    }

    fn is_addressed(&self, text: &str) -> bool {
        match &self.bot_username {
            Some(username) => text
                .to_lowercase()
                .contains(&format!("@{}", username.to_lowercase())),
            None => false,
        }
    }

    fn route(&self, message: &Message, from: &User) -> Routing {
        // An admin-created link wins over the config map, which in turn beats
        // falling back to a guest principal. The DB is checked first so
        // onboarding someone does not need a config edit and a restart.
        let principal = self
            .directory
            .identity_principal("telegram", &from.id.to_string())
            .ok()
            .flatten()
            .or_else(|| self.config.principals.get(&from.id.to_string()).cloned())
            .unwrap_or_else(|| format!("telegram:{}", from.id));

        let display_name = from.username.clone().or_else(|| from.first_name.clone());

        if message.chat.kind == "private" {
            Routing {
                scope: ScopeId::personal(&principal),
                principal,
                display_name,
                session_type: SessionType::Dm,
                thread_ref: format!("tg:{}", message.chat.id),
                channel_name: None,
            }
        } else {
            // A bound chat points at a group or channel the admin already
            // made, so a Telegram group and the web UI share one scope — one
            // memory, one set of files. Unbound chats get their own derived
            // scope.
            let bound = self
                .directory
                .channel_scope("telegram", &message.chat.id.to_string())
                .ok()
                .flatten();
            let derived = format!("tg-{}", message.chat.id);
            let scope = bound.unwrap_or_else(|| ScopeId::channel(&derived));
            let label = scope.reference().to_string();
            Routing {
                scope,
                principal,
                display_name,
                session_type: SessionType::Channel,
                thread_ref: format!("tg:{}", message.chat.id),
                channel_name: message.chat.title.clone().or(Some(label)),
            }
        }
    }

    /// Send a reply, splitting anything past Telegram's length limit.
    pub async fn send(&self, chat_id: i64, text: &str, reply_to: Option<i64>) -> AppResult<()> {
        for (index, chunk) in split_message(text).into_iter().enumerate() {
            let mut body = serde_json::json!({ "chat_id": chat_id, "text": chunk });
            // Only the first chunk quotes the original message.
            if index == 0 {
                if let Some(message_id) = reply_to {
                    body["reply_to_message_id"] = serde_json::json!(message_id);
                }
            }
            let response = self
                .client
                .post(self.url("sendMessage"))
                .json(&body)
                .send()
                .await?;
            if !response.status().is_success() {
                let status = response.status();
                let detail: String = response
                    .text()
                    .await
                    .unwrap_or_default()
                    .chars()
                    .take(300)
                    .collect();
                return Err(AppError::internal(format!(
                    "sendMessage returned {status}: {detail}"
                )));
            }
        }
        Ok(())
    }
}

/// Remove a leading or trailing `@bot` mention so the model does not see it.
pub fn strip_mention(text: &str, bot_username: Option<&str>) -> String {
    let Some(username) = bot_username else {
        return text.trim().to_string();
    };
    let handle = format!("@{username}");
    let lower_handle = handle.to_lowercase();
    let mut cleaned = String::with_capacity(text.len());
    for word in text.split_whitespace() {
        if word.to_lowercase().trim_end_matches([',', ':', '.']) == lower_handle {
            continue;
        }
        if !cleaned.is_empty() {
            cleaned.push(' ');
        }
        cleaned.push_str(word);
    }
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
            // A single line longer than the limit still has to be cut.
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

    fn message(chat_kind: &str, chat_id: i64, user_id: i64, text: &str) -> Message {
        Message {
            text: Some(text.into()),
            chat: Chat {
                id: chat_id,
                kind: chat_kind.into(),
                title: Some("Engineering".into()),
            },
            from: Some(User {
                id: user_id,
                username: Some("ada".into()),
                first_name: Some("Ada".into()),
                is_bot: false,
            }),
            message_id: Some(7),
        }
    }

    fn connector(config: TelegramConfig) -> TelegramConnector {
        // Routing and formatting are pure; the orchestrator is never touched
        // by the functions these tests exercise.
        TelegramConnector {
            config,
            token: "test".into(),
            client: reqwest::Client::new(),
            orchestrator: test_orchestrator(),
            directory: DirectoryStore::new(crate::db::test_pool()),
            bot_username: Some("qm_bot".into()),
        }
    }

    /// The routing tests never dereference this, and building a real
    /// orchestrator here would pull in a sandbox and a harness for no benefit.
    fn test_orchestrator() -> Arc<Orchestrator> {
        use crate::harness::mock::MockHarness;
        use crate::plugin::native::NativeHost;
        use crate::sandbox::LocalSandbox;
        let (events, _) = tokio::sync::broadcast::channel(4);
        Arc::new(Orchestrator {
            config: Arc::new(crate::config::Config::default()),
            stores: crate::store::Stores::new(crate::db::test_pool()).unwrap(),
            sandbox: Arc::new(LocalSandbox::new(
                std::env::temp_dir().join("qm-tg-test"),
                5,
                1000,
            )),
            harness: Arc::new(MockHarness::new()),
            plugins: Arc::new(NativeHost::new(&crate::config::PluginsConfig::default())),
            events,
        })
    }

    #[test]
    fn a_private_chat_maps_to_the_senders_personal_scope() {
        let c = connector(TelegramConfig::default());
        let routing = c.route(
            &message("private", 111, 222, "hi"),
            message("private", 111, 222, "hi").from.as_ref().unwrap(),
        );
        assert_eq!(routing.scope, ScopeId::personal("telegram:222"));
        assert_eq!(routing.session_type, SessionType::Dm);
        assert_eq!(routing.thread_ref, "tg:111");
        assert!(routing.channel_name.is_none());
    }

    #[test]
    fn a_group_chat_maps_to_a_channel_scope_keyed_by_chat_not_sender() {
        let c = connector(TelegramConfig::default());
        let first = message("group", -100, 222, "hi");
        let second = message("group", -100, 333, "hi");
        let a = c.route(&first, first.from.as_ref().unwrap());
        let b = c.route(&second, second.from.as_ref().unwrap());

        assert_eq!(a.scope, ScopeId::channel("tg--100"));
        assert_eq!(
            a.scope, b.scope,
            "two people in one group must share the group's scope"
        );
        assert_ne!(a.principal, b.principal, "but remain distinct principals");
        assert_eq!(a.session_type, SessionType::Channel);
        assert_eq!(a.channel_name.as_deref(), Some("Engineering"));
    }

    #[test]
    fn a_configured_telegram_user_maps_to_a_named_principal() {
        let mut config = TelegramConfig::default();
        config.principals.insert("222".into(), "ada".into());
        let c = connector(config);
        let m = message("private", 111, 222, "hi");
        let routing = c.route(&m, m.from.as_ref().unwrap());
        assert_eq!(routing.principal, "ada");
        assert_eq!(routing.scope, ScopeId::personal("ada"));

        // An unmapped user is still served, as a guest principal.
        let other = message("private", 111, 999, "hi");
        assert_eq!(
            c.route(&other, other.from.as_ref().unwrap()).principal,
            "telegram:999"
        );
    }

    #[test]
    fn mention_detection_is_case_insensitive() {
        let c = connector(TelegramConfig::default());
        assert!(c.is_addressed("hey @qm_bot can you check"));
        assert!(c.is_addressed("@QM_Bot status"));
        assert!(!c.is_addressed("no mention here"));
        assert!(!c.is_addressed("@other_bot hello"));
    }

    #[test]
    fn the_mention_is_stripped_before_the_model_sees_the_text() {
        assert_eq!(
            strip_mention("@qm_bot check CI", Some("qm_bot")),
            "check CI"
        );
        assert_eq!(
            strip_mention("check CI @qm_bot", Some("qm_bot")),
            "check CI"
        );
        assert_eq!(
            strip_mention("@QM_BOT, check CI", Some("qm_bot")),
            "check CI"
        );
        assert_eq!(strip_mention("check CI", Some("qm_bot")), "check CI");
        assert_eq!(strip_mention("  spaced  ", None), "spaced");
        // A message that is only a mention keeps its text rather than becoming
        // empty, which would be rejected as a blank turn.
        assert_eq!(strip_mention("@qm_bot", Some("qm_bot")), "@qm_bot");
    }

    #[test]
    fn short_replies_are_sent_whole() {
        assert_eq!(split_message("hello"), vec!["hello"]);
        assert_eq!(split_message(""), vec![""]);
    }

    #[test]
    fn long_replies_split_on_line_boundaries_within_the_limit() {
        let line = format!("{}\n", "x".repeat(200));
        let text = line.repeat(40); // ~8040 chars
        let chunks = split_message(&text);
        assert!(chunks.len() > 1);
        for chunk in &chunks {
            assert!(
                chunk.chars().count() <= MAX_MESSAGE_CHARS,
                "chunk of {} chars exceeds the limit",
                chunk.chars().count()
            );
        }
        assert_eq!(chunks.concat(), text, "splitting must not lose text");
    }

    #[test]
    fn a_single_over_long_line_is_still_cut() {
        let text = "y".repeat(MAX_MESSAGE_CHARS * 2 + 50);
        let chunks = split_message(&text);
        assert_eq!(chunks.len(), 3);
        for chunk in &chunks {
            assert!(chunk.chars().count() <= MAX_MESSAGE_CHARS);
        }
        assert_eq!(chunks.concat(), text);
    }

    #[test]
    fn multibyte_replies_split_without_slicing_a_character() {
        let text = "日本語のテキスト。".repeat(1200);
        let chunks = split_message(&text);
        assert!(chunks.len() > 1);
        assert_eq!(chunks.concat(), text);
    }

    #[test]
    fn a_connector_without_a_token_refuses_to_start() {
        let config = TelegramConfig {
            enabled: true,
            bot_token: None,
            bot_token_env: "QM_TELEGRAM_ABSENT_FOR_TEST".into(),
            ..TelegramConfig::default()
        };
        let err = TelegramConnector::new(config, test_orchestrator()).unwrap_err();
        assert!(err.to_string().contains("no bot token is set"));
    }

    #[test]
    fn the_update_cursor_round_trips_through_settings() {
        let c = connector(TelegramConfig::default());
        assert!(c.stored_offset().unwrap().is_none());
        c.store_offset(42).unwrap();
        assert_eq!(c.stored_offset().unwrap(), Some(42));
        c.store_offset(43).unwrap();
        assert_eq!(c.stored_offset().unwrap(), Some(43));
    }
}
