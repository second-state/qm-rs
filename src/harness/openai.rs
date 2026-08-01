//! The OpenAI-compatible harness.
//!
//! Talks chat-completions with tool calling to any gateway that speaks the
//! shape — OpenAI, an internal gateway such as `cloud_ai_gateway`, or anything
//! else with a `/v1/chat/completions` endpoint. The tool loop lives here: call
//! the model, dispatch whatever tools it asked for, feed the results back, and
//! repeat until it answers or the step budget runs out.

use async_trait::async_trait;
use serde::Deserialize;
use serde_json::json;

use super::{
    render_history, Harness, HarnessOutcome, PendingApprovalRequest, ToolOutcome, TurnInput,
};
use crate::config::HarnessConfig;
use crate::error::{AppError, AppResult};
use crate::types::{EntryType, NewEntry};

/// History budget, in characters, before the tail is kept and the rest dropped.
const HISTORY_BUDGET_CHARS: usize = 24_000;

pub struct OpenAiHarness {
    client: reqwest::Client,
    endpoint: String,
    api_key: Option<String>,
    model: String,
    utility_model: String,
    max_tokens: u32,
}

/// Written by hand rather than derived: a derived `Debug` would print the API
/// key into any log line or panic message that formats the harness.
impl std::fmt::Debug for OpenAiHarness {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OpenAiHarness")
            .field("endpoint", &self.endpoint)
            .field("api_key", &self.api_key.as_ref().map(|_| "<redacted>"))
            .field("model", &self.model)
            .field("utility_model", &self.utility_model)
            .field("max_tokens", &self.max_tokens)
            .finish()
    }
}

impl OpenAiHarness {
    /// Build the harness, refusing to start without an endpoint.
    ///
    /// There is deliberately no implicit default endpoint: a mistyped config
    /// should fail loudly at boot rather than send a scope's data somewhere
    /// unintended.
    pub fn new(config: &HarnessConfig) -> AppResult<Self> {
        let endpoint = config
            .endpoint
            .as_deref()
            .map(str::trim)
            .filter(|e| !e.is_empty())
            .ok_or_else(|| {
                AppError::bad_request(
                    "[harness].endpoint is not configured — set an OpenAI-compatible base URL \
                     (including /v1), or use kind = \"mock\"",
                )
            })?
            .trim_end_matches('/')
            .to_string();

        let api_key = config.resolve_api_key();
        if api_key.is_none() {
            tracing::warn!(
                "no harness API key configured — set [harness].api_key or the {} env var",
                config.api_key_env
            );
        }

        Ok(Self {
            client: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(config.timeout_secs.max(1)))
                .build()?,
            endpoint,
            api_key,
            model: config.model.clone(),
            utility_model: config
                .utility_model
                .clone()
                .unwrap_or_else(|| config.model.clone()),
            max_tokens: config.max_tokens,
        })
    }

    async fn complete(&self, body: serde_json::Value) -> AppResult<ChatResponse> {
        let mut request = self
            .client
            .post(format!("{}/chat/completions", self.endpoint))
            .json(&body);
        if let Some(key) = &self.api_key {
            request = request.bearer_auth(key);
        }

        let response = request.send().await?;
        let status = response.status();
        let text = response.text().await?;
        if !status.is_success() {
            // The body carries the gateway's reason (rate limit, bad model,
            // policy); truncate so a huge error page cannot flood the log.
            let detail: String = text.chars().take(600).collect();
            return Err(AppError::internal(format!(
                "model gateway returned {status}: {detail}"
            )));
        }
        serde_json::from_str(&text).map_err(|e| {
            let detail: String = text.chars().take(600).collect();
            AppError::internal(format!(
                "could not parse the gateway response: {e}; body: {detail}"
            ))
        })
    }
}

// --- wire types -------------------------------------------------------------

#[derive(Debug, Deserialize)]
struct ChatResponse {
    #[serde(default)]
    choices: Vec<Choice>,
}

#[derive(Debug, Deserialize)]
struct Choice {
    #[serde(default)]
    message: Message,
}

#[derive(Debug, Default, Deserialize)]
struct Message {
    #[serde(default)]
    content: Option<String>,
    #[serde(default)]
    reasoning_content: Option<String>,
    #[serde(default)]
    tool_calls: Vec<ToolCall>,
}

#[derive(Debug, Clone, Deserialize)]
struct ToolCall {
    #[serde(default)]
    id: String,
    #[serde(default)]
    function: FunctionCall,
}

#[derive(Debug, Clone, Default, Deserialize)]
struct FunctionCall {
    #[serde(default)]
    name: String,
    /// Providers send this as a JSON *string*, not an object.
    #[serde(default)]
    arguments: String,
}

impl FunctionCall {
    /// Parse the argument string, tolerating the empty string a provider sends
    /// for a no-argument tool.
    fn parsed_arguments(&self) -> Result<serde_json::Value, serde_json::Error> {
        let raw = self.arguments.trim();
        if raw.is_empty() {
            return Ok(json!({}));
        }
        serde_json::from_str(raw)
    }
}

#[async_trait]
impl Harness for OpenAiHarness {
    fn name(&self) -> &str {
        "openai"
    }

    async fn run_turn(&self, input: TurnInput<'_>) -> AppResult<HarnessOutcome> {
        let model = input.model.unwrap_or_else(|| self.model.clone());
        let specs = input.tools.specs();
        let tools: Vec<serde_json::Value> = specs
            .iter()
            .map(|spec| {
                json!({
                    "type": "function",
                    "function": {
                        "name": spec.name,
                        "description": spec.description,
                        "parameters": spec.parameters,
                    }
                })
            })
            .collect();

        let mut messages: Vec<serde_json::Value> =
            vec![json!({ "role": "system", "content": input.system_prompt })];
        for (role, text) in render_history(input.history, HISTORY_BUDGET_CHARS) {
            messages.push(json!({ "role": role, "content": text }));
        }
        messages.push(json!({ "role": "user", "content": input.text }));

        let mut outcome = HarnessOutcome::default();

        while outcome.steps < input.max_steps {
            outcome.steps += 1;

            let mut body = json!({
                "model": model,
                "messages": messages,
                "max_tokens": self.max_tokens,
            });
            if !tools.is_empty() {
                body["tools"] = json!(tools);
                body["tool_choice"] = json!("auto");
            }

            let response = self.complete(body).await?;
            let Some(choice) = response.choices.into_iter().next() else {
                return Err(AppError::internal("the model returned no choices"));
            };
            let message = choice.message;

            if let Some(thinking) = message
                .reasoning_content
                .as_deref()
                .map(str::trim)
                .filter(|t| !t.is_empty())
            {
                input
                    .sink
                    .emit(NewEntry::text(
                        EntryType::Thinking,
                        input.scope_label.clone(),
                        thinking,
                    ))
                    .await?;
            }

            if message.tool_calls.is_empty() {
                outcome.reply = message.content.unwrap_or_default().trim().to_string();
                if !outcome.reply.is_empty() {
                    input
                        .sink
                        .emit(NewEntry::text(
                            EntryType::Assistant,
                            input.scope_label.clone(),
                            &outcome.reply,
                        ))
                        .await?;
                }
                return Ok(outcome);
            }

            // Echo the assistant's tool-call message back verbatim: the
            // provider requires each tool result to answer a call it can see.
            messages.push(json!({
                "role": "assistant",
                "content": message.content.clone().unwrap_or_default(),
                "tool_calls": message.tool_calls.iter().map(|c| json!({
                    "id": c.id,
                    "type": "function",
                    "function": { "name": c.function.name, "arguments": c.function.arguments },
                })).collect::<Vec<_>>(),
            }));

            for call in &message.tool_calls {
                let args = match call.function.parsed_arguments() {
                    Ok(args) => args,
                    Err(e) => {
                        // Tell the model rather than failing the turn: a
                        // malformed argument string is usually recoverable on
                        // the next step.
                        messages.push(json!({
                            "role": "tool",
                            "tool_call_id": call.id,
                            "content": format!("error: arguments were not valid JSON: {e}"),
                        }));
                        continue;
                    }
                };

                let entry = input
                    .sink
                    .emit(NewEntry::new(
                        EntryType::ToolCall,
                        input.scope_label.clone(),
                        json!({ "tool": call.function.name, "args": args }),
                    ))
                    .await?;

                if input.approve_every_tool {
                    outcome.pending_approval = Some(PendingApprovalRequest {
                        command: format!("{} {}", call.function.name, args),
                        reason: "strict posture: every tool call needs approval".into(),
                        matched: None,
                        approval_key: format!("tool:{}", call.function.name),
                    });
                    return Ok(outcome);
                }

                let result = input.tools.call(&call.function.name, &args).await;
                let content = match result {
                    ToolOutcome::Output(text) => text,
                    ToolOutcome::Denied(reason) => format!("denied: {reason}"),
                    ToolOutcome::NeedsApproval {
                        command,
                        reason,
                        matched,
                        approval_key,
                    } => {
                        outcome.pending_approval = Some(PendingApprovalRequest {
                            command,
                            reason,
                            matched,
                            approval_key,
                        });
                        return Ok(outcome);
                    }
                    ToolOutcome::EndTurn { reply, silent } => {
                        outcome.reply = reply;
                        outcome.silent = silent;
                        return Ok(outcome);
                    }
                };

                input
                    .sink
                    .emit(
                        NewEntry::text(EntryType::ToolResult, input.scope_label.clone(), &content)
                            .with_parent(entry.seq),
                    )
                    .await?;
                messages.push(json!({
                    "role": "tool",
                    "tool_call_id": call.id,
                    "content": content,
                }));
            }
        }

        // The budget ran out mid-work. Say so rather than returning an empty
        // reply that reads like the model had nothing to add.
        outcome.hit_step_limit = true;
        outcome.reply = format!(
            "I stopped after {} tool steps without finishing. Ask me to continue if that \
             looks like more work than expected.",
            outcome.steps
        );
        input
            .sink
            .emit(NewEntry::text(
                EntryType::Assistant,
                input.scope_label.clone(),
                &outcome.reply,
            ))
            .await?;
        Ok(outcome)
    }

    async fn one_shot(&self, system_prompt: &str, prompt: &str) -> AppResult<Option<String>> {
        let body = json!({
            "model": self.utility_model,
            "messages": [
                { "role": "system", "content": system_prompt },
                { "role": "user", "content": prompt },
            ],
            "max_tokens": 512,
        });
        // Utility calls are best-effort: a title or a screen verdict that
        // cannot be fetched must degrade, not fail the turn. Callers treat
        // `None` as "unavailable" and handle it explicitly.
        match self.complete(body).await {
            Ok(response) => Ok(response
                .choices
                .into_iter()
                .next()
                .and_then(|c| c.message.content)
                .map(|c| c.trim().to_string())
                .filter(|c| !c.is_empty())),
            Err(e) => {
                tracing::warn!(error = %e, "one-shot model call failed");
                Ok(None)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config() -> HarnessConfig {
        HarnessConfig {
            kind: "openai".into(),
            endpoint: Some("https://gateway.test/v1".into()),
            api_key: Some("k".into()),
            ..HarnessConfig::default()
        }
    }

    #[test]
    fn a_missing_endpoint_is_a_refusal_not_a_default() {
        let err = OpenAiHarness::new(&HarnessConfig::default()).unwrap_err();
        let message = err.to_string();
        assert!(
            message.contains("[harness].endpoint is not configured"),
            "{message}"
        );
        assert!(
            message.contains("mock"),
            "the error should point at the alternative"
        );
    }

    #[test]
    fn a_trailing_slash_on_the_endpoint_is_normalized() {
        let harness = OpenAiHarness::new(&HarnessConfig {
            endpoint: Some("https://gateway.test/v1/".into()),
            ..config()
        })
        .unwrap();
        assert_eq!(harness.endpoint, "https://gateway.test/v1");
    }

    #[test]
    fn the_utility_model_falls_back_to_the_main_model() {
        let harness = OpenAiHarness::new(&config()).unwrap();
        assert_eq!(harness.utility_model, harness.model);

        let split = OpenAiHarness::new(&HarnessConfig {
            utility_model: Some("cheap".into()),
            ..config()
        })
        .unwrap();
        assert_eq!(split.utility_model, "cheap");
        assert_ne!(split.model, "cheap");
    }

    #[test]
    fn a_harness_builds_without_a_key_so_local_gateways_work() {
        let harness = OpenAiHarness::new(&HarnessConfig {
            api_key: None,
            api_key_env: "QM_TEST_ABSENT_KEY".into(),
            ..config()
        })
        .unwrap();
        assert!(harness.api_key.is_none());
    }

    #[test]
    fn empty_tool_arguments_parse_to_an_empty_object() {
        let call = FunctionCall {
            name: "stay_silent".into(),
            arguments: String::new(),
        };
        assert_eq!(call.parsed_arguments().unwrap(), json!({}));

        let spaced = FunctionCall {
            name: "x".into(),
            arguments: "   ".into(),
        };
        assert_eq!(spaced.parsed_arguments().unwrap(), json!({}));
    }

    #[test]
    fn tool_arguments_parse_from_the_provider_json_string() {
        let call = FunctionCall {
            name: "execute".into(),
            arguments: r#"{"command":"ls -la"}"#.into(),
        };
        assert_eq!(call.parsed_arguments().unwrap()["command"], "ls -la");

        let broken = FunctionCall {
            name: "execute".into(),
            arguments: "{not json".into(),
        };
        assert!(broken.parsed_arguments().is_err());
    }

    #[test]
    fn a_chat_response_deserializes_with_and_without_tool_calls() {
        let plain: ChatResponse = serde_json::from_str(
            r#"{"choices":[{"message":{"role":"assistant","content":"hello"}}]}"#,
        )
        .unwrap();
        assert_eq!(plain.choices[0].message.content.as_deref(), Some("hello"));
        assert!(plain.choices[0].message.tool_calls.is_empty());

        let with_tools: ChatResponse = serde_json::from_str(
            r#"{"choices":[{"message":{"role":"assistant","content":null,
                "tool_calls":[{"id":"c1","type":"function",
                "function":{"name":"execute","arguments":"{\"command\":\"ls\"}"}}]}}]}"#,
        )
        .unwrap();
        let call = &with_tools.choices[0].message.tool_calls[0];
        assert_eq!(call.id, "c1");
        assert_eq!(call.function.name, "execute");
        assert_eq!(call.function.parsed_arguments().unwrap()["command"], "ls");

        // A response with no choices at all must not panic on deserialize.
        let empty: ChatResponse = serde_json::from_str(r#"{"choices":[]}"#).unwrap();
        assert!(empty.choices.is_empty());
    }

    #[test]
    fn reasoning_content_is_picked_up_when_a_gateway_sends_it() {
        let response: ChatResponse = serde_json::from_str(
            r#"{"choices":[{"message":{"role":"assistant","reasoning_content":"thinking...","content":"answer"}}]}"#,
        )
        .unwrap();
        assert_eq!(
            response.choices[0].message.reasoning_content.as_deref(),
            Some("thinking...")
        );
    }
}
