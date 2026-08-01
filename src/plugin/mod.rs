//! Extension points.
//!
//! QM lets a deployment inject organization-specific behaviour without forking
//! core: custom agent tools, turn middleware, and its own security screener.
//! Here those are WasmEdge modules — sandboxed, hot-swappable, and selected
//! per scope.
//!
//! Surfaces (the web UI, the Telegram connector) are deliberately *not* here.
//! They hold sockets and timers and are native in-process Rust; a Wasm module
//! is a pure function over bytes, which is the wrong shape for a daemon.
//!
//! # ABI
//!
//! The same contract `cloud_ai_gateway` uses, so modules and tooling carry
//! across. A module exports:
//!
//! ```text
//! allocate(len: i32) -> i32          // reserve len bytes, return the pointer
//! run(ptr: i32, len: i32) -> i64     // (out_ptr << 32) | out_len
//! ```
//!
//! Input and output are both JSON: a [`PluginRequest`] in, a
//! [`PluginResponse`] out. `plugins/qm_plugin_sdk` wraps this so a module
//! author writes one safe Rust function.

pub mod native;
#[cfg(feature = "wasm")]
pub mod wasm;

use serde::{Deserialize, Serialize};

use crate::config::PluginsConfig;
use crate::error::AppResult;
use crate::policy::{ScreenDecision, SecurityScreenVerdict};
use crate::types::ScopeId;

/// Which extension point is being invoked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Hook {
    /// A custom agent tool, by the name the model sees.
    Tool(String),
    /// Middleware run before the model, able to rewrite the turn.
    TurnBefore,
    /// A deployment's own security screener.
    Screen,
}

impl Hook {
    pub fn as_str(&self) -> String {
        match self {
            Self::Tool(name) => format!("tool:{name}"),
            Self::TurnBefore => "turn.before".to_string(),
            Self::Screen => "screen".to_string(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginRequest {
    pub hook: String,
    pub scope: String,
    pub actor: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    pub payload: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PluginResponse {
    #[serde(default)]
    pub ok: bool,
    /// Tool hooks: the text handed back to the model.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// `turn.before`: replace the user text.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
    /// `turn.before`: route to a different model.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
    /// `turn.before`: append to the system prompt.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub system_suffix: Option<String>,
    /// `screen`: `auto` or `strict`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decision: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

impl PluginResponse {
    pub fn failure(error: impl Into<String>) -> Self {
        Self {
            ok: false,
            error: Some(error.into()),
            ..Default::default()
        }
    }

    /// Interpret this response as a screener verdict.
    ///
    /// Anything other than an explicit `auto` is `strict`: a malformed or
    /// failed screener must fail closed, exactly as the model screener does.
    pub fn as_verdict(&self) -> SecurityScreenVerdict {
        if !self.ok {
            return SecurityScreenVerdict::strict(
                self.error
                    .clone()
                    .unwrap_or_else(|| "screener failed".into()),
            );
        }
        match self.decision.as_deref() {
            Some("auto") => SecurityScreenVerdict::auto(),
            Some("strict") => SecurityScreenVerdict {
                decision: ScreenDecision::Strict,
                reason: self.reason.clone(),
                unscreened: false,
            },
            _ => SecurityScreenVerdict::strict("invalid plugin screen verdict"),
        }
    }
}

/// A custom tool a plugin contributes to the agent's tool surface.
#[derive(Debug, Clone)]
pub struct PluginTool {
    pub name: String,
    pub description: String,
    /// JSON Schema for the arguments.
    pub parameters: serde_json::Value,
    pub module: String,
}

/// The seam. [`native::NativeHost`] is the no-op implementation used when the
/// `wasm` feature is off; `wasm::WasmHost` runs real modules when it is on.
pub trait PluginHost: Send + Sync {
    /// Tools offered to `scope`.
    fn tools(&self, scope: &ScopeId) -> Vec<PluginTool>;

    /// Invoke a module. Errors are returned rather than propagated so one bad
    /// module cannot fail a turn.
    fn call(&self, module: &str, request: &PluginRequest) -> PluginResponse;

    /// Modules run before the model, in configured order.
    fn turn_middleware(&self) -> &[String];

    /// The configured screener module, if any.
    fn screener(&self) -> Option<&str>;

    /// Whether real modules can actually run in this build.
    fn is_active(&self) -> bool;

    /// One line per configured module for the admin page.
    fn describe(&self) -> Vec<String>;
}

/// Run the `turn.before` chain, folding each module's rewrites together.
///
/// Last writer wins on any field, matching the gateway's team → user → key
/// ordering. A module that fails is logged and skipped: middleware is an
/// extension point, not a gate.
pub fn apply_turn_middleware(
    host: &dyn PluginHost,
    scope: &ScopeId,
    actor: &str,
    session_id: Option<&str>,
    text: &str,
) -> TurnRewrite {
    let mut rewrite = TurnRewrite {
        text: text.to_string(),
        model: None,
        system_suffix: None,
    };
    for module in host.turn_middleware() {
        let request = PluginRequest {
            hook: Hook::TurnBefore.as_str(),
            scope: scope.to_string(),
            actor: actor.to_string(),
            session_id: session_id.map(str::to_string),
            payload: serde_json::json!({ "text": rewrite.text }),
        };
        let response = host.call(module, &request);
        if !response.ok {
            tracing::warn!(
                module,
                error = response.error.as_deref().unwrap_or("unknown"),
                "turn middleware failed — skipping it"
            );
            continue;
        }
        if let Some(text) = response.text {
            rewrite.text = text;
        }
        if let Some(model) = response.model {
            rewrite.model = Some(model);
        }
        if let Some(suffix) = response.system_suffix {
            // Suffixes accumulate rather than overwrite: two modules that each
            // add an instruction should both be heard.
            rewrite.system_suffix = Some(match rewrite.system_suffix {
                Some(existing) => format!("{existing}\n{suffix}"),
                None => suffix,
            });
        }
    }
    rewrite
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TurnRewrite {
    pub text: String,
    pub model: Option<String>,
    pub system_suffix: Option<String>,
}

/// Build the host this build supports.
pub fn build_host(config: &PluginsConfig) -> AppResult<Box<dyn PluginHost>> {
    #[cfg(feature = "wasm")]
    {
        Ok(Box::new(wasm::WasmHost::new(config)?))
    }
    #[cfg(not(feature = "wasm"))]
    {
        Ok(Box::new(native::NativeHost::new(config)))
    }
}

#[cfg(test)]
pub(crate) mod testing {
    use super::*;
    use std::collections::HashMap;

    /// A host backed by canned responses, for testing call sites without a
    /// Wasm runtime.
    pub struct StubHost {
        pub responses: HashMap<String, PluginResponse>,
        pub tools: Vec<PluginTool>,
        pub middleware: Vec<String>,
        pub screener: Option<String>,
    }

    impl StubHost {
        pub fn new() -> Self {
            Self {
                responses: HashMap::new(),
                tools: Vec::new(),
                middleware: Vec::new(),
                screener: None,
            }
        }

        pub fn with_response(mut self, module: &str, response: PluginResponse) -> Self {
            self.responses.insert(module.to_string(), response);
            self
        }

        pub fn with_middleware(mut self, modules: &[&str]) -> Self {
            self.middleware = modules.iter().map(|m| m.to_string()).collect();
            self
        }
    }

    impl PluginHost for StubHost {
        fn tools(&self, _scope: &ScopeId) -> Vec<PluginTool> {
            self.tools.clone()
        }

        fn call(&self, module: &str, _request: &PluginRequest) -> PluginResponse {
            self.responses
                .get(module)
                .cloned()
                .unwrap_or_else(|| PluginResponse::failure(format!("no stub for {module}")))
        }

        fn turn_middleware(&self) -> &[String] {
            &self.middleware
        }

        fn screener(&self) -> Option<&str> {
            self.screener.as_deref()
        }

        fn is_active(&self) -> bool {
            true
        }

        fn describe(&self) -> Vec<String> {
            vec!["stub".into()]
        }
    }
}

#[cfg(test)]
mod tests {
    use super::testing::StubHost;
    use super::*;

    fn scope() -> ScopeId {
        ScopeId::personal("u1")
    }

    #[test]
    fn hooks_render_their_wire_names() {
        assert_eq!(Hook::Tool("lookup".into()).as_str(), "tool:lookup");
        assert_eq!(Hook::TurnBefore.as_str(), "turn.before");
        assert_eq!(Hook::Screen.as_str(), "screen");
    }

    #[test]
    fn middleware_rewrites_fold_with_last_writer_winning_on_scalars() {
        let host = StubHost::new()
            .with_middleware(&["a.wasm", "b.wasm"])
            .with_response(
                "a.wasm",
                PluginResponse {
                    ok: true,
                    text: Some("rewritten by a".into()),
                    model: Some("model-a".into()),
                    system_suffix: Some("from a".into()),
                    ..Default::default()
                },
            )
            .with_response(
                "b.wasm",
                PluginResponse {
                    ok: true,
                    model: Some("model-b".into()),
                    system_suffix: Some("from b".into()),
                    ..Default::default()
                },
            );

        let rewrite = apply_turn_middleware(&host, &scope(), "u1", None, "original");
        assert_eq!(rewrite.text, "rewritten by a", "b left the text alone");
        assert_eq!(
            rewrite.model.as_deref(),
            Some("model-b"),
            "last writer wins"
        );
        assert_eq!(
            rewrite.system_suffix.as_deref(),
            Some("from a\nfrom b"),
            "suffixes accumulate so both modules are heard"
        );
    }

    #[test]
    fn a_failing_module_is_skipped_rather_than_failing_the_turn() {
        let host = StubHost::new()
            .with_middleware(&["broken.wasm", "good.wasm"])
            .with_response("broken.wasm", PluginResponse::failure("trap"))
            .with_response(
                "good.wasm",
                PluginResponse {
                    ok: true,
                    text: Some("still works".into()),
                    ..Default::default()
                },
            );
        let rewrite = apply_turn_middleware(&host, &scope(), "u1", None, "original");
        assert_eq!(rewrite.text, "still works");
    }

    #[test]
    fn no_middleware_leaves_the_turn_untouched() {
        let host = StubHost::new();
        let rewrite = apply_turn_middleware(&host, &scope(), "u1", None, "original");
        assert_eq!(rewrite.text, "original");
        assert!(rewrite.model.is_none());
        assert!(rewrite.system_suffix.is_none());
    }

    #[test]
    fn a_plugin_screen_verdict_fails_closed() {
        let auto = PluginResponse {
            ok: true,
            decision: Some("auto".into()),
            ..Default::default()
        };
        assert!(!auto.as_verdict().quarantined());

        let strict = PluginResponse {
            ok: true,
            decision: Some("strict".into()),
            reason: Some("injection".into()),
            ..Default::default()
        };
        assert!(strict.as_verdict().quarantined());
        assert_eq!(strict.as_verdict().reason.as_deref(), Some("injection"));

        // Anything else is strict.
        for response in [
            PluginResponse::failure("trap"),
            PluginResponse {
                ok: true,
                decision: None,
                ..Default::default()
            },
            PluginResponse {
                ok: true,
                decision: Some("dangerous".into()),
                ..Default::default()
            },
        ] {
            assert!(
                response.as_verdict().quarantined(),
                "a non-auto verdict must fail closed: {response:?}"
            );
        }
    }
}
