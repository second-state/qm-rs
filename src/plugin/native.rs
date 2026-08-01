//! The no-op plugin host used when the `wasm` feature is off.
//!
//! Configured modules are reported as inert rather than silently ignored: an
//! operator who configured a screener and got a build without WasmEdge must be
//! able to see that from the admin page, because the fallback is the model
//! screener rather than their own.

use super::{PluginHost, PluginRequest, PluginResponse, PluginTool};
use crate::config::PluginsConfig;
use crate::types::ScopeId;

pub struct NativeHost {
    configured: Vec<String>,
    middleware: Vec<String>,
    screener: Option<String>,
}

impl NativeHost {
    pub fn new(config: &PluginsConfig) -> Self {
        let mut configured: Vec<String> = config.turn_middleware.clone();
        configured.extend(config.tools.iter().map(|t| t.module.clone()));
        if let Some(screener) = &config.screener {
            configured.push(screener.clone());
        }
        if !configured.is_empty() {
            tracing::warn!(
                modules = configured.len(),
                "plugin modules are configured but this binary was built without the \
                 `wasm` feature — they are inert; rebuild with `--features wasm`"
            );
        }
        Self {
            configured,
            middleware: Vec::new(),
            screener: None,
        }
    }
}

impl PluginHost for NativeHost {
    fn tools(&self, _scope: &ScopeId) -> Vec<PluginTool> {
        Vec::new()
    }

    fn call(&self, module: &str, _request: &PluginRequest) -> PluginResponse {
        PluginResponse::failure(format!(
            "plugin {module} cannot run: this binary was built without the `wasm` feature"
        ))
    }

    /// Empty even when modules are configured — reporting them here would run
    /// a chain that cannot execute.
    fn turn_middleware(&self) -> &[String] {
        &self.middleware
    }

    fn screener(&self) -> Option<&str> {
        self.screener.as_deref()
    }

    fn is_active(&self) -> bool {
        false
    }

    fn describe(&self) -> Vec<String> {
        if self.configured.is_empty() {
            return vec!["no plugin modules configured".into()];
        }
        self.configured
            .iter()
            .map(|m| format!("{m} — inert (built without the `wasm` feature)"))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::PluginToolConfig;

    #[test]
    fn an_unconfigured_host_is_quiet_and_offers_nothing() {
        let host = NativeHost::new(&PluginsConfig::default());
        assert!(host.tools(&ScopeId::personal("u1")).is_empty());
        assert!(host.turn_middleware().is_empty());
        assert!(host.screener().is_none());
        assert!(!host.is_active());
        assert_eq!(host.describe(), vec!["no plugin modules configured"]);
    }

    #[test]
    fn configured_modules_are_reported_as_inert_not_silently_dropped() {
        let host = NativeHost::new(&PluginsConfig {
            turn_middleware: vec!["route.wasm".into()],
            screener: Some("screen.wasm".into()),
            tools: vec![PluginToolConfig {
                name: "lookup".into(),
                description: "d".into(),
                module: "orders.wasm".into(),
                parameters: None,
                scopes: vec![],
            }],
            ..PluginsConfig::default()
        });

        let described = host.describe();
        assert_eq!(described.len(), 3);
        assert!(described.iter().all(|d| d.contains("inert")));
        assert!(described.iter().any(|d| d.starts_with("screen.wasm")));

        // Crucially: the chain stays empty, so nothing tries to run.
        assert!(host.turn_middleware().is_empty());
        assert!(host.screener().is_none());
        assert!(!host.call("route.wasm", &request()).ok);
    }

    fn request() -> PluginRequest {
        PluginRequest {
            hook: "turn.before".into(),
            scope: "personal:u1".into(),
            actor: "u1".into(),
            session_id: None,
            payload: serde_json::json!({}),
        }
    }
}
