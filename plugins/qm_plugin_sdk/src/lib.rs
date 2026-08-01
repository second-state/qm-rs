//! SDK for qm-rs WasmEdge plugin modules.
//!
//! A module implements one extension point — a custom agent tool, turn
//! middleware, or the security screener — as a single safe Rust function. The
//! [`handler!`] macro generates the `allocate` / `run` exports the host calls.
//!
//! # Example
//!
//! ```rust,ignore
//! use qm_plugin_sdk::{PluginRequest, PluginResponse};
//!
//! qm_plugin_sdk::handler!(process);
//!
//! fn process(req: PluginRequest) -> PluginResponse {
//!     match req.hook.as_str() {
//!         "turn.before" => PluginResponse::rewrite(req.text().to_uppercase()),
//!         _ => PluginResponse::failure("unsupported hook"),
//!     }
//! }
//! ```
//!
//! Build for the host with:
//!
//! ```bash
//! cargo build --release --target wasm32-wasip1
//! ```

pub use serde_json;

use serde::{Deserialize, Serialize};

/// What the host is asking for.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginRequest {
    /// `tool:<name>`, `turn.before`, or `screen`.
    pub hook: String,
    /// Scope id the turn is running in, e.g. `personal:u1`.
    pub scope: String,
    /// Principal id of whoever is asking.
    pub actor: String,
    #[serde(default)]
    pub session_id: Option<String>,
    /// Hook-specific data. `turn.before` carries `{"text": ...}`; a tool hook
    /// carries the model's arguments; `screen` carries
    /// `{"source": ..., "content": ...}`.
    pub payload: serde_json::Value,
}

impl PluginRequest {
    /// `payload.text` — the user text for `turn.before`.
    pub fn text(&self) -> &str {
        self.payload
            .get("text")
            .and_then(|v| v.as_str())
            .unwrap_or("")
    }

    /// `payload.content` — the material to judge for `screen`.
    pub fn content(&self) -> &str {
        self.payload
            .get("content")
            .and_then(|v| v.as_str())
            .unwrap_or("")
    }

    /// A named string argument from a tool call.
    pub fn arg(&self, name: &str) -> Option<&str> {
        self.payload.get(name).and_then(|v| v.as_str())
    }

    /// The tool name, for a `tool:<name>` hook.
    pub fn tool_name(&self) -> Option<&str> {
        self.hook.strip_prefix("tool:")
    }
}

/// What the module hands back.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PluginResponse {
    pub ok: bool,
    /// Tool hooks: the text the model sees as the tool result.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub output: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// `turn.before`: replace the user text.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
    /// `turn.before`: route to a different model.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
    /// `turn.before`: append to the system prompt.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub system_suffix: Option<String>,
    /// `screen`: `auto` to allow, `strict` to quarantine.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub decision: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

impl PluginResponse {
    /// A tool result.
    pub fn output(text: impl Into<String>) -> Self {
        Self {
            ok: true,
            output: Some(text.into()),
            ..Default::default()
        }
    }

    /// Leave the turn as it is.
    pub fn pass() -> Self {
        Self {
            ok: true,
            ..Default::default()
        }
    }

    /// Replace the user text.
    pub fn rewrite(text: impl Into<String>) -> Self {
        Self {
            ok: true,
            text: Some(text.into()),
            ..Default::default()
        }
    }

    /// Route this turn to a different model.
    pub fn route(mut self, model: impl Into<String>) -> Self {
        self.model = Some(model.into());
        self
    }

    /// Append an instruction to the system prompt.
    pub fn instruct(mut self, suffix: impl Into<String>) -> Self {
        self.system_suffix = Some(suffix.into());
        self
    }

    /// Let the content through.
    pub fn allow() -> Self {
        Self {
            ok: true,
            decision: Some("auto".into()),
            ..Default::default()
        }
    }

    /// Quarantine the content.
    pub fn quarantine(reason: impl Into<String>) -> Self {
        Self {
            ok: true,
            decision: Some("strict".into()),
            reason: Some(reason.into()),
            ..Default::default()
        }
    }

    /// Report failure. The host logs it and carries on without this module —
    /// except on the `screen` hook, where a failure fails closed.
    pub fn failure(error: impl Into<String>) -> Self {
        Self {
            ok: false,
            error: Some(error.into()),
            ..Default::default()
        }
    }
}

/// Generate the `allocate` and `run` exports around a handler function.
///
/// The handler must have the signature `fn(PluginRequest) -> PluginResponse`.
#[macro_export]
macro_rules! handler {
    ($handler_fn:ident) => {
        /// Reserve `len` bytes for the host to write the request into.
        ///
        /// # Safety
        /// The host is trusted to write exactly `len` bytes at the returned
        /// pointer and to pass that same pointer and length to `run`.
        #[no_mangle]
        pub extern "C" fn allocate(len: i32) -> i32 {
            let mut buffer = Vec::<u8>::with_capacity(len.max(0) as usize);
            let ptr = buffer.as_mut_ptr();
            ::std::mem::forget(buffer);
            ptr as i32
        }

        /// Run the handler over the request at `ptr`, returning
        /// `(out_ptr << 32) | out_len`.
        ///
        /// # Safety
        /// `ptr`/`len` must describe a buffer the host obtained from
        /// `allocate` and filled with the request bytes.
        #[no_mangle]
        pub extern "C" fn run(ptr: i32, len: i32) -> i64 {
            let input =
                unsafe { ::std::slice::from_raw_parts(ptr as *const u8, len.max(0) as usize) };
            let response = match $crate::serde_json::from_slice::<$crate::PluginRequest>(input) {
                Ok(request) => $handler_fn(request),
                Err(e) => $crate::PluginResponse::failure(::std::format!(
                    "could not parse the plugin request: {e}"
                )),
            };
            let mut bytes = $crate::serde_json::to_vec(&response).unwrap_or_else(|_| {
                br#"{"ok":false,"error":"could not serialize the plugin response"}"#.to_vec()
            });
            let out_ptr = bytes.as_mut_ptr() as i64;
            let out_len = bytes.len() as i64;
            ::std::mem::forget(bytes);
            (out_ptr << 32) | out_len
        }
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(hook: &str, payload: serde_json::Value) -> PluginRequest {
        PluginRequest {
            hook: hook.into(),
            scope: "personal:u1".into(),
            actor: "u1".into(),
            session_id: None,
            payload,
        }
    }

    #[test]
    fn accessors_read_the_payload_without_panicking_on_absence() {
        let r = request("turn.before", serde_json::json!({"text": "hello"}));
        assert_eq!(r.text(), "hello");
        assert_eq!(r.content(), "");
        assert_eq!(r.arg("missing"), None);
        assert_eq!(r.tool_name(), None);

        let t = request("tool:lookup", serde_json::json!({"order_id": "A1"}));
        assert_eq!(t.tool_name(), Some("lookup"));
        assert_eq!(t.arg("order_id"), Some("A1"));
    }

    #[test]
    fn responses_serialize_to_the_wire_shape_the_host_expects() {
        let json = serde_json::to_value(PluginResponse::output("done")).unwrap();
        assert_eq!(json["ok"], true);
        assert_eq!(json["output"], "done");
        assert!(json.get("error").is_none(), "absent fields stay absent");

        let routed = serde_json::to_value(PluginResponse::pass().route("fast-model")).unwrap();
        assert_eq!(routed["model"], "fast-model");

        let quarantined = serde_json::to_value(PluginResponse::quarantine("injection")).unwrap();
        assert_eq!(quarantined["decision"], "strict");
        assert_eq!(quarantined["reason"], "injection");

        assert_eq!(
            serde_json::to_value(PluginResponse::allow()).unwrap()["decision"],
            "auto"
        );
    }

    #[test]
    fn builders_compose() {
        let r = PluginResponse::rewrite("new text")
            .route("model-b")
            .instruct("Be brief.");
        assert_eq!(r.text.as_deref(), Some("new text"));
        assert_eq!(r.model.as_deref(), Some("model-b"));
        assert_eq!(r.system_suffix.as_deref(), Some("Be brief."));
        assert!(r.ok);
    }
}
