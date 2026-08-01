//! The WasmEdge plugin host.
//!
//! Built only under the `wasm` feature, because `wasmedge-sys` is unavailable
//! on some targets (musl, for one). The ABI matches `cloud_ai_gateway` so
//! modules and authoring tooling carry across the two projects:
//!
//! ```text
//! allocate(len: i32) -> i32          // reserve len bytes, return the pointer
//! run(ptr: i32, len: i32) -> i64     // (out_ptr << 32) | out_len
//! ```
//!
//! Each call gets a fresh store and instance. That costs an instantiation per
//! call and buys the property that matters for a multi-tenant agent: one
//! scope's call cannot observe or corrupt another's module state.

use std::path::{Path, PathBuf};

use wasmedge_sdk::WasmValue;
use wasmedge_sys::{AsInstance, Config, Executor, Loader, Store, Validator, WasiModule};

use super::{PluginHost, PluginRequest, PluginResponse, PluginTool};
use crate::config::PluginsConfig;
use crate::error::{AppError, AppResult};
use crate::types::ScopeId;

pub struct WasmHost {
    dir: PathBuf,
    tools: Vec<(PluginTool, Vec<String>)>,
    middleware: Vec<String>,
    screener: Option<String>,
}

impl WasmHost {
    pub fn new(config: &PluginsConfig) -> AppResult<Self> {
        let mut tools = Vec::new();
        for tool in &config.tools {
            let parameters = match tool.parameters.as_deref() {
                Some(raw) => serde_json::from_str(raw).map_err(|e| {
                    AppError::bad_request(format!(
                        "plugin tool {}: `parameters` is not valid JSON Schema: {e}",
                        tool.name
                    ))
                })?,
                None => serde_json::json!({ "type": "object", "properties": {} }),
            };
            tools.push((
                PluginTool {
                    name: tool.name.clone(),
                    description: tool.description.clone(),
                    parameters,
                    module: tool.module.clone(),
                },
                tool.scopes.clone(),
            ));
        }
        Ok(Self {
            dir: config.dir.clone(),
            tools,
            middleware: config.turn_middleware.clone(),
            screener: config.screener.clone(),
        })
    }

    /// Resolve a configured module name to a path inside the plugin directory.
    /// A name containing a separator or `..` is refused: module names come from
    /// config, but treating them as paths would make a typo a file-read.
    fn module_path(&self, module: &str) -> AppResult<PathBuf> {
        if module.is_empty()
            || module.contains('/')
            || module.contains('\\')
            || module.contains("..")
        {
            return Err(AppError::bad_request(format!(
                "invalid plugin module name {module:?}: use a bare filename under [plugins].dir"
            )));
        }
        let path = self.dir.join(module);
        if !path.is_file() {
            return Err(AppError::not_found(format!(
                "plugin module {module} (looked in {})",
                self.dir.display()
            )));
        }
        Ok(path)
    }

    fn invoke(&self, path: &Path, input: &[u8]) -> AppResult<Vec<u8>> {
        let wasi = WasiModule::create(None, None, None).map_err(|e| {
            AppError::internal(format!("wasm: could not create the WASI module: {e}"))
        })?;

        let mut config = Config::create()
            .map_err(|e| AppError::internal(format!("wasm: could not create a config: {e}")))?;
        config.bulk_memory_operations(true);
        config.reference_types(true);
        config.mutable_globals(true);
        config.non_trap_conversions(true);
        config.sign_extension_operators(true);

        let mut store = Store::create()
            .map_err(|e| AppError::internal(format!("wasm: could not create a store: {e}")))?;
        let mut executor = Executor::create(Some(&config), None)
            .map_err(|e| AppError::internal(format!("wasm: could not create an executor: {e}")))?;
        executor
            .register_import_module(&mut store, &wasi)
            .map_err(|e| AppError::internal(format!("wasm: could not register WASI: {e}")))?;

        let loader = Loader::create(Some(&config))
            .map_err(|e| AppError::internal(format!("wasm: could not create a loader: {e}")))?;
        let module = loader.from_file(path).map_err(|e| {
            AppError::internal(format!("wasm: could not load {}: {e}", path.display()))
        })?;

        // Validate before instantiating: an untrusted module must not reach
        // the executor unchecked.
        let validator = Validator::create(Some(&config))
            .map_err(|e| AppError::internal(format!("wasm: could not create a validator: {e}")))?;
        validator.validate(&module).map_err(|e| {
            AppError::internal(format!("wasm: {} failed validation: {e}", path.display()))
        })?;

        let mut instance = executor
            .register_active_module(&mut store, &module)
            .map_err(|e| AppError::internal(format!("wasm: could not instantiate: {e}")))?;

        // allocate(len) -> ptr, then copy the request into the module's memory.
        let len = i32::try_from(input.len())
            .map_err(|_| AppError::bad_request("wasm: plugin input exceeds 2GiB"))?;
        let ptr = {
            let mut allocate = instance
                .get_func_mut("allocate")
                .map_err(|e| AppError::internal(format!("wasm: allocate() not exported: {e}")))?;
            executor
                .call_func(&mut allocate, vec![WasmValue::from_i32(len)])
                .map_err(|e| AppError::internal(format!("wasm: allocate() failed: {e}")))?
                .first()
                .map(WasmValue::to_i32)
                .ok_or_else(|| AppError::internal("wasm: allocate() returned nothing"))?
        };

        {
            let mut memory = instance
                .get_memory_mut("memory")
                .map_err(|e| AppError::internal(format!("wasm: no exported memory: {e}")))?;
            memory
                .set_data(input, ptr as u32)
                .map_err(|e| AppError::internal(format!("wasm: could not write input: {e}")))?;
        }

        let packed = {
            let mut run = instance
                .get_func_mut("run")
                .map_err(|e| AppError::internal(format!("wasm: run() not exported: {e}")))?;
            executor
                .call_func(
                    &mut run,
                    vec![WasmValue::from_i32(ptr), WasmValue::from_i32(len)],
                )
                .map_err(|e| AppError::internal(format!("wasm: run() trapped: {e}")))?
                .first()
                .map(WasmValue::to_i64)
                .ok_or_else(|| AppError::internal("wasm: run() returned nothing"))?
        };

        // The module packs its result as (ptr << 32) | len.
        let out_ptr = (packed >> 32) as u32;
        let out_len = (packed & 0xffff_ffff) as u32;
        if out_len == 0 {
            return Err(AppError::internal("wasm: run() returned an empty result"));
        }

        let memory = instance
            .get_memory_ref("memory")
            .map_err(|e| AppError::internal(format!("wasm: no exported memory: {e}")))?;
        memory
            .get_data(out_ptr, out_len)
            .map_err(|e| AppError::internal(format!("wasm: could not read the result: {e}")))
    }
}

impl PluginHost for WasmHost {
    fn tools(&self, scope: &ScopeId) -> Vec<PluginTool> {
        self.tools
            .iter()
            .filter(|(_, scopes)| scopes.is_empty() || scopes.iter().any(|s| s == scope.as_str()))
            .map(|(tool, _)| tool.clone())
            .collect()
    }

    fn call(&self, module: &str, request: &PluginRequest) -> PluginResponse {
        let result = (|| -> AppResult<PluginResponse> {
            let path = self.module_path(module)?;
            let input = serde_json::to_vec(request)?;
            let output = self.invoke(&path, &input)?;
            serde_json::from_slice(&output).map_err(|e| {
                AppError::internal(format!("wasm: {module} returned malformed JSON: {e}"))
            })
        })();

        match result {
            Ok(response) => response,
            Err(e) => {
                tracing::warn!(module, error = %e, "plugin call failed");
                PluginResponse::failure(e.to_string())
            }
        }
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
        let mut out = Vec::new();
        for module in &self.middleware {
            out.push(format!(
                "{module} — turn.before {}",
                self.availability(module)
            ));
        }
        for (tool, scopes) in &self.tools {
            let where_ = if scopes.is_empty() {
                "all scopes".to_string()
            } else {
                scopes.join(", ")
            };
            out.push(format!(
                "{} — tool:{} for {where_} {}",
                tool.module,
                tool.name,
                self.availability(&tool.module)
            ));
        }
        if let Some(screener) = &self.screener {
            out.push(format!(
                "{screener} — screen {}",
                self.availability(screener)
            ));
        }
        if out.is_empty() {
            out.push("no plugin modules configured".into());
        }
        out
    }
}

impl WasmHost {
    fn availability(&self, module: &str) -> &'static str {
        match self.module_path(module) {
            Ok(_) => "(ready)",
            Err(_) => "(MISSING)",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::PluginToolConfig;

    fn host(config: PluginsConfig) -> WasmHost {
        WasmHost::new(&config).unwrap()
    }

    #[test]
    fn module_names_may_not_be_paths() {
        let h = host(PluginsConfig::default());
        for bad in ["../../etc/passwd", "sub/dir.wasm", "", "a..b"] {
            assert!(h.module_path(bad).is_err(), "{bad:?} should be rejected");
        }
    }

    #[test]
    fn tools_are_filtered_by_scope() {
        let h = host(PluginsConfig {
            tools: vec![
                PluginToolConfig {
                    name: "everywhere".into(),
                    description: "d".into(),
                    module: "a.wasm".into(),
                    parameters: None,
                    scopes: vec![],
                },
                PluginToolConfig {
                    name: "eng_only".into(),
                    description: "d".into(),
                    module: "b.wasm".into(),
                    parameters: None,
                    scopes: vec!["channel:eng".into()],
                },
            ],
            ..PluginsConfig::default()
        });

        let personal = h.tools(&ScopeId::personal("u1"));
        assert_eq!(personal.len(), 1);
        assert_eq!(personal[0].name, "everywhere");

        let eng = h.tools(&ScopeId::channel("eng"));
        assert_eq!(eng.len(), 2);
    }

    #[test]
    fn a_tool_without_a_schema_gets_an_empty_object_schema() {
        let h = host(PluginsConfig {
            tools: vec![PluginToolConfig {
                name: "t".into(),
                description: "d".into(),
                module: "a.wasm".into(),
                parameters: None,
                scopes: vec![],
            }],
            ..PluginsConfig::default()
        });
        assert_eq!(
            h.tools(&ScopeId::personal("u1"))[0].parameters["type"],
            "object"
        );
    }

    #[test]
    fn a_malformed_parameter_schema_is_refused_at_construction() {
        let result = WasmHost::new(&PluginsConfig {
            tools: vec![PluginToolConfig {
                name: "t".into(),
                description: "d".into(),
                module: "a.wasm".into(),
                parameters: Some("{not json".into()),
                scopes: vec![],
            }],
            ..PluginsConfig::default()
        });
        assert!(result.is_err());
    }

    #[test]
    fn a_missing_module_is_reported_rather_than_failing_the_host() {
        let h = host(PluginsConfig {
            dir: PathBuf::from("/nonexistent/plugin/dir"),
            turn_middleware: vec!["absent.wasm".into()],
            ..PluginsConfig::default()
        });
        assert!(h.describe().iter().any(|d| d.contains("MISSING")));
        let response = h.call(
            "absent.wasm",
            &PluginRequest {
                hook: "turn.before".into(),
                scope: "personal:u1".into(),
                actor: "u1".into(),
                session_id: None,
                payload: serde_json::json!({}),
            },
        );
        assert!(!response.ok);
        assert!(response.error.unwrap().contains("absent.wasm"));
    }
}
