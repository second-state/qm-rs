//! Example qm-rs plugin: a **custom agent tool**.
//!
//! This is the shape most deployments want first — the agent gains a verb that
//! reaches into something only your organization has. Here it is a service
//! registry: ask who owns a service and you get the team, the runbook and who
//! is on call.
//!
//! A real one would query your internal API. This one answers from a table
//! compiled into the module, which keeps the example deterministic and makes
//! the point that the module is a pure function over bytes — it gets the
//! model's arguments and returns text, and cannot reach the host's filesystem,
//! network or database except through what you build into it.
//!
//! Build and install:
//!
//! ```bash
//! cargo build --release --target wasm32-wasip1
//! cp target/wasm32-wasip1/release/service_registry.wasm ../
//! ```
//!
//! Then in `config.toml`:
//!
//! ```toml
//! [plugins]
//! dir = "plugins/modules"
//!
//! [[plugins.tools]]
//! name = "lookup_service"
//! description = "Look up who owns a service, its runbook, and who is on call."
//! module = "service_registry.wasm"
//! parameters = '{"type":"object","properties":{"service":{"type":"string"}},"required":["service"]}'
//! ```
//!
//! The server must be built with `--features wasm`; without it the module is
//! reported as inert on the admin page rather than silently ignored.

use qm_plugin_sdk::{PluginRequest, PluginResponse};

qm_plugin_sdk::handler!(process);

/// name, owning team, runbook, on-call rotation
const REGISTRY: &[(&str, &str, &str, &str)] = &[
    (
        "billing",
        "Payments",
        "https://runbooks.internal/billing",
        "payments-oncall",
    ),
    (
        "checkout",
        "Storefront",
        "https://runbooks.internal/checkout",
        "storefront-oncall",
    ),
    (
        "search",
        "Discovery",
        "https://runbooks.internal/search",
        "discovery-oncall",
    ),
    (
        "notifications",
        "Platform",
        "https://runbooks.internal/notifications",
        "platform-oncall",
    ),
];

fn process(request: PluginRequest) -> PluginResponse {
    if request.tool_name() != Some("lookup_service") {
        return PluginResponse::failure(format!(
            "service_registry does not handle {}",
            request.hook
        ));
    }

    let Some(query) = request.arg("service") else {
        return PluginResponse::failure("`service` is required");
    };
    let needle = query.trim().to_lowercase();

    // Exact match first, then a contains match, so "the billing service"
    // resolves as readily as "billing".
    let found = REGISTRY
        .iter()
        .find(|(name, ..)| *name == needle)
        .or_else(|| REGISTRY.iter().find(|(name, ..)| needle.contains(name)));

    match found {
        Some((name, team, runbook, oncall)) => PluginResponse::output(format!(
            "{name}\n  owner:   {team}\n  runbook: {runbook}\n  on call: @{oncall}"
        )),
        // Listing what does exist turns a miss into something the model can act
        // on, rather than a dead end it will retry.
        None => PluginResponse::output(format!(
            "No service named {query:?} is registered. Known services: {}.",
            REGISTRY
                .iter()
                .map(|(name, ..)| *name)
                .collect::<Vec<_>>()
                .join(", ")
        )),
    }
}
