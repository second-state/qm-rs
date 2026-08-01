//! qm-rs — boot: load config, migrate, wire the substrates, start the surfaces.

use std::sync::Arc;

use qm_rs::auth::email::Mailer;
use qm_rs::config::Config;
use qm_rs::connectors::{SlackClient, TelegramConnector};
use qm_rs::cron::scheduler::Scheduler;
use qm_rs::harness::{mock::MockHarness, openai::OpenAiHarness, Harness};
use qm_rs::orchestrator::Orchestrator;
use qm_rs::plugin;
use qm_rs::sandbox::{LocalSandbox, Sandbox};
use qm_rs::store::Stores;
use qm_rs::types::{PrincipalKind, ScopeId};
use qm_rs::{db, web};

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            std::env::var("RUST_LOG").unwrap_or_else(|_| "qm_rs=info,tower_http=warn".into()),
        )
        .init();

    let config = Arc::new(Config::load());

    let pool = db::init_pool(&config.database.path).expect("open the database");
    db::run_migrations(&pool).expect("run migrations");
    let stores = Stores::new(pool).expect("build stores");

    // The configured admin is a real principal from the first boot, so the org
    // scope resolves without a special case.
    //
    // `[auth].admin_email` is attached here on purpose: sign-in resolves an
    // address to a principal by email, so without it the admin's first sign-in
    // would mint a *second* principal (`ada-2`) and the configured admin could
    // never actually be the admin.
    stores
        .directory
        .upsert_principal(
            &config.org.admin,
            PrincipalKind::Internal,
            None,
            config.auth.admin_email.as_deref(),
        )
        .expect("register the admin principal");

    let harness = build_harness(&config);
    tracing::info!(harness = harness.name(), "harness ready");

    let plugins = plugin::build_host(&config.plugins).expect("build the plugin host");
    for line in plugins.describe() {
        tracing::info!(plugin = %line, "plugin");
    }

    let sandbox: Arc<dyn Sandbox> = Arc::new(LocalSandbox::new(
        config.sandbox.root_dir.clone(),
        config.sandbox.exec_timeout_secs,
        config.sandbox.max_output_bytes,
    ));
    std::fs::create_dir_all(&config.sandbox.root_dir).expect("create the sandbox root");

    let (events, _) = tokio::sync::broadcast::channel(1024);
    let orchestrator = Arc::new(Orchestrator {
        config: config.clone(),
        stores: stores.clone(),
        sandbox,
        harness,
        plugins: Arc::from(plugins),
        events,
    });

    if config.cron.enabled {
        let scheduler = Scheduler::new(orchestrator.clone(), config.cron.clone());
        tokio::spawn(scheduler.run());
    } else {
        tracing::info!("cron scheduler disabled by config");
    }

    if config.telegram.enabled {
        match TelegramConnector::new(config.telegram.clone(), orchestrator.clone()) {
            Ok(connector) => {
                tokio::spawn(connector.run());
            }
            // A misconfigured connector must not stop the server: the web UI
            // is how an operator would fix it.
            Err(e) => tracing::error!(error = %e, "telegram connector not started"),
        }
    }

    // Slack. Socket Mode runs as a background task; Events API mode instead
    // hands the client to the router, which serves the signed webhook.
    let mut slack_for_router = None;
    if config.slack.enabled {
        match SlackClient::new(config.slack.clone(), orchestrator.clone()) {
            Ok(client) => {
                if config.slack.uses_socket_mode() {
                    tokio::spawn(client.run_socket_mode());
                    tracing::info!("slack connector starting in socket mode");
                } else {
                    let mut client = client;
                    match client.authenticate().await {
                        Ok(()) => {
                            tracing::info!("slack connector ready on POST /slack/events");
                            slack_for_router = Some(Arc::new(client));
                        }
                        Err(e) => tracing::error!(error = %e, "slack events mode not started"),
                    }
                }
            }
            Err(e) => tracing::error!(error = %e, "slack connector not started"),
        }
    }

    let mailer = Arc::new(Mailer::new(config.auth.clone()).expect("build the mailer"));
    tracing::info!(email = %mailer.describe(), "sign-in");
    if config.auth.admin_email.is_none()
        && config.auth.allowed_emails.is_empty()
        && config.auth.allowed_domains.is_empty()
    {
        tracing::warn!(
            "no [auth].admin_email, allowed_emails or allowed_domains configured — nobody \
             can sign in to the web UI. Set at least [auth].admin_email."
        );
    }

    // Bootstrap key, so a fresh install can be driven by script before anyone
    // has signed in. Adopted once, only while no key exists.
    if let Some(key) = config.auth.resolve_bootstrap_key() {
        match stores.auth.any_api_key_exists() {
            Ok(false) => match stores
                .auth
                .adopt_api_key(&key, &config.org.admin, "bootstrap")
            {
                Ok(()) => tracing::warn!(
                    principal = %config.org.admin,
                    "adopted a bootstrap API key from configuration — revoke it once real \
                     keys exist"
                ),
                Err(e) => tracing::error!(error = %e, "could not adopt the bootstrap API key"),
            },
            Ok(true) => tracing::info!("API keys already exist; ignoring the bootstrap key"),
            Err(e) => tracing::error!(error = %e, "could not check for existing API keys"),
        }
    }

    // Expired sessions and spent login links are swept hourly; Slack dedupe
    // rows outlive any retry window by a wide margin at a day.
    {
        let stores = stores.clone();
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(std::time::Duration::from_secs(3600));
            loop {
                ticker.tick().await;
                if let Err(e) = stores.auth.sweep_expired() {
                    tracing::warn!(error = %e, "could not sweep expired credentials");
                }
                if let Err(e) = stores.slack_dedupe.sweep(86_400) {
                    tracing::warn!(error = %e, "could not sweep slack dedupe rows");
                }
            }
        });
    }

    let templates = Arc::new(web::build_templates("templates/**/*").expect("load templates"));
    let state = web::AppState {
        orchestrator,
        templates,
        config: config.clone(),
        stores,
        mailer,
        slack: slack_for_router,
    };

    let app = web::router(state).layer(tower_http::trace::TraceLayer::new_for_http());
    let addr = format!("{}:{}", config.server.host, config.server.port);
    let listener = tokio::net::TcpListener::bind(&addr)
        .await
        .unwrap_or_else(|e| panic!("could not bind {addr}: {e}"));

    tracing::info!(
        "qm listening on http://{addr} — org {} ({}), scope {}",
        config.org.name,
        config.org.security_posture,
        ScopeId::org(&config.org.id)
    );
    if config.server.host != "127.0.0.1"
        && config.server.host != "localhost"
        && config.auth.public_url.starts_with("http://")
    {
        tracing::warn!(
            "bound to {} but [auth].public_url is plain HTTP — sign-in links and session \
             cookies will travel unencrypted. Terminate TLS and set an https:// public_url.",
            config.server.host
        );
    }

    axum::serve(listener, app).await.expect("serve");
}

/// Pick the harness. An unrecognised `kind`, or a misconfigured OpenAI
/// harness, falls back to the mock with a loud warning rather than refusing to
/// boot: a running server with an inert model is diagnosable from the admin
/// page, whereas a crash loop is not.
fn build_harness(config: &Config) -> Arc<dyn Harness> {
    match config.harness.kind.trim().to_lowercase().as_str() {
        "mock" => Arc::new(MockHarness::new()),
        "openai" | "openai-compatible" | "gateway" => match OpenAiHarness::new(&config.harness) {
            Ok(harness) => Arc::new(harness),
            Err(e) => {
                tracing::error!(error = %e, "falling back to the mock harness");
                Arc::new(MockHarness::new())
            }
        },
        other => {
            tracing::error!(
                kind = other,
                "unknown [harness].kind — expected `mock` or `openai`; falling back to the mock"
            );
            Arc::new(MockHarness::new())
        }
    }
}
