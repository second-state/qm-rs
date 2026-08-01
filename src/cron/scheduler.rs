//! The cron scheduler loop.
//!
//! Wakes on a tick, claims every due fire, and runs each as an automation turn
//! in the cron's own thread. Claiming is what makes this safe to restart: the
//! unique index on `(cron_id, fire_key)` means a scheduled instant runs once,
//! even if the process dies mid-fire and comes back.

use std::sync::Arc;

use chrono::{DateTime, Duration, Utc};
use tokio::time::{interval, Duration as TokioDuration};

use crate::config::CronConfig;
use crate::error::AppResult;
use crate::orchestrator::Orchestrator;
use crate::store::crons::Cron;
use crate::types::{SessionType, TurnOrigin, TurnRequest, TurnStatus};

pub struct Scheduler {
    pub orchestrator: Arc<Orchestrator>,
    pub config: CronConfig,
}

impl Scheduler {
    pub fn new(orchestrator: Arc<Orchestrator>, config: CronConfig) -> Self {
        Self {
            orchestrator,
            config,
        }
    }

    /// Run forever. Spawned by `main` when `[cron].enabled` is true.
    pub async fn run(self) {
        let mut ticker = interval(TokioDuration::from_secs(self.config.tick_seconds.max(1)));
        tracing::info!(
            tick_seconds = self.config.tick_seconds,
            "cron scheduler started"
        );
        loop {
            ticker.tick().await;
            if let Err(e) = self.tick(Utc::now()).await {
                // A failing tick must not kill the loop; the next one retries.
                tracing::error!(error = %e, "cron tick failed");
            }
        }
    }

    /// One pass over the due crons. Returns how many fired.
    pub async fn tick(&self, now: DateTime<Utc>) -> AppResult<usize> {
        let due = self.orchestrator.stores.crons.due(now)?;
        let mut fired = 0;
        for cron in due {
            if self.run_one(&cron, now).await? {
                fired += 1;
            }
        }
        Ok(fired)
    }

    /// Claim and run one cron. `false` means another worker claimed it, or it
    /// was too far behind to be worth running.
    async fn run_one(&self, cron: &Cron, now: DateTime<Utc>) -> AppResult<bool> {
        let scheduled_at = cron.next_fire_at.unwrap_or(now);
        let Some(fire_id) = self
            .orchestrator
            .stores
            .crons
            .claim_fire(cron, scheduled_at)?
        else {
            // Someone else has this instant.
            return Ok(false);
        };

        // A restart after a long outage must not stampede: a fire that is
        // further behind than the catch-up window is skipped, and the schedule
        // still advances.
        let behind = now.signed_duration_since(scheduled_at);
        if behind > Duration::seconds(self.config.max_catchup_secs.max(0)) {
            let note = format!(
                "skipped: {}s behind schedule, past the {}s catch-up window",
                behind.num_seconds(),
                self.config.max_catchup_secs
            );
            tracing::warn!(cron = %cron.id, "{note}");
            self.orchestrator
                .stores
                .crons
                .skip_fire(&fire_id, cron, now, &note)?;
            return Ok(false);
        }

        let request = TurnRequest::new(
            "cron",
            &cron.owner,
            cron.owner_scope_id.clone(),
            cron.thread_ref(),
            &cron.message,
        )
        .with_origin(TurnOrigin::Automation)
        .with_session_type(if cron.owner_scope_id.is_shared() {
            SessionType::Channel
        } else {
            SessionType::Dm
        });

        let (status, reply, session_id) = match self.orchestrator.handle_turn(request).await {
            Ok(result) => {
                let status = match result.status {
                    TurnStatus::Ok => "ok",
                    TurnStatus::Silent => "silent",
                    TurnStatus::Refused => "refused",
                    TurnStatus::PendingApproval => "pending_approval",
                    TurnStatus::Failed => "failed",
                };
                let reply = if result.reply.is_empty() {
                    result.reason.unwrap_or_default()
                } else {
                    result.reply
                };
                (status.to_string(), reply, Some(result.session_id))
            }
            Err(e) => {
                tracing::error!(error = %e, cron = %cron.id, "cron turn failed");
                ("failed".to_string(), e.to_string(), None)
            }
        };

        // The schedule advances whatever the outcome: a cron that fails must
        // still run tomorrow.
        let next = self.orchestrator.stores.crons.complete_fire(
            &fire_id,
            cron,
            now,
            &status,
            Some(&reply),
            session_id.as_deref(),
        )?;

        self.orchestrator.stores.audit.record(
            &cron.owner,
            "cron.fire",
            Some(&cron.owner_scope_id),
            Some(&cron.id),
            Some(serde_json::json!({ "status": status, "next": next.map(|t| t.to_rfc3339()) })),
            status == "ok" || status == "silent",
        );

        // Queue the reply for delivery when the cron has somewhere to send it.
        if let Some(destination) = &cron.destination {
            if !reply.trim().is_empty() {
                let key = format!("cron:{}:{}", cron.id, scheduled_at.to_rfc3339());
                self.orchestrator
                    .stores
                    .deliveries
                    .enqueue(destination, &reply, &key)?;
            }
        }

        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use crate::cron::schedule::CronSchedule;
    use crate::db::test_pool;
    use crate::harness::mock::MockHarness;
    use crate::plugin::native::NativeHost;
    use crate::sandbox::LocalSandbox;
    use crate::store::crons::NewCron;
    use crate::store::Stores;
    use crate::types::ScopeId;

    struct Fixture {
        scheduler: Scheduler,
        orchestrator: Arc<Orchestrator>,
        _dir: tempfile::TempDir,
    }

    fn fixture(cron_config: CronConfig) -> Fixture {
        let dir = tempfile::tempdir().unwrap();
        let (events, _) = tokio::sync::broadcast::channel(64);
        let orchestrator = Arc::new(Orchestrator {
            config: Arc::new(Config::default()),
            stores: Stores::new(test_pool()).unwrap(),
            sandbox: Arc::new(LocalSandbox::new(dir.path().to_path_buf(), 10, 32_000)),
            harness: Arc::new(MockHarness::new()),
            plugins: Arc::new(NativeHost::new(&crate::config::PluginsConfig::default())),
            events,
        });
        Fixture {
            scheduler: Scheduler::new(orchestrator.clone(), cron_config),
            orchestrator,
            _dir: dir,
        }
    }

    fn utc(s: &str) -> DateTime<Utc> {
        DateTime::parse_from_rfc3339(s).unwrap().with_timezone(&Utc)
    }

    fn make_cron(f: &Fixture, message: &str, created_at: DateTime<Utc>) -> Cron {
        f.orchestrator
            .stores
            .crons
            .create(
                NewCron {
                    owner_scope_id: ScopeId::personal("u1"),
                    owner: "u1".into(),
                    created_by: "u1".into(),
                    title: None,
                    message: message.into(),
                    schedule: CronSchedule::calendar("0 9 * * *", "UTC"),
                    destination: None,
                    run_as: "owner".into(),
                },
                created_at,
            )
            .unwrap()
    }

    #[tokio::test]
    async fn a_due_cron_fires_and_records_its_reply() {
        let f = fixture(CronConfig::default());
        let cron = make_cron(&f, "check the deploy", utc("2026-08-01T10:00:00Z"));

        let fired = f.scheduler.tick(utc("2026-08-02T09:00:05Z")).await.unwrap();
        assert_eq!(fired, 1);

        let fires = f.orchestrator.stores.crons.fires(&cron.id, 10).unwrap();
        assert_eq!(fires.len(), 1);
        assert_eq!(fires[0].status.as_deref(), Some("ok"));
        assert!(fires[0]
            .reply
            .as_deref()
            .unwrap()
            .contains("check the deploy"));
        assert!(fires[0].session_id.is_some());
    }

    #[tokio::test]
    async fn a_cron_runs_once_per_instant_however_often_the_tick_runs() {
        let f = fixture(CronConfig::default());
        let cron = make_cron(&f, "hourly", utc("2026-08-01T10:00:00Z"));

        let at = utc("2026-08-02T09:00:05Z");
        assert_eq!(f.scheduler.tick(at).await.unwrap(), 1);
        // Ticking again at the same instant finds the schedule already advanced.
        assert_eq!(f.scheduler.tick(at).await.unwrap(), 0);
        assert_eq!(
            f.orchestrator
                .stores
                .crons
                .fires(&cron.id, 10)
                .unwrap()
                .len(),
            1
        );
    }

    #[tokio::test]
    async fn the_schedule_advances_after_a_fire() {
        let f = fixture(CronConfig::default());
        let cron = make_cron(&f, "daily", utc("2026-08-01T10:00:00Z"));
        f.scheduler.tick(utc("2026-08-02T09:00:05Z")).await.unwrap();

        let reloaded = f.orchestrator.stores.crons.require(&cron.id).unwrap();
        assert_eq!(reloaded.next_fire_at, Some(utc("2026-08-03T09:00:00Z")));
        assert!(reloaded.last_fired_at.is_some());
    }

    #[tokio::test]
    async fn a_fire_far_past_its_time_is_skipped_rather_than_stampeding() {
        let f = fixture(CronConfig {
            max_catchup_secs: 600,
            ..CronConfig::default()
        });
        let cron = make_cron(&f, "daily", utc("2026-08-01T10:00:00Z"));

        // Come back a week late.
        let fired = f.scheduler.tick(utc("2026-08-09T12:00:00Z")).await.unwrap();
        assert_eq!(fired, 0);

        let fires = f.orchestrator.stores.crons.fires(&cron.id, 10).unwrap();
        assert_eq!(fires[0].status.as_deref(), Some("skipped"));
        assert!(fires[0]
            .note
            .as_deref()
            .unwrap()
            .contains("catch-up window"));

        // The schedule still moved forward, so it will run normally next time.
        let reloaded = f.orchestrator.stores.crons.require(&cron.id).unwrap();
        assert_eq!(reloaded.next_fire_at, Some(utc("2026-08-10T09:00:00Z")));
        assert!(reloaded.last_fired_at.is_none(), "a skip is not a run");
    }

    #[tokio::test]
    async fn a_disabled_cron_does_not_fire() {
        let f = fixture(CronConfig::default());
        let cron = make_cron(&f, "daily", utc("2026-08-01T10:00:00Z"));
        f.orchestrator
            .stores
            .crons
            .set_enabled(&cron.id, false, utc("2026-08-01T10:00:00Z"))
            .unwrap();
        assert_eq!(
            f.scheduler.tick(utc("2026-08-02T09:00:05Z")).await.unwrap(),
            0
        );
    }

    #[tokio::test]
    async fn every_fire_of_one_cron_shares_a_thread() {
        let f = fixture(CronConfig::default());
        let cron = make_cron(&f, "daily", utc("2026-08-01T10:00:00Z"));
        f.scheduler.tick(utc("2026-08-02T09:00:05Z")).await.unwrap();
        f.scheduler.tick(utc("2026-08-03T09:00:05Z")).await.unwrap();

        let fires = f.orchestrator.stores.crons.fires(&cron.id, 10).unwrap();
        assert_eq!(fires.len(), 2);
        let sessions: std::collections::HashSet<Option<String>> =
            fires.iter().map(|f| f.session_id.clone()).collect();
        assert_eq!(
            sessions.len(),
            1,
            "the agent must see what it said last time, so fires share one thread"
        );
    }

    #[tokio::test]
    async fn a_paused_cron_records_pending_approval_and_still_advances() {
        let f = fixture(CronConfig::default());
        let cron = f
            .orchestrator
            .stores
            .crons
            .create(
                NewCron {
                    owner_scope_id: ScopeId::personal("u1"),
                    owner: "u1".into(),
                    created_by: "u1".into(),
                    title: None,
                    message: "!exec rm -rf /tmp/nightly".into(),
                    schedule: CronSchedule::calendar("0 9 * * *", "UTC"),
                    destination: None,
                    run_as: "owner".into(),
                },
                utc("2026-08-01T10:00:00Z"),
            )
            .unwrap();

        f.scheduler.tick(utc("2026-08-02T09:00:05Z")).await.unwrap();
        let fires = f.orchestrator.stores.crons.fires(&cron.id, 10).unwrap();
        assert_eq!(fires[0].status.as_deref(), Some("pending_approval"));
        assert_eq!(
            f.orchestrator
                .stores
                .crons
                .require(&cron.id)
                .unwrap()
                .next_fire_at,
            Some(utc("2026-08-03T09:00:00Z")),
            "an unattended cron waiting on a human must not block its own schedule"
        );
    }

    #[tokio::test]
    async fn a_cron_with_a_destination_queues_its_reply_for_delivery() {
        let f = fixture(CronConfig::default());
        f.orchestrator
            .stores
            .crons
            .create(
                NewCron {
                    owner_scope_id: ScopeId::personal("u1"),
                    owner: "u1".into(),
                    created_by: "u1".into(),
                    title: None,
                    message: "morning summary".into(),
                    schedule: CronSchedule::calendar("0 9 * * *", "UTC"),
                    destination: Some(crate::types::Destination::new("telegram", "12345")),
                    run_as: "owner".into(),
                },
                utc("2026-08-01T10:00:00Z"),
            )
            .unwrap();

        f.scheduler.tick(utc("2026-08-02T09:00:05Z")).await.unwrap();
        let pending = f.orchestrator.stores.deliveries.pending(10).unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].destination.target, "12345");
        assert!(pending[0].text.contains("morning summary"));
    }
}
