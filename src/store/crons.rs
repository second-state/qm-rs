//! Crons and their fire log.

use chrono::{DateTime, Utc};
use rusqlite::{params, Row};

use crate::cron::schedule::{next_fire_after, normalize, CronSchedule};
use crate::db::{new_id, now_rfc3339, DbPool};
use crate::error::{AppError, AppResult};
use crate::types::{Destination, ScopeId};

#[derive(Clone)]
pub struct CronStore {
    pool: DbPool,
}

#[derive(Debug, Clone)]
pub struct Cron {
    pub id: String,
    pub owner_scope_id: ScopeId,
    pub owner: String,
    pub created_by: String,
    pub title: Option<String>,
    pub message: String,
    pub schedule: CronSchedule,
    pub next_fire_at: Option<DateTime<Utc>>,
    pub enabled: bool,
    pub archived: bool,
    pub run_as: String,
    pub destination: Option<Destination>,
    pub created_at: String,
    pub last_fired_at: Option<String>,
}

impl Cron {
    pub fn display_title(&self) -> String {
        match self
            .title
            .as_deref()
            .map(str::trim)
            .filter(|t| !t.is_empty())
        {
            Some(t) => t.to_string(),
            None => {
                let first_line = self.message.lines().next().unwrap_or("").trim();
                if first_line.is_empty() {
                    "untitled cron".to_string()
                } else if first_line.chars().count() > 60 {
                    format!("{}…", first_line.chars().take(60).collect::<String>())
                } else {
                    first_line.to_string()
                }
            }
        }
    }

    /// Thread a fire runs in. Every fire of one cron shares a thread, so the
    /// agent sees what it said last time.
    pub fn thread_ref(&self) -> String {
        format!("cron:{}", self.id)
    }
}

#[derive(Debug, Clone)]
pub struct CronFire {
    pub id: String,
    pub cron_id: String,
    pub fire_key: String,
    pub fired_at: String,
    pub scheduled_at: Option<String>,
    pub status: Option<String>,
    pub note: Option<String>,
    pub reply: Option<String>,
    pub session_id: Option<String>,
}

fn cron_from_row(row: &Row<'_>) -> rusqlite::Result<Cron> {
    let schedule: String = row.get("schedule")?;
    let destination: Option<String> = row.get("destination")?;
    let next: Option<String> = row.get("next_fire_at")?;
    Ok(Cron {
        id: row.get("id")?,
        owner_scope_id: ScopeId::from_raw(row.get::<_, String>("owner_scope_id")?),
        owner: row.get("owner")?,
        created_by: row.get("created_by")?,
        title: row.get("title")?,
        message: row.get("message")?,
        schedule: serde_json::from_str(&schedule).unwrap_or_default(),
        next_fire_at: next.as_deref().and_then(parse_ts),
        enabled: row.get::<_, i64>("enabled")? == 1,
        archived: row.get::<_, i64>("archived")? == 1,
        run_as: row.get("run_as")?,
        destination: destination
            .as_deref()
            .and_then(|d| serde_json::from_str(d).ok()),
        created_at: row.get("created_at")?,
        last_fired_at: row.get("last_fired_at")?,
    })
}

fn fire_from_row(row: &Row<'_>) -> rusqlite::Result<CronFire> {
    Ok(CronFire {
        id: row.get("id")?,
        cron_id: row.get("cron_id")?,
        fire_key: row.get("fire_key")?,
        fired_at: row.get("fired_at")?,
        scheduled_at: row.get("scheduled_at")?,
        status: row.get("status")?,
        note: row.get("note")?,
        reply: row.get("reply")?,
        session_id: row.get("session_id")?,
    })
}

fn parse_ts(raw: &str) -> Option<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(raw)
        .ok()
        .map(|d| d.with_timezone(&Utc))
}

fn format_ts(at: DateTime<Utc>) -> String {
    at.to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

pub struct NewCron {
    pub owner_scope_id: ScopeId,
    pub owner: String,
    pub created_by: String,
    pub title: Option<String>,
    pub message: String,
    pub schedule: CronSchedule,
    pub destination: Option<Destination>,
    pub run_as: String,
}

impl CronStore {
    pub fn new(pool: DbPool) -> Self {
        Self { pool }
    }

    pub fn create(&self, input: NewCron, now: DateTime<Utc>) -> AppResult<Cron> {
        if input.message.trim().is_empty() {
            return Err(AppError::bad_request("a cron needs a message to run"));
        }
        let (schedule, first_fire) = normalize(&input.schedule, now)?;
        let id = new_id();
        let conn = self.pool.get()?;
        conn.execute(
            "INSERT INTO crons
                (id, owner_scope_id, owner, created_by, title, message, schedule,
                 next_fire_at, enabled, archived, run_as, destination, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 1, 0, ?9, ?10, ?11)",
            params![
                id,
                input.owner_scope_id.as_str(),
                input.owner,
                input.created_by,
                input.title,
                input.message,
                serde_json::to_string(&schedule)?,
                format_ts(first_fire),
                input.run_as,
                input
                    .destination
                    .as_ref()
                    .map(serde_json::to_string)
                    .transpose()?,
                now_rfc3339(),
            ],
        )?;
        self.require(&id)
    }

    pub fn get(&self, id: &str) -> AppResult<Option<Cron>> {
        let conn = self.pool.get()?;
        let mut stmt = conn.prepare("SELECT * FROM crons WHERE id = ?1")?;
        let mut rows = stmt.query_map([id], cron_from_row)?;
        Ok(rows.next().transpose()?)
    }

    pub fn require(&self, id: &str) -> AppResult<Cron> {
        self.get(id)?
            .ok_or_else(|| AppError::not_found(format!("cron {id}")))
    }

    pub fn list_for_scopes(
        &self,
        scopes: &[ScopeId],
        include_archived: bool,
    ) -> AppResult<Vec<Cron>> {
        if scopes.is_empty() {
            return Ok(Vec::new());
        }
        let conn = self.pool.get()?;
        let placeholders = vec!["?"; scopes.len()].join(",");
        let sql = format!(
            "SELECT * FROM crons WHERE owner_scope_id IN ({placeholders}) {}
             ORDER BY enabled DESC, next_fire_at",
            if include_archived {
                ""
            } else {
                "AND archived = 0"
            }
        );
        let mut stmt = conn.prepare(&sql)?;
        let owned: Vec<String> = scopes.iter().map(|s| s.as_str().to_string()).collect();
        let args: Vec<&dyn rusqlite::ToSql> =
            owned.iter().map(|s| s as &dyn rusqlite::ToSql).collect();
        let rows = stmt.query_map(args.as_slice(), cron_from_row)?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    /// Enabled, unarchived crons whose next fire has arrived.
    pub fn due(&self, now: DateTime<Utc>) -> AppResult<Vec<Cron>> {
        let conn = self.pool.get()?;
        let mut stmt = conn.prepare(
            "SELECT * FROM crons
             WHERE enabled = 1 AND archived = 0
               AND next_fire_at IS NOT NULL AND next_fire_at <= ?1
             ORDER BY next_fire_at",
        )?;
        let rows = stmt.query_map([format_ts(now)], cron_from_row)?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    /// Claim a due fire exactly once.
    ///
    /// The unique index on `(cron_id, fire_key)` is the guard: a second
    /// scheduler tick — or a restart mid-fire — inserts nothing and gets
    /// `false`, so the cron never runs twice for the same scheduled instant.
    pub fn claim_fire(
        &self,
        cron: &Cron,
        scheduled_at: DateTime<Utc>,
    ) -> AppResult<Option<String>> {
        let fire_key = format_ts(scheduled_at);
        let id = new_id();
        let conn = self.pool.get()?;
        let inserted = conn.execute(
            "INSERT INTO cron_fires (id, cron_id, fire_key, thread_ref, fired_at, scheduled_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?3)
             ON CONFLICT(cron_id, fire_key) DO NOTHING",
            params![id, cron.id, fire_key, cron.thread_ref(), now_rfc3339()],
        )?;
        Ok((inserted > 0).then_some(id))
    }

    /// Record the outcome and schedule the next fire.
    pub fn complete_fire(
        &self,
        fire_id: &str,
        cron: &Cron,
        now: DateTime<Utc>,
        status: &str,
        reply: Option<&str>,
        session_id: Option<&str>,
    ) -> AppResult<Option<DateTime<Utc>>> {
        let next = next_fire_after(&cron.schedule, now)?;
        let mut conn = self.pool.get()?;
        let tx = conn.transaction()?;
        tx.execute(
            "UPDATE cron_fires SET status = ?2, reply = ?3, session_id = ?4 WHERE id = ?1",
            params![fire_id, status, reply, session_id],
        )?;
        tx.execute(
            "UPDATE crons SET next_fire_at = ?2, last_fired_at = ?3 WHERE id = ?1",
            params![cron.id, next.map(format_ts), now_rfc3339()],
        )?;
        tx.commit()?;
        Ok(next)
    }

    /// Note that a fire was skipped, still advancing the schedule.
    pub fn skip_fire(
        &self,
        fire_id: &str,
        cron: &Cron,
        now: DateTime<Utc>,
        note: &str,
    ) -> AppResult<Option<DateTime<Utc>>> {
        let next = next_fire_after(&cron.schedule, now)?;
        let mut conn = self.pool.get()?;
        let tx = conn.transaction()?;
        tx.execute(
            "UPDATE cron_fires SET status = 'skipped', note = ?2 WHERE id = ?1",
            params![fire_id, note],
        )?;
        tx.execute(
            "UPDATE crons SET next_fire_at = ?2 WHERE id = ?1",
            params![cron.id, next.map(format_ts)],
        )?;
        tx.commit()?;
        Ok(next)
    }

    pub fn fires(&self, cron_id: &str, limit: usize) -> AppResult<Vec<CronFire>> {
        let conn = self.pool.get()?;
        let mut stmt = conn.prepare(
            "SELECT * FROM cron_fires WHERE cron_id = ?1 ORDER BY fired_at DESC, rowid DESC LIMIT ?2",
        )?;
        let rows = stmt.query_map(params![cron_id, limit as i64], fire_from_row)?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    pub fn set_enabled(&self, id: &str, enabled: bool, now: DateTime<Utc>) -> AppResult<()> {
        let cron = self.require(id)?;
        // Re-arm from now so a long-disabled cron does not fire immediately
        // for every instant it missed.
        let next = if enabled {
            next_fire_after(&cron.schedule, now)?
        } else {
            cron.next_fire_at
        };
        let conn = self.pool.get()?;
        conn.execute(
            "UPDATE crons SET enabled = ?2, next_fire_at = ?3 WHERE id = ?1",
            params![id, i64::from(enabled), next.map(format_ts)],
        )?;
        Ok(())
    }

    pub fn set_archived(&self, id: &str, archived: bool) -> AppResult<()> {
        let conn = self.pool.get()?;
        conn.execute(
            "UPDATE crons SET archived = ?2 WHERE id = ?1",
            params![id, i64::from(archived)],
        )?;
        Ok(())
    }

    pub fn delete(&self, id: &str) -> AppResult<bool> {
        let conn = self.pool.get()?;
        Ok(conn.execute("DELETE FROM crons WHERE id = ?1", [id])? > 0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::test_pool;

    fn store() -> CronStore {
        CronStore::new(test_pool())
    }

    fn utc(s: &str) -> DateTime<Utc> {
        DateTime::parse_from_rfc3339(s).unwrap().with_timezone(&Utc)
    }

    fn new_cron(message: &str, schedule: CronSchedule) -> NewCron {
        NewCron {
            owner_scope_id: ScopeId::personal("u1"),
            owner: "u1".into(),
            created_by: "u1".into(),
            title: None,
            message: message.into(),
            schedule,
            destination: None,
            run_as: "owner".into(),
        }
    }

    #[test]
    fn creating_a_cron_computes_its_first_fire() {
        let s = store();
        let now = utc("2026-08-01T10:00:00Z");
        let cron = s
            .create(
                new_cron(
                    "check the deploy",
                    CronSchedule::calendar("0 9 * * *", "UTC"),
                ),
                now,
            )
            .unwrap();
        assert_eq!(cron.next_fire_at, Some(utc("2026-08-02T09:00:00Z")));
        assert!(cron.enabled);
        assert!(!cron.archived);
        assert_eq!(cron.thread_ref(), format!("cron:{}", cron.id));
    }

    #[test]
    fn an_empty_message_or_bad_schedule_is_refused() {
        let s = store();
        let now = utc("2026-08-01T10:00:00Z");
        assert!(s
            .create(new_cron("  ", CronSchedule::every(60)), now)
            .is_err());
        assert!(s
            .create(
                new_cron("x", CronSchedule::calendar("nonsense", "UTC")),
                now
            )
            .is_err());
        assert!(s
            .create(new_cron("x", CronSchedule::default()), now)
            .is_err());
    }

    #[test]
    fn due_returns_only_arrived_enabled_unarchived_crons() {
        let s = store();
        let now = utc("2026-08-01T10:00:00Z");
        let cron = s
            .create(
                new_cron("x", CronSchedule::calendar("0 9 * * *", "UTC")),
                now,
            )
            .unwrap();

        assert!(s.due(now).unwrap().is_empty(), "not due yet");
        assert_eq!(s.due(utc("2026-08-02T09:00:00Z")).unwrap().len(), 1);

        s.set_enabled(&cron.id, false, now).unwrap();
        assert!(s.due(utc("2026-08-02T09:00:00Z")).unwrap().is_empty());

        s.set_enabled(&cron.id, true, utc("2026-08-02T09:00:00Z"))
            .unwrap();
        s.set_archived(&cron.id, true).unwrap();
        assert!(s.due(utc("2026-08-03T09:00:00Z")).unwrap().is_empty());
    }

    #[test]
    fn a_scheduled_instant_can_only_be_claimed_once() {
        let s = store();
        let now = utc("2026-08-01T10:00:00Z");
        let cron = s
            .create(
                new_cron("x", CronSchedule::calendar("0 9 * * *", "UTC")),
                now,
            )
            .unwrap();
        let scheduled = utc("2026-08-02T09:00:00Z");

        let first = s.claim_fire(&cron, scheduled).unwrap();
        assert!(first.is_some());
        assert!(
            s.claim_fire(&cron, scheduled).unwrap().is_none(),
            "a second tick must not re-fire the same instant"
        );
        // A different instant is a different claim.
        assert!(s
            .claim_fire(&cron, utc("2026-08-03T09:00:00Z"))
            .unwrap()
            .is_some());
        assert_eq!(s.fires(&cron.id, 10).unwrap().len(), 2);
    }

    #[test]
    fn completing_a_fire_records_the_outcome_and_arms_the_next() {
        let s = store();
        let now = utc("2026-08-01T10:00:00Z");
        let cron = s
            .create(
                new_cron("x", CronSchedule::calendar("0 9 * * *", "UTC")),
                now,
            )
            .unwrap();
        let fired_at = utc("2026-08-02T09:00:00Z");
        let fire_id = s.claim_fire(&cron, fired_at).unwrap().unwrap();

        let next = s
            .complete_fire(
                &fire_id,
                &cron,
                fired_at,
                "ok",
                Some("all green"),
                Some("s1"),
            )
            .unwrap();
        assert_eq!(next, Some(utc("2026-08-03T09:00:00Z")));

        let reloaded = s.require(&cron.id).unwrap();
        assert_eq!(reloaded.next_fire_at, next);
        assert!(reloaded.last_fired_at.is_some());

        let fires = s.fires(&cron.id, 10).unwrap();
        assert_eq!(fires[0].status.as_deref(), Some("ok"));
        assert_eq!(fires[0].reply.as_deref(), Some("all green"));
        assert_eq!(fires[0].session_id.as_deref(), Some("s1"));
    }

    #[test]
    fn skipping_a_fire_still_advances_the_schedule() {
        let s = store();
        let now = utc("2026-08-01T10:00:00Z");
        let cron = s
            .create(
                new_cron("x", CronSchedule::calendar("0 9 * * *", "UTC")),
                now,
            )
            .unwrap();
        let fired_at = utc("2026-08-02T09:00:00Z");
        let fire_id = s.claim_fire(&cron, fired_at).unwrap().unwrap();

        let next = s
            .skip_fire(&fire_id, &cron, fired_at, "too far behind")
            .unwrap();
        assert_eq!(next, Some(utc("2026-08-03T09:00:00Z")));
        assert_eq!(
            s.fires(&cron.id, 1).unwrap()[0].status.as_deref(),
            Some("skipped")
        );
        assert!(
            s.require(&cron.id).unwrap().last_fired_at.is_none(),
            "a skip is not a run"
        );
    }

    #[test]
    fn re_enabling_re_arms_from_now_rather_than_the_stale_instant() {
        let s = store();
        let created = utc("2026-08-01T10:00:00Z");
        let cron = s
            .create(
                new_cron("x", CronSchedule::calendar("0 9 * * *", "UTC")),
                created,
            )
            .unwrap();
        s.set_enabled(&cron.id, false, created).unwrap();

        // Come back a month later.
        let later = utc("2026-09-01T12:00:00Z");
        s.set_enabled(&cron.id, true, later).unwrap();
        assert_eq!(
            s.require(&cron.id).unwrap().next_fire_at,
            Some(utc("2026-09-02T09:00:00Z")),
            "a re-enabled cron must not fire for every instant it missed"
        );
    }

    #[test]
    fn listing_is_scoped_and_hides_archived_by_default() {
        let s = store();
        let now = utc("2026-08-01T10:00:00Z");
        let cron = s
            .create(new_cron("x", CronSchedule::every(3600)), now)
            .unwrap();
        assert_eq!(
            s.list_for_scopes(&[ScopeId::personal("u1")], false)
                .unwrap()
                .len(),
            1
        );
        assert!(s
            .list_for_scopes(&[ScopeId::channel("eng")], false)
            .unwrap()
            .is_empty());

        s.set_archived(&cron.id, true).unwrap();
        assert!(s
            .list_for_scopes(&[ScopeId::personal("u1")], false)
            .unwrap()
            .is_empty());
        assert_eq!(
            s.list_for_scopes(&[ScopeId::personal("u1")], true)
                .unwrap()
                .len(),
            1
        );
    }

    #[test]
    fn titles_fall_back_to_the_first_line_of_the_message() {
        let s = store();
        let now = utc("2026-08-01T10:00:00Z");
        let cron = s
            .create(
                new_cron("Check CI\nand report", CronSchedule::every(3600)),
                now,
            )
            .unwrap();
        assert_eq!(cron.display_title(), "Check CI");

        let long = "x".repeat(100);
        let cron2 = s
            .create(
                NewCron {
                    message: long,
                    ..new_cron("ignored", CronSchedule::every(3600))
                },
                now,
            )
            .unwrap();
        assert!(cron2.display_title().ends_with('…'));
        assert_eq!(cron2.display_title().chars().count(), 61);
    }

    #[test]
    fn deleting_a_cron_removes_its_fires() {
        let s = store();
        let now = utc("2026-08-01T10:00:00Z");
        let cron = s
            .create(new_cron("x", CronSchedule::every(3600)), now)
            .unwrap();
        s.claim_fire(&cron, now).unwrap();
        assert!(s.delete(&cron.id).unwrap());
        assert!(
            s.fires(&cron.id, 10).unwrap().is_empty(),
            "cascade must clean up"
        );
        assert!(!s.delete(&cron.id).unwrap());
    }
}
