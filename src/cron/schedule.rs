//! Cron schedules: a 5-field expression in an IANA timezone, or a fixed
//! interval. Ported from QM's `src/cron/schedule.ts`, which delegates to
//! `croner` in 5-part mode.

use chrono::{DateTime, Datelike, Duration, NaiveDate, NaiveDateTime, TimeZone, Timelike, Utc};
use chrono_tz::Tz;
use serde::{Deserialize, Serialize};

use crate::error::{AppError, AppResult};

pub const DEFAULT_TIMEZONE: &str = "UTC";
/// A recurring interval below this would fire faster than the scheduler ticks.
pub const MIN_INTERVAL_SECS: i64 = 60;
/// How far ahead the search gives up. Four years covers every Feb-29 rule.
const MAX_SEARCH_DAYS: i64 = 366 * 4;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct CronSchedule {
    /// 5-field cron expression: minute hour day-of-month month day-of-week.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cron: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timezone: Option<String>,
    /// Fixed interval in seconds, as an alternative to `cron`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub every_secs: Option<i64>,
    /// When an interval schedule first fires. Defaults to one interval out.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub first_fire_at: Option<DateTime<Utc>>,
}

impl CronSchedule {
    pub fn every(secs: i64) -> Self {
        Self {
            every_secs: Some(secs),
            ..Default::default()
        }
    }

    pub fn calendar(expression: impl Into<String>, timezone: impl Into<String>) -> Self {
        Self {
            cron: Some(expression.into()),
            timezone: Some(timezone.into()),
            ..Default::default()
        }
    }

    pub fn is_calendar(&self) -> bool {
        self.cron.is_some()
    }

    /// Human-readable summary for the crons page.
    pub fn describe(&self) -> String {
        match (&self.cron, self.every_secs) {
            (Some(expr), _) => {
                let tz = self.timezone.as_deref().unwrap_or(DEFAULT_TIMEZONE);
                format!("{expr} ({tz})")
            }
            (None, Some(secs)) => format!("every {}", humanize_secs(secs)),
            (None, None) => "unscheduled".to_string(),
        }
    }
}

fn humanize_secs(secs: i64) -> String {
    match secs {
        s if s % 86_400 == 0 => format!("{}d", s / 86_400),
        s if s % 3_600 == 0 => format!("{}h", s / 3_600),
        s if s % 60 == 0 => format!("{}m", s / 60),
        s => format!("{s}s"),
    }
}

/// Validate and canonicalize a schedule, computing its first fire.
///
/// Rejects a schedule that specifies neither or both of `cron` and
/// `every_secs`: a cron whose next fire is ambiguous would run at two
/// cadences, which is worse than refusing to save it.
pub fn normalize(
    schedule: &CronSchedule,
    now: DateTime<Utc>,
) -> AppResult<(CronSchedule, DateTime<Utc>)> {
    match (schedule.cron.as_deref(), schedule.every_secs) {
        (Some(_), Some(_)) => Err(AppError::bad_request(
            "a schedule takes either `cron` or `every_secs`, not both",
        )),
        (None, None) => Err(AppError::bad_request(
            "a schedule needs a `cron` expression or an `every_secs` interval",
        )),
        (Some(expression), None) => {
            let expression = canonical_expression(expression)?;
            let tz_name = schedule
                .timezone
                .clone()
                .unwrap_or_else(|| DEFAULT_TIMEZONE.to_string());
            let tz = parse_timezone(&tz_name)?;
            let parsed = CronExpression::parse(&expression)?;
            let next = parsed
                .next_after(now, tz)
                .ok_or_else(|| AppError::bad_request(format!("`{expression}` never fires")))?;
            Ok((
                CronSchedule {
                    cron: Some(expression),
                    timezone: Some(tz_name),
                    every_secs: None,
                    first_fire_at: None,
                },
                next,
            ))
        }
        (None, Some(secs)) => {
            if secs < MIN_INTERVAL_SECS {
                return Err(AppError::bad_request(format!(
                    "`every_secs` must be at least {MIN_INTERVAL_SECS} seconds"
                )));
            }
            let first = schedule
                .first_fire_at
                .unwrap_or_else(|| now + Duration::seconds(secs));
            Ok((
                CronSchedule {
                    cron: None,
                    timezone: None,
                    every_secs: Some(secs),
                    first_fire_at: Some(first),
                },
                first,
            ))
        }
    }
}

/// The next fire strictly after `after`.
pub fn next_fire_after(
    schedule: &CronSchedule,
    after: DateTime<Utc>,
) -> AppResult<Option<DateTime<Utc>>> {
    match (schedule.cron.as_deref(), schedule.every_secs) {
        (Some(expression), _) => {
            let tz = parse_timezone(schedule.timezone.as_deref().unwrap_or(DEFAULT_TIMEZONE))?;
            Ok(CronExpression::parse(expression)?.next_after(after, tz))
        }
        (None, Some(secs)) if secs >= MIN_INTERVAL_SECS => {
            let anchor = schedule.first_fire_at.unwrap_or(after);
            if anchor > after {
                return Ok(Some(anchor));
            }
            // Advance in whole intervals from the anchor so a slow tick does
            // not drift the schedule forward.
            let elapsed = (after - anchor).num_seconds();
            let steps = elapsed / secs + 1;
            Ok(Some(anchor + Duration::seconds(steps * secs)))
        }
        _ => Ok(None),
    }
}

pub fn parse_timezone(name: &str) -> AppResult<Tz> {
    name.trim()
        .parse::<Tz>()
        .map_err(|_| AppError::bad_request(format!("invalid IANA timezone: {name}")))
}

fn canonical_expression(input: &str) -> AppResult<String> {
    let expression = input.split_whitespace().collect::<Vec<_>>().join(" ");
    if expression.split(' ').count() != 5 {
        return Err(AppError::bad_request(
            "cron must be a 5-field expression: minute hour day-of-month month day-of-week",
        ));
    }
    CronExpression::parse(&expression)?;
    Ok(expression)
}

// ---------------------------------------------------------------------------
// Expression parsing
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CronExpression {
    minutes: Vec<u32>,
    hours: Vec<u32>,
    days_of_month: Vec<u32>,
    months: Vec<u32>,
    days_of_week: Vec<u32>,
    dom_restricted: bool,
    dow_restricted: bool,
}

const MONTH_NAMES: [&str; 12] = [
    "jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec",
];
const DAY_NAMES: [&str; 7] = ["sun", "mon", "tue", "wed", "thu", "fri", "sat"];

impl CronExpression {
    pub fn parse(expression: &str) -> AppResult<Self> {
        let fields: Vec<&str> = expression.split_whitespace().collect();
        if fields.len() != 5 {
            return Err(AppError::bad_request(
                "cron must be a 5-field expression: minute hour day-of-month month day-of-week",
            ));
        }
        Ok(Self {
            minutes: parse_field(fields[0], 0, 59, &[], "minute")?,
            hours: parse_field(fields[1], 0, 23, &[], "hour")?,
            days_of_month: parse_field(fields[2], 1, 31, &[], "day-of-month")?,
            months: parse_field(fields[3], 1, 12, &MONTH_NAMES, "month")?,
            days_of_week: parse_day_of_week(fields[4])?,
            dom_restricted: fields[2] != "*",
            dow_restricted: fields[4] != "*",
        })
    }

    /// Standard cron semantics: when *both* day-of-month and day-of-week are
    /// restricted the day matches if *either* does; otherwise both must match.
    fn day_matches(&self, date: NaiveDate) -> bool {
        let dom = date.day();
        let dow = date.weekday().num_days_from_sunday();
        let dom_hit = self.days_of_month.contains(&dom);
        let dow_hit = self.days_of_week.contains(&dow);
        match (self.dom_restricted, self.dow_restricted) {
            (true, true) => dom_hit || dow_hit,
            _ => dom_hit && dow_hit,
        }
    }

    fn date_matches(&self, date: NaiveDate) -> bool {
        self.months.contains(&date.month()) && self.day_matches(date)
    }

    /// The next instant strictly after `after`, in `tz`.
    pub fn next_after(&self, after: DateTime<Utc>, tz: Tz) -> Option<DateTime<Utc>> {
        let local = after.with_timezone(&tz);
        let mut date = local.date_naive();
        // Start one minute past `after`, truncated to the minute.
        let mut cursor_minutes = local.hour() * 60 + local.minute() + 1;
        if cursor_minutes >= 24 * 60 {
            date = date.succ_opt()?;
            cursor_minutes = 0;
        }

        for _ in 0..MAX_SEARCH_DAYS {
            if self.date_matches(date) {
                for hour in self.hours.iter().copied() {
                    for minute in self.minutes.iter().copied() {
                        if hour * 60 + minute < cursor_minutes {
                            continue;
                        }
                        let naive = date.and_hms_opt(hour, minute, 0)?;
                        if let Some(resolved) = resolve_local(naive, tz) {
                            return Some(resolved);
                        }
                        // A DST spring-forward gap: this wall-clock time does
                        // not exist today. Try the next candidate.
                    }
                }
            }
            date = date.succ_opt()?;
            cursor_minutes = 0;
        }
        None
    }
}

/// Turn a local wall-clock time into an instant.
///
/// Ambiguous times (the repeated hour at a DST fall-back) resolve to the
/// **earlier** instant so a daily job runs once, not twice. Nonexistent times
/// (the skipped hour at spring-forward) return `None` so the caller moves on
/// rather than silently shifting the job by an hour.
fn resolve_local(naive: NaiveDateTime, tz: Tz) -> Option<DateTime<Utc>> {
    match tz.from_local_datetime(&naive) {
        chrono::LocalResult::Single(dt) => Some(dt.with_timezone(&Utc)),
        chrono::LocalResult::Ambiguous(earlier, _) => Some(earlier.with_timezone(&Utc)),
        chrono::LocalResult::None => None,
    }
}

fn parse_field(
    field: &str,
    min: u32,
    max: u32,
    names: &[&str],
    label: &str,
) -> AppResult<Vec<u32>> {
    let mut values: Vec<u32> = Vec::new();
    for part in field.split(',') {
        let part = part.trim();
        if part.is_empty() {
            return Err(AppError::bad_request(format!("{label}: empty list entry")));
        }
        let (range_part, step) = match part.split_once('/') {
            Some((r, s)) => {
                let step: u32 = s
                    .parse()
                    .map_err(|_| AppError::bad_request(format!("{label}: bad step {s:?}")))?;
                if step == 0 {
                    return Err(AppError::bad_request(format!(
                        "{label}: step must be positive"
                    )));
                }
                (r, step)
            }
            None => (part, 1),
        };

        let (start, end) = if range_part == "*" {
            (min, max)
        } else if let Some((a, b)) = range_part.split_once('-') {
            (
                parse_value(a, min, max, names, label)?,
                parse_value(b, min, max, names, label)?,
            )
        } else {
            let v = parse_value(range_part, min, max, names, label)?;
            // A bare value with a step means "from here to the top": `5/10`.
            if step > 1 {
                (v, max)
            } else {
                (v, v)
            }
        };

        if start > end {
            return Err(AppError::bad_request(format!(
                "{label}: range {start}-{end} runs backwards"
            )));
        }
        let mut v = start;
        while v <= end {
            values.push(v);
            v += step;
        }
    }
    values.sort_unstable();
    values.dedup();
    if values.is_empty() {
        return Err(AppError::bad_request(format!("{label}: matches nothing")));
    }
    Ok(values)
}

fn parse_value(raw: &str, min: u32, max: u32, names: &[&str], label: &str) -> AppResult<u32> {
    let token = raw.trim();
    let value = match token.parse::<u32>() {
        Ok(v) => v,
        Err(_) => {
            let lower = token.to_ascii_lowercase();
            names
                .iter()
                .position(|n| *n == lower)
                .map(|i| i as u32 + min)
                .ok_or_else(|| {
                    AppError::bad_request(format!("{label}: unrecognised value {token:?}"))
                })?
        }
    };
    if value < min || value > max {
        return Err(AppError::bad_request(format!(
            "{label}: {value} is outside {min}-{max}"
        )));
    }
    Ok(value)
}

/// Day-of-week accepts 0-7 (both 0 and 7 mean Sunday) and three-letter names.
fn parse_day_of_week(field: &str) -> AppResult<Vec<u32>> {
    let raw = parse_field(field, 0, 7, &DAY_NAMES, "day-of-week")?;
    let mut values: Vec<u32> = raw
        .into_iter()
        .map(|v| if v == 7 { 0 } else { v })
        .collect();
    values.sort_unstable();
    values.dedup();
    Ok(values)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn utc(s: &str) -> DateTime<Utc> {
        DateTime::parse_from_rfc3339(s).unwrap().with_timezone(&Utc)
    }

    fn next(expression: &str, tz: &str, from: &str) -> String {
        let schedule = CronSchedule::calendar(expression, tz);
        next_fire_after(&schedule, utc(from))
            .unwrap()
            .unwrap()
            .to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
    }

    #[test]
    fn every_minute_advances_by_one_minute() {
        assert_eq!(
            next("* * * * *", "UTC", "2026-08-01T10:00:30Z"),
            "2026-08-01T10:01:00Z"
        );
    }

    #[test]
    fn a_daily_job_finds_tomorrow_once_today_has_passed() {
        assert_eq!(
            next("0 9 * * *", "UTC", "2026-08-01T10:00:00Z"),
            "2026-08-02T09:00:00Z"
        );
        assert_eq!(
            next("0 9 * * *", "UTC", "2026-08-01T08:00:00Z"),
            "2026-08-01T09:00:00Z"
        );
    }

    #[test]
    fn the_boundary_minute_is_exclusive() {
        // Firing exactly at 09:00 must yield tomorrow, not the same instant —
        // otherwise the scheduler re-fires the cron it just ran.
        assert_eq!(
            next("0 9 * * *", "UTC", "2026-08-01T09:00:00Z"),
            "2026-08-02T09:00:00Z"
        );
    }

    #[test]
    fn lists_ranges_and_steps_all_parse() {
        assert_eq!(
            next("0,30 * * * *", "UTC", "2026-08-01T10:05:00Z"),
            "2026-08-01T10:30:00Z"
        );
        assert_eq!(
            next("*/15 * * * *", "UTC", "2026-08-01T10:05:00Z"),
            "2026-08-01T10:15:00Z"
        );
        assert_eq!(
            next("0 9-17 * * *", "UTC", "2026-08-01T20:00:00Z"),
            "2026-08-02T09:00:00Z"
        );
        assert_eq!(
            next("0 0 1 */3 *", "UTC", "2026-02-01T00:00:00Z"),
            "2026-04-01T00:00:00Z"
        );
    }

    #[test]
    fn month_and_day_names_are_accepted() {
        assert_eq!(
            next("0 9 * * mon", "UTC", "2026-08-01T00:00:00Z"),
            "2026-08-03T09:00:00Z"
        );
        assert_eq!(
            next("0 0 1 jan *", "UTC", "2026-08-01T00:00:00Z"),
            "2027-01-01T00:00:00Z"
        );
    }

    #[test]
    fn sunday_is_both_zero_and_seven() {
        let from = "2026-08-01T00:00:00Z"; // a Saturday
        assert_eq!(
            next("0 9 * * 0", "UTC", from),
            next("0 9 * * 7", "UTC", from)
        );
    }

    #[test]
    fn day_of_month_and_day_of_week_are_ored_when_both_are_restricted() {
        // Standard cron: "1st of the month OR any Monday", not the intersection.
        let expression = "0 0 1 * mon";
        // 2026-08-01 is a Saturday, so the 1st itself matches via day-of-month.
        assert_eq!(
            next(expression, "UTC", "2026-07-31T12:00:00Z"),
            "2026-08-01T00:00:00Z"
        );
        // The next hit after that is Monday the 3rd.
        assert_eq!(
            next(expression, "UTC", "2026-08-01T00:00:00Z"),
            "2026-08-03T00:00:00Z"
        );
    }

    #[test]
    fn day_fields_are_anded_when_only_one_is_restricted() {
        // day-of-week is `*`, so only the 15th matches.
        assert_eq!(
            next("0 0 15 * *", "UTC", "2026-08-01T00:00:00Z"),
            "2026-08-15T00:00:00Z"
        );
    }

    #[test]
    fn schedules_respect_their_timezone() {
        // 09:00 in Los Angeles is 16:00 UTC in August (PDT, UTC-7).
        assert_eq!(
            next("0 9 * * *", "America/Los_Angeles", "2026-08-01T00:00:00Z"),
            "2026-08-01T16:00:00Z"
        );
        // And 17:00 UTC in January (PST, UTC-8).
        assert_eq!(
            next("0 9 * * *", "America/Los_Angeles", "2026-01-05T00:00:00Z"),
            "2026-01-05T17:00:00Z"
        );
    }

    #[test]
    fn a_daily_job_fires_once_across_a_dst_fall_back() {
        // US DST ends 2026-11-01; 01:30 local occurs twice. The earlier
        // instant wins, so the job runs once.
        let fired = next("30 1 * * *", "America/Los_Angeles", "2026-10-31T12:00:00Z");
        assert_eq!(fired, "2026-11-01T08:30:00Z"); // 01:30 PDT, the first pass
    }

    #[test]
    fn a_job_in_a_dst_spring_forward_gap_moves_to_the_next_valid_day() {
        // US DST starts 2026-03-08: 02:30 local never happens that day, so a
        // daily 02:30 job skips to the 9th rather than silently shifting.
        let fired = next("30 2 * * *", "America/Los_Angeles", "2026-03-07T12:00:00Z");
        assert_eq!(fired, "2026-03-09T09:30:00Z");
    }

    #[test]
    fn leap_day_schedules_find_the_next_leap_year() {
        assert_eq!(
            next("0 0 29 2 *", "UTC", "2026-03-01T00:00:00Z"),
            "2028-02-29T00:00:00Z"
        );
    }

    #[test]
    fn interval_schedules_advance_in_whole_steps_without_drift() {
        let anchor = utc("2026-08-01T10:00:00Z");
        let schedule = CronSchedule {
            every_secs: Some(300),
            first_fire_at: Some(anchor),
            ..Default::default()
        };
        assert_eq!(
            next_fire_after(&schedule, utc("2026-08-01T09:00:00Z")).unwrap(),
            Some(anchor),
            "before the anchor, the anchor is next"
        );
        // A long outage must land back on the original 5-minute grid.
        assert_eq!(
            next_fire_after(&schedule, utc("2026-08-01T10:47:13Z")).unwrap(),
            Some(utc("2026-08-01T10:50:00Z"))
        );
        assert_eq!(
            next_fire_after(&schedule, anchor).unwrap(),
            Some(utc("2026-08-01T10:05:00Z"))
        );
    }

    #[test]
    fn normalize_rejects_ambiguous_and_incomplete_schedules() {
        let now = utc("2026-08-01T10:00:00Z");
        assert!(normalize(&CronSchedule::default(), now).is_err());
        assert!(normalize(
            &CronSchedule {
                cron: Some("* * * * *".into()),
                every_secs: Some(60),
                ..Default::default()
            },
            now
        )
        .is_err());
        assert!(
            normalize(&CronSchedule::every(30), now).is_err(),
            "too frequent"
        );
        assert!(normalize(&CronSchedule::every(60), now).is_ok());
    }

    #[test]
    fn normalize_canonicalizes_whitespace_and_fills_in_the_timezone() {
        let (schedule, first) = normalize(
            &CronSchedule {
                cron: Some("  0   9  *  *  * ".into()),
                ..Default::default()
            },
            utc("2026-08-01T10:00:00Z"),
        )
        .unwrap();
        assert_eq!(schedule.cron.as_deref(), Some("0 9 * * *"));
        assert_eq!(schedule.timezone.as_deref(), Some("UTC"));
        assert_eq!(first, utc("2026-08-02T09:00:00Z"));
    }

    #[test]
    fn malformed_expressions_are_rejected() {
        for bad in [
            "* * * *",      // four fields
            "* * * * * *",  // six fields
            "60 * * * *",   // minute out of range
            "* 24 * * *",   // hour out of range
            "* * 0 * *",    // day-of-month starts at 1
            "* * * 13 *",   // month out of range
            "* * * * 8",    // day-of-week out of range
            "*/0 * * * *",  // zero step
            "10-5 * * * *", // backwards range
            "abc * * * *",  // not a number or name
            "1,,2 * * * *", // empty list entry
        ] {
            assert!(
                CronExpression::parse(bad).is_err(),
                "{bad:?} should have been rejected"
            );
        }
    }

    #[test]
    fn invalid_timezones_are_rejected() {
        assert!(parse_timezone("Mars/Olympus").is_err());
        assert!(parse_timezone("America/Los_Angeles").is_ok());
        assert!(parse_timezone(" UTC ").is_ok());
    }

    #[test]
    fn schedules_describe_themselves_for_the_ui() {
        assert_eq!(
            CronSchedule::calendar("0 9 * * *", "America/Los_Angeles").describe(),
            "0 9 * * * (America/Los_Angeles)"
        );
        assert_eq!(CronSchedule::every(3600).describe(), "every 1h");
        assert_eq!(CronSchedule::every(86_400).describe(), "every 1d");
        assert_eq!(CronSchedule::every(90).describe(), "every 90s");
        assert_eq!(CronSchedule::default().describe(), "unscheduled");
    }
}
