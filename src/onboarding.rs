//! Conversational onboarding.
//!
//! Ported from upstream QM's `src/onboarding/onboarding.ts`. The idea worth
//! copying is that onboarding is **a conversation, not a form**: the agent
//! walks a new person through setup on their first DM, and completion is
//! recorded as a marker line in that person's own memory notebook.
//!
//! Using memory as the source of truth means there is no separate onboarding
//! table to keep in sync, the person can see and edit their own state, and an
//! admin reading the notebook can tell at a glance where someone got to.

use crate::memory::is_bullet;

/// Bumping this re-runs onboarding for everyone — the point of versioning it.
pub const ONBOARDING_VERSION: &str = "v1";
const SKILL_NAME: &str = "onboarding";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OnboardingStatus {
    Completed,
    Dismissed,
    Pending,
    NotStarted,
}

impl OnboardingStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Completed => "completed",
            Self::Dismissed => "dismissed",
            Self::Pending => "pending",
            Self::NotStarted => "not_started",
        }
    }

    /// Whether the agent should still be onboarding this person.
    pub fn is_outstanding(self) -> bool {
        matches!(self, Self::Pending | Self::NotStarted)
    }
}

/// Does this notebook line mark `state` for `version`?
///
/// Upstream uses a regex; the same shape is cheaper to read as an explicit
/// parse, and it avoids a regex compile on every turn.
fn marker_state(line: &str, version: &str) -> Option<&'static str> {
    let text = if is_bullet(line) {
        crate::memory::bullet_text(line)
    } else {
        line.trim().to_string()
    };
    // An optional leading capture date, as `fold_capture` writes.
    let text = crate::memory::strip_capture_date(&text);
    let rest = text.strip_prefix("Onboarding:").or_else(|| {
        text.strip_prefix("onboarding:")
            .or_else(|| text.strip_prefix("ONBOARDING:"))
    })?;
    let rest = rest.trim_start();
    for state in ["completed", "dismissed", "pending"] {
        if let Some(after) = strip_prefix_ci(rest, state) {
            // The version must match as a whole word: `v1` must not match
            // `v10`, or bumping the version would silently do nothing.
            let after = after.trim_start();
            if let Some(tail) = strip_prefix_ci(after, version) {
                if tail.is_empty() || !tail.starts_with(|c: char| c.is_alphanumeric() || c == '.') {
                    return Some(match state {
                        "completed" => "completed",
                        "dismissed" => "dismissed",
                        _ => "pending",
                    });
                }
            }
        }
    }
    None
}

fn strip_prefix_ci<'a>(text: &'a str, prefix: &str) -> Option<&'a str> {
    text.get(..prefix.len())
        .filter(|head| head.eq_ignore_ascii_case(prefix))
        .map(|_| &text[prefix.len()..])
}

/// Read the onboarding state out of a memory notebook.
pub fn detect_status(memory: &str, version: &str) -> OnboardingStatus {
    let mut best = OnboardingStatus::NotStarted;
    for line in memory.lines() {
        match marker_state(line, version) {
            // Completed and dismissed are terminal; either ends the search.
            Some("completed") => return OnboardingStatus::Completed,
            Some("dismissed") => return OnboardingStatus::Dismissed,
            Some("pending") => best = OnboardingStatus::Pending,
            _ => {}
        }
    }
    best
}

/// Rewrite the notebook so it carries exactly one marker for `version`.
pub fn set_status(memory: &str, status: OnboardingStatus, today: &str, version: &str) -> String {
    let kept: Vec<&str> = memory
        .lines()
        .filter(|line| marker_state(line, version).is_none())
        .collect();
    let mut base = kept.join("\n").trim_end().to_string();

    if status == OnboardingStatus::NotStarted {
        if !base.is_empty() {
            base.push('\n');
        }
        return base;
    }

    let line = match status {
        OnboardingStatus::Pending => {
            format!("- Onboarding: pending {version} since {today}.")
        }
        _ => format!("- Onboarding: {} {version} on {today}.", status.as_str()),
    };
    if base.is_empty() {
        format!("{line}\n")
    } else {
        format!("{base}\n{line}\n")
    }
}

/// Whether an `onboarding` skill is among those visible to this turn.
pub fn skill_visible(skill_names: &[String]) -> bool {
    skill_names.iter().any(|n| n == SKILL_NAME)
}

/// The prompt block appended while onboarding is outstanding.
///
/// Returns empty once onboarding is settled, so the instruction disappears
/// rather than nagging forever.
pub fn pending_prompt(status: OnboardingStatus, version: &str, has_skill: bool) -> String {
    if !status.is_outstanding() {
        return String::new();
    }
    let marker = match status {
        OnboardingStatus::Pending => format!("Memory says onboarding is pending for {version}."),
        _ => format!("Memory has no onboarding completion marker for {version}."),
    };
    let source = if has_skill {
        "Read your `onboarding` skill with the `skills` tool and follow its ordered flow."
    } else {
        "Introduce yourself, say briefly what you can do, and ask what they want to work on."
    };
    [
        "## Pending onboarding".to_string(),
        marker,
        String::new(),
        "This is a new person's first conversation. Onboarding is a setup task; already \
         knowing who they are is no reason to skip it."
            .to_string(),
        String::new(),
        source.to_string(),
        String::new(),
        format!(
            "Use the `memory` tool as the source of truth. When it is done, or they ask you to \
             stop, record `Onboarding: completed {version} on YYYY-MM-DD.` so it does not recur."
        ),
    ]
    .join("\n")
}

/// The opener for someone who has just arrived and typed nothing yet.
pub const PROACTIVE_OPENER_PROMPT: &str =
    "This person just opened the app for the first time and has not typed anything. You already \
     know who they are from their sign-in — open the conversation yourself: greet them by name, \
     say briefly what you can do for them, and start onboarding. Do not ask their name, and do \
     not research them; the hello is just a hello.";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_fresh_notebook_has_not_started() {
        assert_eq!(
            detect_status("# Memory\n", "v1"),
            OnboardingStatus::NotStarted
        );
        assert_eq!(detect_status("", "v1"), OnboardingStatus::NotStarted);
    }

    #[test]
    fn markers_are_detected_in_the_notebook_grammar() {
        let pending = "# Memory\n- Onboarding: pending v1 since 2026-08-01.\n";
        assert_eq!(detect_status(pending, "v1"), OnboardingStatus::Pending);

        let completed = "# Memory\n- Onboarding: completed v1 on 2026-08-02.\n";
        assert_eq!(detect_status(completed, "v1"), OnboardingStatus::Completed);

        let dismissed = "# Memory\n- Onboarding: dismissed v1 on 2026-08-02.\n";
        assert_eq!(detect_status(dismissed, "v1"), OnboardingStatus::Dismissed);
    }

    #[test]
    fn a_capture_dated_marker_is_still_read() {
        // `fold_capture` prefixes bullets with the capture date, so a marker the
        // agent wrote through the memory tool looks like this.
        let memory = "# Memory\n- (2026-08-01) Onboarding: completed v1 on 2026-08-01.\n";
        assert_eq!(detect_status(memory, "v1"), OnboardingStatus::Completed);
    }

    #[test]
    fn a_completed_marker_wins_over_a_stale_pending_one() {
        let memory = "# Memory\n- Onboarding: pending v1 since 2026-08-01.\n\
                      - Onboarding: completed v1 on 2026-08-02.\n";
        assert_eq!(detect_status(memory, "v1"), OnboardingStatus::Completed);
    }

    #[test]
    fn a_marker_for_another_version_does_not_count() {
        let memory = "# Memory\n- Onboarding: completed v1 on 2026-08-02.\n";
        assert_eq!(
            detect_status(memory, "v2"),
            OnboardingStatus::NotStarted,
            "bumping the version must re-run onboarding"
        );
    }

    #[test]
    fn version_matching_does_not_confuse_a_prefix() {
        let memory = "# Memory\n- Onboarding: completed v10 on 2026-08-02.\n";
        assert_eq!(
            detect_status(memory, "v1"),
            OnboardingStatus::NotStarted,
            "v1 must not match v10"
        );
    }

    #[test]
    fn setting_a_status_replaces_any_previous_marker() {
        let start = "# Memory\n- likes tea\n- Onboarding: pending v1 since 2026-08-01.\n";
        let done = set_status(start, OnboardingStatus::Completed, "2026-08-02", "v1");

        assert_eq!(detect_status(&done, "v1"), OnboardingStatus::Completed);
        assert_eq!(
            done.lines().filter(|l| l.contains("Onboarding:")).count(),
            1,
            "exactly one marker should remain"
        );
        assert!(done.contains("likes tea"), "other facts must survive");
        assert!(done.starts_with("# Memory"), "the header must survive");
    }

    #[test]
    fn clearing_the_status_removes_the_marker_and_keeps_the_rest() {
        let start = "# Memory\n- likes tea\n- Onboarding: completed v1 on 2026-08-02.\n";
        let cleared = set_status(start, OnboardingStatus::NotStarted, "2026-08-03", "v1");
        assert_eq!(detect_status(&cleared, "v1"), OnboardingStatus::NotStarted);
        assert!(cleared.contains("likes tea"));
        assert!(!cleared.contains("Onboarding:"));
    }

    #[test]
    fn setting_a_status_on_an_empty_notebook_works() {
        let done = set_status("", OnboardingStatus::Pending, "2026-08-01", "v1");
        assert_eq!(detect_status(&done, "v1"), OnboardingStatus::Pending);
    }

    #[test]
    fn the_prompt_appears_only_while_onboarding_is_outstanding() {
        assert!(!pending_prompt(OnboardingStatus::NotStarted, "v1", false).is_empty());
        assert!(!pending_prompt(OnboardingStatus::Pending, "v1", false).is_empty());
        assert!(
            pending_prompt(OnboardingStatus::Completed, "v1", false).is_empty(),
            "a settled state must stop nagging"
        );
        assert!(pending_prompt(OnboardingStatus::Dismissed, "v1", false).is_empty());
    }

    #[test]
    fn the_prompt_points_at_the_skill_when_there_is_one() {
        let with = pending_prompt(OnboardingStatus::NotStarted, "v1", true);
        assert!(with.contains("`onboarding` skill"));

        let without = pending_prompt(OnboardingStatus::NotStarted, "v1", false);
        assert!(!without.contains("skill"));
        assert!(without.contains("Introduce yourself"));
    }

    #[test]
    fn the_prompt_names_the_version_to_record() {
        assert!(pending_prompt(OnboardingStatus::NotStarted, "v3", false).contains("completed v3"));
    }

    #[test]
    fn a_visible_onboarding_skill_is_detected() {
        assert!(skill_visible(&["onboarding".to_string()]));
        assert!(!skill_visible(&["triage".to_string()]));
        assert!(!skill_visible(&[]));
    }
}
