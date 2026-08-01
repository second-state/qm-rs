//! The harness: what drives one turn's conversation with a model.
//!
//! QM's point is that a deployment is not tied to one vendor — Pi, OpenCode,
//! Codex and Claude Code all drive the same core. That property lives in this
//! trait. [`openai::OpenAiHarness`] talks to any OpenAI-compatible gateway;
//! [`mock::MockHarness`] is deterministic and needs no network, which is what
//! the tests and the smoke script run against.
//!
//! A harness never touches the database. It receives history, drives the model,
//! calls tools through [`ToolDispatch`], and emits entries through [`TurnSink`].

pub mod mock;
pub mod openai;

use async_trait::async_trait;

use crate::error::AppResult;
use crate::types::{NewEntry, SessionEntry};

/// A tool as the model sees it.
#[derive(Debug, Clone)]
pub struct ToolSpec {
    pub name: String,
    pub description: String,
    /// JSON Schema for the arguments.
    pub parameters: serde_json::Value,
}

/// What running a tool produced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ToolOutcome {
    /// Normal result; the text goes back to the model.
    Output(String),
    /// The command policy wants a human. The turn stops here and resumes when
    /// the approval is resolved.
    NeedsApproval {
        command: String,
        reason: String,
        matched: Option<String>,
        approval_key: String,
    },
    /// A hard denial. The model is told, and may try something else.
    Denied(String),
    /// A turn-ending tool: `stay_silent` / `finish_silently`.
    EndTurn { reply: String, silent: bool },
}

/// The tool surface a harness drives. Implemented by [`crate::tools`].
#[async_trait]
pub trait ToolDispatch: Send + Sync {
    fn specs(&self) -> Vec<ToolSpec>;
    async fn call(&self, name: &str, args: &serde_json::Value) -> ToolOutcome;
}

/// Where a harness writes the transcript as it goes, so the UI can stream it
/// and a resumed turn can see what already ran.
#[async_trait]
pub trait TurnSink: Send + Sync {
    async fn emit(&self, entry: NewEntry) -> AppResult<SessionEntry>;
}

/// One turn's inputs.
pub struct TurnInput<'a> {
    pub system_prompt: String,
    /// Prior transcript, oldest first.
    pub history: &'a [SessionEntry],
    pub text: String,
    pub model: Option<String>,
    pub max_steps: u32,
    pub tools: &'a dyn ToolDispatch,
    pub sink: &'a dyn TurnSink,
    pub scope_label: crate::types::ScopeId,
    /// When set, every tool call pauses for a human first (strict posture).
    pub approve_every_tool: bool,
}

/// What the turn produced.
#[derive(Debug, Clone, Default)]
pub struct HarnessOutcome {
    pub reply: String,
    pub silent: bool,
    /// Model round-trips consumed.
    pub steps: u32,
    /// Set when a tool call is waiting on a human.
    pub pending_approval: Option<PendingApprovalRequest>,
    /// Set when the loop hit `max_steps` before the model finished.
    pub hit_step_limit: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingApprovalRequest {
    pub command: String,
    pub reason: String,
    pub matched: Option<String>,
    pub approval_key: String,
}

#[async_trait]
pub trait Harness: Send + Sync {
    fn name(&self) -> &str;

    async fn run_turn(&self, input: TurnInput<'_>) -> AppResult<HarnessOutcome>;

    /// A cheap one-shot call for the utility work: titles, security screening.
    /// Returning `None` means "unavailable", which callers must handle rather
    /// than treat as an empty answer.
    async fn one_shot(&self, system_prompt: &str, prompt: &str) -> AppResult<Option<String>>;
}

/// Render prior entries as plain conversation turns for a chat-completions
/// style model.
///
/// Tool traffic is folded into compact notes rather than replayed as real tool
/// messages: replaying `tool_call`/`tool_result` pairs would require the exact
/// call ids the provider issued, which are not durable across turns.
pub fn render_history(history: &[SessionEntry], max_chars: usize) -> Vec<(String, String)> {
    let mut turns: Vec<(String, String)> = Vec::new();
    for entry in history {
        use crate::types::EntryType::*;
        let (role, text) = match entry.entry_type {
            User => ("user", entry.text().to_string()),
            Assistant => ("assistant", entry.text().to_string()),
            ToolCall => {
                let tool = entry
                    .payload
                    .get("tool")
                    .and_then(|t| t.as_str())
                    .unwrap_or("tool");
                ("assistant", format!("[called {tool}]"))
            }
            ToolResult => {
                let text = entry.text();
                let capped: String = text.chars().take(600).collect();
                ("assistant", format!("[tool result] {capped}"))
            }
            System | Delivery => ("system", entry.text().to_string()),
            // Thinking is the model's own scratch space and approval rows are
            // UI state; neither belongs in the next prompt.
            Thinking | ApprovalRequest | ApprovalResolved => continue,
        };
        if text.trim().is_empty() {
            continue;
        }
        turns.push((role.to_string(), text));
    }

    // Keep the tail within budget: recent context beats old context.
    let mut total: usize = turns.iter().map(|(_, t)| t.len()).sum();
    let mut start = 0;
    while total > max_chars && start < turns.len() {
        total -= turns[start].1.len();
        start += 1;
    }
    turns.split_off(start)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{EntryType, ScopeId};

    fn entry(seq: i64, entry_type: EntryType, payload: serde_json::Value) -> SessionEntry {
        SessionEntry {
            session_id: "s1".into(),
            seq,
            parent_seq: None,
            entry_type,
            payload,
            scope_label: ScopeId::personal("u1"),
            created_at: "2026-08-01T10:00:00Z".into(),
        }
    }

    fn text_entry(seq: i64, entry_type: EntryType, text: &str) -> SessionEntry {
        entry(seq, entry_type, serde_json::json!({ "text": text }))
    }

    #[test]
    fn history_renders_user_and_assistant_turns() {
        let history = vec![
            text_entry(0, EntryType::User, "hello"),
            text_entry(1, EntryType::Assistant, "hi"),
        ];
        let rendered = render_history(&history, 10_000);
        assert_eq!(rendered.len(), 2);
        assert_eq!(rendered[0], ("user".into(), "hello".into()));
        assert_eq!(rendered[1], ("assistant".into(), "hi".into()));
    }

    #[test]
    fn thinking_and_approval_rows_stay_out_of_the_next_prompt() {
        let history = vec![
            text_entry(0, EntryType::User, "hello"),
            text_entry(1, EntryType::Thinking, "the user probably wants X"),
            text_entry(2, EntryType::ApprovalRequest, "rm -rf"),
            text_entry(3, EntryType::ApprovalResolved, "approved"),
            text_entry(4, EntryType::Assistant, "done"),
        ];
        let rendered = render_history(&history, 10_000);
        assert_eq!(rendered.len(), 2);
        assert!(!rendered.iter().any(|(_, t)| t.contains("probably wants")));
    }

    #[test]
    fn tool_traffic_is_folded_into_compact_notes() {
        let history = vec![
            entry(
                0,
                EntryType::ToolCall,
                serde_json::json!({"tool": "execute", "args": {"command": "ls"}}),
            ),
            text_entry(1, EntryType::ToolResult, "a.txt\nb.txt"),
        ];
        let rendered = render_history(&history, 10_000);
        assert_eq!(rendered[0].1, "[called execute]");
        assert!(rendered[1].1.starts_with("[tool result] a.txt"));
    }

    #[test]
    fn a_long_tool_result_is_capped() {
        let history = vec![text_entry(0, EntryType::ToolResult, &"x".repeat(5_000))];
        let rendered = render_history(&history, 10_000);
        assert!(rendered[0].1.len() < 700);
    }

    #[test]
    fn empty_entries_are_dropped() {
        let history = vec![
            text_entry(0, EntryType::User, "   "),
            text_entry(1, EntryType::Assistant, "real"),
        ];
        assert_eq!(render_history(&history, 10_000).len(), 1);
    }

    #[test]
    fn the_tail_is_what_survives_the_budget() {
        let history: Vec<SessionEntry> = (0..50)
            .map(|i| text_entry(i, EntryType::User, &format!("message number {i}")))
            .collect();
        let rendered = render_history(&history, 100);
        assert!(rendered.len() < 50);
        assert!(
            rendered.last().unwrap().1.contains("message number 49"),
            "the most recent turn must survive"
        );
        let total: usize = rendered.iter().map(|(_, t)| t.len()).sum();
        assert!(total <= 100, "budget exceeded: {total}");
    }

    #[test]
    fn an_empty_history_renders_to_nothing() {
        assert!(render_history(&[], 1_000).is_empty());
    }
}
