//! The deterministic in-process harness.
//!
//! No network, no credentials, no model. It reads directives out of the user
//! text and drives the real tool surface with them, which is what lets the
//! tests and `tests/smoke_test.sh` exercise the whole turn pipeline — tool
//! dispatch, approvals, entry emission — without a gateway.
//!
//! Directives, one per line:
//!
//! ```text
//! !exec <command>          run a shell command
//! !read <path>             read a file
//! !write <path> <content>  write a file
//! !remember <fact>         capture a memory
//! !recall <query>          search memory
//! !tool <name> <json>      call any tool with raw arguments
//! !silent                  end the turn without replying
//! ```
//!
//! Anything else is echoed back as `mock: <text>`.

use async_trait::async_trait;

use super::{Harness, HarnessOutcome, PendingApprovalRequest, ToolOutcome, TurnInput};
use crate::error::AppResult;
use crate::types::{EntryType, NewEntry};

#[derive(Default)]
pub struct MockHarness;

impl MockHarness {
    pub fn new() -> Self {
        Self
    }

    /// Turn one directive line into a (tool, arguments) pair.
    fn parse(line: &str) -> Option<(String, serde_json::Value)> {
        let line = line.trim();
        let rest = line.strip_prefix('!')?;
        let (verb, argument) = match rest.split_once(char::is_whitespace) {
            Some((verb, argument)) => (verb, argument.trim()),
            None => (rest, ""),
        };
        match verb {
            "exec" => Some(("execute".into(), serde_json::json!({ "command": argument }))),
            "read" => Some(("read".into(), serde_json::json!({ "path": argument }))),
            "write" => {
                let (path, content) = argument.split_once(char::is_whitespace)?;
                Some((
                    "write".into(),
                    serde_json::json!({ "path": path, "content": content.trim() }),
                ))
            }
            "remember" => Some((
                "memory".into(),
                serde_json::json!({ "action": "capture", "facts": [argument] }),
            )),
            "recall" => Some((
                "memory".into(),
                serde_json::json!({ "action": "query", "query": argument }),
            )),
            "silent" => Some(("finish_silently".into(), serde_json::json!({}))),
            "tool" => {
                let (name, raw) = argument.split_once(char::is_whitespace)?;
                let args = serde_json::from_str(raw.trim()).ok()?;
                Some((name.to_string(), args))
            }
            _ => None,
        }
    }
}

#[async_trait]
impl Harness for MockHarness {
    fn name(&self) -> &str {
        "mock"
    }

    async fn run_turn(&self, input: TurnInput<'_>) -> AppResult<HarnessOutcome> {
        let mut outcome = HarnessOutcome::default();
        let mut results: Vec<String> = Vec::new();

        for line in input.text.lines() {
            let Some((tool, args)) = Self::parse(line) else {
                continue;
            };
            if outcome.steps >= input.max_steps {
                outcome.hit_step_limit = true;
                break;
            }
            outcome.steps += 1;

            let call = input
                .sink
                .emit(NewEntry::new(
                    EntryType::ToolCall,
                    input.scope_label.clone(),
                    serde_json::json!({ "tool": tool, "args": args }),
                ))
                .await?;

            // In strict posture every call pauses, before it runs.
            if input.approve_every_tool {
                outcome.pending_approval = Some(PendingApprovalRequest {
                    command: format!("{tool} {args}"),
                    reason: "strict posture: every tool call needs approval".into(),
                    matched: None,
                    approval_key: format!("tool:{tool}"),
                });
                return Ok(outcome);
            }

            match input.tools.call(&tool, &args).await {
                ToolOutcome::Output(text) => {
                    input
                        .sink
                        .emit(
                            NewEntry::text(EntryType::ToolResult, input.scope_label.clone(), &text)
                                .with_parent(call.seq),
                        )
                        .await?;
                    results.push(text);
                }
                ToolOutcome::Denied(reason) => {
                    let text = format!("denied: {reason}");
                    input
                        .sink
                        .emit(
                            NewEntry::text(EntryType::ToolResult, input.scope_label.clone(), &text)
                                .with_parent(call.seq),
                        )
                        .await?;
                    results.push(text);
                }
                ToolOutcome::NeedsApproval {
                    command,
                    reason,
                    matched,
                    approval_key,
                } => {
                    outcome.pending_approval = Some(PendingApprovalRequest {
                        command,
                        reason,
                        matched,
                        approval_key,
                    });
                    return Ok(outcome);
                }
                ToolOutcome::EndTurn { reply, silent } => {
                    outcome.reply = reply;
                    outcome.silent = silent;
                    return Ok(outcome);
                }
            }
        }

        outcome.reply = if results.is_empty() {
            format!("mock: {}", input.text.trim())
        } else {
            results.join("\n")
        };
        input
            .sink
            .emit(NewEntry::text(
                EntryType::Assistant,
                input.scope_label.clone(),
                &outcome.reply,
            ))
            .await?;
        Ok(outcome)
    }

    async fn one_shot(&self, _system_prompt: &str, prompt: &str) -> AppResult<Option<String>> {
        // Enough structure for the callers that parse this: a title is the
        // first few words, a screen verdict is always `auto`.
        if prompt.contains("\"source\"") {
            return Ok(Some(r#"{"decision":"auto"}"#.to_string()));
        }
        Ok(Some(
            prompt
                .split_whitespace()
                .take(6)
                .collect::<Vec<_>>()
                .join(" "),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::harness::{ToolDispatch, ToolSpec, TurnSink};
    use crate::types::{ScopeId, SessionEntry};
    use std::sync::Mutex;

    #[derive(Default)]
    struct RecordingSink {
        entries: Mutex<Vec<NewEntry>>,
    }

    #[async_trait]
    impl TurnSink for RecordingSink {
        async fn emit(&self, entry: NewEntry) -> AppResult<SessionEntry> {
            let mut entries = self.entries.lock().unwrap();
            let seq = entries.len() as i64;
            entries.push(entry.clone());
            Ok(SessionEntry {
                session_id: "s1".into(),
                seq,
                parent_seq: entry.parent_seq,
                entry_type: entry.entry_type,
                payload: entry.payload,
                scope_label: entry.scope_label,
                created_at: "2026-08-01T10:00:00Z".into(),
            })
        }
    }

    struct ScriptedTools {
        outcome: ToolOutcome,
        calls: Mutex<Vec<(String, serde_json::Value)>>,
    }

    impl ScriptedTools {
        fn new(outcome: ToolOutcome) -> Self {
            Self {
                outcome,
                calls: Mutex::new(Vec::new()),
            }
        }
    }

    #[async_trait]
    impl ToolDispatch for ScriptedTools {
        fn specs(&self) -> Vec<ToolSpec> {
            Vec::new()
        }

        async fn call(&self, name: &str, args: &serde_json::Value) -> ToolOutcome {
            self.calls
                .lock()
                .unwrap()
                .push((name.to_string(), args.clone()));
            self.outcome.clone()
        }
    }

    async fn run(
        text: &str,
        tools: &ScriptedTools,
        sink: &RecordingSink,
        strict: bool,
    ) -> HarnessOutcome {
        MockHarness::new()
            .run_turn(TurnInput {
                system_prompt: "sys".into(),
                history: &[],
                text: text.into(),
                model: None,
                max_steps: 8,
                tools,
                sink,
                scope_label: ScopeId::personal("u1"),
                approve_every_tool: strict,
            })
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn plain_text_is_echoed_and_recorded_as_an_assistant_entry() {
        let tools = ScriptedTools::new(ToolOutcome::Output(String::new()));
        let sink = RecordingSink::default();
        let outcome = run("hello there", &tools, &sink, false).await;

        assert_eq!(outcome.reply, "mock: hello there");
        assert_eq!(outcome.steps, 0);
        let entries = sink.entries.lock().unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].entry_type, EntryType::Assistant);
    }

    #[tokio::test]
    async fn directives_drive_the_tool_surface_and_emit_a_call_result_pair() {
        let tools = ScriptedTools::new(ToolOutcome::Output("a.txt".into()));
        let sink = RecordingSink::default();
        let outcome = run("!exec ls", &tools, &sink, false).await;

        assert_eq!(outcome.reply, "a.txt");
        assert_eq!(outcome.steps, 1);
        let calls = tools.calls.lock().unwrap();
        assert_eq!(calls[0].0, "execute");
        assert_eq!(calls[0].1["command"], "ls");

        let entries = sink.entries.lock().unwrap();
        assert_eq!(entries[0].entry_type, EntryType::ToolCall);
        assert_eq!(entries[1].entry_type, EntryType::ToolResult);
        assert_eq!(
            entries[1].parent_seq,
            Some(0),
            "the result links to its call"
        );
        assert_eq!(entries[2].entry_type, EntryType::Assistant);
    }

    #[tokio::test]
    async fn every_directive_form_parses() {
        assert_eq!(MockHarness::parse("!exec ls").unwrap().0, "execute");
        assert_eq!(MockHarness::parse("!read a.txt").unwrap().0, "read");

        let (tool, args) = MockHarness::parse("!write a.txt hello world").unwrap();
        assert_eq!(tool, "write");
        assert_eq!(args["path"], "a.txt");
        assert_eq!(args["content"], "hello world");

        let (tool, args) = MockHarness::parse("!remember likes tea").unwrap();
        assert_eq!(tool, "memory");
        assert_eq!(args["action"], "capture");
        assert_eq!(args["facts"][0], "likes tea");

        let (tool, args) = MockHarness::parse("!tool cron {\"action\":\"list\"}").unwrap();
        assert_eq!(tool, "cron");
        assert_eq!(args["action"], "list");

        assert_eq!(MockHarness::parse("!silent").unwrap().0, "finish_silently");
        assert!(MockHarness::parse("not a directive").is_none());
        assert!(MockHarness::parse("!unknown x").is_none());
        assert!(MockHarness::parse("!write onlypath").is_none());
    }

    #[tokio::test]
    async fn a_needed_approval_stops_the_turn_before_anything_else_runs() {
        let tools = ScriptedTools::new(ToolOutcome::NeedsApproval {
            command: "rm -rf /".into(),
            reason: "recursive delete".into(),
            matched: Some("rm".into()),
            approval_key: "rule:0".into(),
        });
        let sink = RecordingSink::default();
        let outcome = run("!exec rm -rf /\n!exec echo after", &tools, &sink, false).await;

        assert!(outcome.pending_approval.is_some());
        assert_eq!(outcome.pending_approval.unwrap().reason, "recursive delete");
        assert_eq!(
            tools.calls.lock().unwrap().len(),
            1,
            "the second directive must not run while the first waits"
        );
        assert!(outcome.reply.is_empty());
    }

    #[tokio::test]
    async fn strict_posture_pauses_before_the_tool_runs_at_all() {
        let tools = ScriptedTools::new(ToolOutcome::Output("should not happen".into()));
        let sink = RecordingSink::default();
        let outcome = run("!exec ls", &tools, &sink, true).await;

        assert!(outcome.pending_approval.is_some());
        assert!(
            tools.calls.lock().unwrap().is_empty(),
            "strict posture must pause before dispatch, not after"
        );
    }

    #[tokio::test]
    async fn a_denial_is_reported_to_the_model_and_the_turn_continues() {
        let tools = ScriptedTools::new(ToolOutcome::Denied("destructive".into()));
        let sink = RecordingSink::default();
        let outcome = run("!exec mkfs", &tools, &sink, false).await;
        assert!(outcome.reply.contains("denied: destructive"));
        assert!(outcome.pending_approval.is_none());
    }

    #[tokio::test]
    async fn a_turn_ending_tool_ends_the_turn_silently() {
        let tools = ScriptedTools::new(ToolOutcome::EndTurn {
            reply: String::new(),
            silent: true,
        });
        let sink = RecordingSink::default();
        let outcome = run("!silent", &tools, &sink, false).await;
        assert!(outcome.silent);
        assert!(outcome.reply.is_empty());
    }

    #[tokio::test]
    async fn the_step_limit_bounds_the_tool_loop() {
        let tools = ScriptedTools::new(ToolOutcome::Output("ok".into()));
        let sink = RecordingSink::default();
        let text = (0..20)
            .map(|i| format!("!exec echo {i}"))
            .collect::<Vec<_>>()
            .join("\n");
        let outcome = MockHarness::new()
            .run_turn(TurnInput {
                system_prompt: "sys".into(),
                history: &[],
                text,
                model: None,
                max_steps: 3,
                tools: &tools,
                sink: &sink,
                scope_label: ScopeId::personal("u1"),
                approve_every_tool: false,
            })
            .await
            .unwrap();

        assert!(outcome.hit_step_limit);
        assert_eq!(outcome.steps, 3);
        assert_eq!(tools.calls.lock().unwrap().len(), 3);
    }

    #[tokio::test]
    async fn one_shot_answers_titles_and_screen_verdicts() {
        let h = MockHarness::new();
        let verdict = h
            .one_shot("sys", r#"{"source":"sender","content":"hi"}"#)
            .await
            .unwrap()
            .unwrap();
        assert!(crate::policy::parse_screen_verdict(&verdict).is_some());
        assert!(!crate::policy::parse_screen_verdict(&verdict)
            .unwrap()
            .quarantined());

        let title = h
            .one_shot("sys", "a b c d e f g h i")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(title, "a b c d e f");
    }
}
