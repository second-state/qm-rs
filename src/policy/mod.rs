//! Policy: what the agent may run, and how carefully its inputs are treated.
//!
//! Two independent axes, both composed from an org floor that a narrower scope
//! can only tighten:
//!
//! * [`security`] — the posture (strict / auto / dangerous), which decides
//!   whether tool calls pause for approval and whether external content is
//!   screened before it reaches the model;
//! * [`command`] — the predeclared command policy, which applies in **every**
//!   posture, Dangerous included.

pub mod command;
pub mod security;

pub use command::{
    compose_policy, default_org_policy, evaluate_command, parse_command_policy, scannable_command,
    CommandDecision, CommandEvaluation, CommandPolicy, CommandRule, PolicyMode,
};
pub use security::{
    compose_posture, parse_screen_verdict, resolve_security_policy, screen_payload,
    unscreened_notice, InboundScreening, ResolvedSecurityPolicy, ScreenDecision, SecurityPosture,
    SecurityScreenVerdict, ToolApprovals, SECURITY_SCREEN_SYSTEM_PROMPT, UNSCREENED_REASON,
};
