//! Connectors: surfaces that bring work in from outside.
//!
//! A connector maps an external conversation onto a scope and a thread, then
//! hands the turn to the orchestrator. It never touches the harness or the
//! stores directly, which is what keeps one identity and one policy across
//! every surface.

pub mod slack;
pub mod telegram;

pub use slack::SlackClient;
pub use telegram::TelegramConnector;
