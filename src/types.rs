//! Core domain types, ported from QM's `src/types.ts`.
//!
//! The central concept is the **scope**: the unit that owns memory, files,
//! skills, keychain entries, crons and permissions. Every principal has a
//! personal scope; channels and groups have shared ones; the org scope is the
//! floor everything else composes over.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

// ---------------------------------------------------------------------------
// Principals
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PrincipalKind {
    Internal,
    Guest,
}

impl PrincipalKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Internal => "internal",
            Self::Guest => "guest",
        }
    }

    pub fn parse(s: &str) -> Self {
        match s {
            "guest" => Self::Guest,
            _ => Self::Internal,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Principal {
    pub id: String,
    pub kind: PrincipalKind,
    pub display_name: Option<String>,
    pub email: Option<String>,
    #[serde(default)]
    pub team_ids: Vec<String>,
    #[serde(default = "yes")]
    pub active: bool,
    pub created_at: String,
}

fn yes() -> bool {
    true
}

impl Principal {
    /// Name for prompts and the UI; falls back to the id so a display never
    /// renders empty.
    pub fn label(&self) -> &str {
        self.display_name
            .as_deref()
            .filter(|s| !s.trim().is_empty())
            .unwrap_or(&self.id)
    }

    pub fn scope(&self) -> ScopeId {
        ScopeId::personal(&self.id)
    }
}

// ---------------------------------------------------------------------------
// Scopes
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ScopeKind {
    Personal,
    Channel,
    Team,
    Org,
    Group,
}

impl ScopeKind {
    pub const ALL: [ScopeKind; 5] = [
        ScopeKind::Personal,
        ScopeKind::Channel,
        ScopeKind::Team,
        ScopeKind::Org,
        ScopeKind::Group,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Personal => "personal",
            Self::Channel => "channel",
            Self::Team => "team",
            Self::Org => "org",
            Self::Group => "group",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|k| k.as_str() == s)
    }
}

/// A scope id is `<kind>:<ref>` — `personal:u1`, `channel:eng`, `org:acme`.
///
/// Parsing is total: an unrecognised prefix yields `kind: None`, matching
/// upstream's `parseScopeId`, so a malformed id from an old row degrades to an
/// inert scope rather than panicking mid-turn.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ScopeId(String);

impl ScopeId {
    pub fn new(kind: ScopeKind, reference: &str) -> Self {
        Self(format!("{}:{}", kind.as_str(), reference))
    }

    pub fn personal(principal_id: &str) -> Self {
        Self::new(ScopeKind::Personal, principal_id)
    }

    pub fn org(org_id: &str) -> Self {
        Self::new(ScopeKind::Org, org_id)
    }

    pub fn channel(channel_ref: &str) -> Self {
        Self::new(ScopeKind::Channel, channel_ref)
    }

    /// Wrap an already-formatted id, e.g. one read back from the database.
    pub fn from_raw(raw: impl Into<String>) -> Self {
        Self(raw.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn kind(&self) -> Option<ScopeKind> {
        self.0
            .split_once(':')
            .and_then(|(k, _)| ScopeKind::parse(k))
    }

    pub fn reference(&self) -> &str {
        self.0.split_once(':').map(|(_, r)| r).unwrap_or("")
    }

    /// Channels and groups are shared: more than one principal reads and
    /// writes them, so entitlement is checked per audience member.
    pub fn is_shared(&self) -> bool {
        matches!(
            self.kind(),
            Some(ScopeKind::Channel) | Some(ScopeKind::Group)
        )
    }

    /// The principal who owns this scope outright, if any.
    pub fn owner(&self) -> Option<&str> {
        match self.kind() {
            Some(ScopeKind::Personal) => Some(self.reference()),
            _ => None,
        }
    }
}

impl fmt::Display for ScopeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// The empty scope: no kind, no ref, entitled to nothing. Exists so config
/// structs can derive `Default`; it is never a valid target for a turn.
impl Default for ScopeId {
    fn default() -> Self {
        Self(String::new())
    }
}

impl FromStr for ScopeId {
    type Err = std::convert::Infallible;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self(s.to_string()))
    }
}

impl Serialize for ScopeId {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for ScopeId {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        Ok(Self(String::deserialize(d)?))
    }
}

// ---------------------------------------------------------------------------
// Sessions and entries
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SessionType {
    Dm,
    Channel,
    Group,
}

impl SessionType {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Dm => "dm",
            Self::Channel => "channel",
            Self::Group => "group",
        }
    }

    pub fn parse(s: &str) -> Self {
        match s {
            "channel" => Self::Channel,
            "group" => Self::Group,
            _ => Self::Dm,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    pub id: String,
    #[serde(rename = "type")]
    pub session_type: SessionType,
    pub scope_id: ScopeId,
    pub thread_ref: String,
    pub surface: String,
    pub channel_name: Option<String>,
    pub title: Option<String>,
    pub archived: bool,
    pub pinned: bool,
    pub color: Option<String>,
    pub created_at: String,
    pub last_activity_at: String,
}

impl Session {
    /// What the sessions list shows before the model has titled the thread.
    pub fn display_title(&self) -> String {
        match self
            .title
            .as_deref()
            .map(str::trim)
            .filter(|t| !t.is_empty())
        {
            Some(t) => t.to_string(),
            None => match self.channel_name.as_deref() {
                Some(c) => format!("#{c}"),
                None => format!("{} · {}", self.surface, self.thread_ref),
            },
        }
    }
}

/// Entry types on the transcript. `Thinking` and `ToolCall`/`ToolResult` are
/// kept as first-class rows rather than folded into the assistant text so the
/// UI can render the work, and so a resumed turn can see what already ran.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EntryType {
    User,
    Assistant,
    Thinking,
    ToolCall,
    ToolResult,
    System,
    Delivery,
    ApprovalRequest,
    ApprovalResolved,
}

impl EntryType {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::User => "user",
            Self::Assistant => "assistant",
            Self::Thinking => "thinking",
            Self::ToolCall => "tool_call",
            Self::ToolResult => "tool_result",
            Self::System => "system",
            Self::Delivery => "delivery",
            Self::ApprovalRequest => "approval_request",
            Self::ApprovalResolved => "approval_resolved",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "user" => Self::User,
            "assistant" => Self::Assistant,
            "thinking" => Self::Thinking,
            "tool_call" => Self::ToolCall,
            "tool_result" => Self::ToolResult,
            "system" => Self::System,
            "delivery" => Self::Delivery,
            "approval_request" => Self::ApprovalRequest,
            "approval_resolved" => Self::ApprovalResolved,
            _ => return None,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionEntry {
    pub session_id: String,
    pub seq: i64,
    pub parent_seq: Option<i64>,
    #[serde(rename = "type")]
    pub entry_type: EntryType,
    pub payload: serde_json::Value,
    pub scope_label: ScopeId,
    pub created_at: String,
}

impl SessionEntry {
    /// `payload.text`, the field every text-bearing entry type carries.
    pub fn text(&self) -> &str {
        self.payload
            .get("text")
            .and_then(|v| v.as_str())
            .unwrap_or("")
    }

    pub fn author(&self) -> Option<&str> {
        self.payload.get("author").and_then(|v| v.as_str())
    }
}

/// An entry not yet assigned a sequence number.
#[derive(Debug, Clone)]
pub struct NewEntry {
    pub entry_type: EntryType,
    pub payload: serde_json::Value,
    pub parent_seq: Option<i64>,
    pub scope_label: ScopeId,
}

impl NewEntry {
    pub fn new(entry_type: EntryType, scope_label: ScopeId, payload: serde_json::Value) -> Self {
        Self {
            entry_type,
            payload,
            parent_seq: None,
            scope_label,
        }
    }

    pub fn text(entry_type: EntryType, scope_label: ScopeId, text: impl Into<String>) -> Self {
        Self::new(
            entry_type,
            scope_label,
            serde_json::json!({ "text": text.into() }),
        )
    }

    pub fn with_parent(mut self, parent_seq: i64) -> Self {
        self.parent_seq = Some(parent_seq);
        self
    }
}

// ---------------------------------------------------------------------------
// Workspace layers, grants, resolution
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LayerMode {
    Ro,
    Rw,
}

impl LayerMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ro => "ro",
            Self::Rw => "rw",
        }
    }
}

/// One scope's files mounted into the turn's workspace. Exactly one layer is
/// `Rw` — the scope the turn writes to.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkspaceLayer {
    pub scope_id: ScopeId,
    pub mount_path: String,
    pub mode: LayerMode,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Permission {
    Read,
    Write,
}

impl Permission {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Read => "read",
            Self::Write => "write",
        }
    }

    pub fn parse(s: &str) -> Self {
        match s {
            "write" => Self::Write,
            _ => Self::Read,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Grant {
    pub owner_scope_id: ScopeId,
    pub reference: String,
    pub grantee_scope_id: ScopeId,
    pub permission: Permission,
    pub granted_by: String,
    pub created_at: String,
}

/// A granted resource as the agent sees it: a path under `shared/`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GrantedHandle {
    pub handle_path: String,
    pub owner_scope_id: ScopeId,
    pub owner_path: String,
    pub permission: Permission,
}

// ---------------------------------------------------------------------------
// Turns
// ---------------------------------------------------------------------------

/// Where a turn came from. Drives whether the reply is delivered, whether the
/// actor may approve their own tool calls, and how history is labelled.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TurnOrigin {
    /// A person typed it.
    Human,
    /// A cron, watch or webhook fired it; nobody is waiting.
    Automation,
    /// An API caller drove it directly.
    Direct,
}

#[derive(Debug, Clone)]
pub struct TurnRequest {
    pub surface: String,
    pub actor: String,
    pub scope_id: ScopeId,
    pub thread_ref: String,
    pub session_type: SessionType,
    pub channel_name: Option<String>,
    pub text: String,
    pub origin: TurnOrigin,
    /// Additional principals who can read this thread. Used to filter history
    /// and granted handles down to what the whole audience may see.
    pub audience: Vec<String>,
    /// Resolve an outstanding approval instead of starting fresh work.
    pub approval: Option<ApprovalDecision>,
    pub model: Option<String>,
}

impl TurnRequest {
    pub fn new(
        surface: impl Into<String>,
        actor: impl Into<String>,
        scope_id: ScopeId,
        thread_ref: impl Into<String>,
        text: impl Into<String>,
    ) -> Self {
        Self {
            surface: surface.into(),
            actor: actor.into(),
            scope_id,
            thread_ref: thread_ref.into(),
            session_type: SessionType::Dm,
            channel_name: None,
            text: text.into(),
            origin: TurnOrigin::Human,
            audience: Vec::new(),
            approval: None,
            model: None,
        }
    }

    pub fn with_origin(mut self, origin: TurnOrigin) -> Self {
        self.origin = origin;
        self
    }

    pub fn with_session_type(mut self, session_type: SessionType) -> Self {
        self.session_type = session_type;
        self
    }

    pub fn with_audience(mut self, audience: Vec<String>) -> Self {
        self.audience = audience;
        self
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalScope {
    Once,
    Session,
    Always,
}

impl ApprovalScope {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Once => "once",
            Self::Session => "session",
            Self::Always => "always",
        }
    }

    pub fn parse(s: &str) -> Self {
        match s {
            "session" => Self::Session,
            "always" => Self::Always,
            _ => Self::Once,
        }
    }
}

#[derive(Debug, Clone)]
pub struct ApprovalDecision {
    pub request_id: String,
    pub approved: bool,
    pub scope: ApprovalScope,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingApproval {
    pub request_id: String,
    pub session_id: String,
    pub command: String,
    pub reason: String,
    pub matched: Option<String>,
    pub purpose: Option<String>,
    pub summary: Option<String>,
    pub approval_key: String,
    pub created_at: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TurnStatus {
    Ok,
    Refused,
    Failed,
    PendingApproval,
    Silent,
}

impl TurnStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::Refused => "refused",
            Self::Failed => "failed",
            Self::PendingApproval => "pending_approval",
            Self::Silent => "silent",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TurnResult {
    pub status: TurnStatus,
    pub session_id: String,
    pub reply: String,
    pub reason: Option<String>,
    #[serde(default)]
    pub pending_approvals: Vec<PendingApproval>,
    /// Model round-trips consumed. Surfaced so a runaway tool loop is visible.
    pub steps: u32,
}

impl TurnResult {
    pub fn ok(session_id: impl Into<String>, reply: impl Into<String>, steps: u32) -> Self {
        Self {
            status: TurnStatus::Ok,
            session_id: session_id.into(),
            reply: reply.into(),
            reason: None,
            pending_approvals: Vec::new(),
            steps,
        }
    }

    pub fn failed(session_id: impl Into<String>, reason: impl Into<String>) -> Self {
        let reason = reason.into();
        Self {
            status: TurnStatus::Failed,
            session_id: session_id.into(),
            reply: String::new(),
            reason: Some(reason),
            pending_approvals: Vec::new(),
            steps: 0,
        }
    }

    pub fn refused(session_id: impl Into<String>, reason: impl Into<String>) -> Self {
        Self {
            status: TurnStatus::Refused,
            session_id: session_id.into(),
            reply: String::new(),
            reason: Some(reason.into()),
            pending_approvals: Vec::new(),
            steps: 0,
        }
    }
}

// ---------------------------------------------------------------------------
// Deliveries
// ---------------------------------------------------------------------------

/// Where a reply goes when nobody is holding a request open — the cron case.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Destination {
    /// Surface name: `telegram`, `web`.
    #[serde(rename = "type")]
    pub kind: String,
    /// Surface-specific address: a Telegram chat id, a web thread ref.
    pub target: String,
    pub on_behalf_of: Option<String>,
}

impl Destination {
    pub fn new(kind: impl Into<String>, target: impl Into<String>) -> Self {
        Self {
            kind: kind.into(),
            target: target.into(),
            on_behalf_of: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeliveryProvenance {
    /// `cron` | `webhook` | `monitor`
    pub trigger: String,
    pub surface: String,
    pub fire_key: String,
    pub source_scope_id: ScopeId,
    pub source_thread_ref: String,
    pub source_session_id: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scope_ids_round_trip_through_kind_and_ref() {
        let s = ScopeId::personal("u1");
        assert_eq!(s.as_str(), "personal:u1");
        assert_eq!(s.kind(), Some(ScopeKind::Personal));
        assert_eq!(s.reference(), "u1");
        assert_eq!(s.owner(), Some("u1"));
        assert!(!s.is_shared());
    }

    #[test]
    fn channel_and_group_scopes_are_shared_and_unowned() {
        for s in [
            ScopeId::channel("eng"),
            ScopeId::new(ScopeKind::Group, "g1"),
        ] {
            assert!(s.is_shared(), "{s} should be shared");
            assert_eq!(s.owner(), None);
        }
        assert!(!ScopeId::org("acme").is_shared());
    }

    #[test]
    fn refs_containing_colons_keep_everything_after_the_first_one() {
        let s = ScopeId::from_raw("channel:team:sub");
        assert_eq!(s.kind(), Some(ScopeKind::Channel));
        assert_eq!(s.reference(), "team:sub");
    }

    #[test]
    fn malformed_scope_ids_parse_to_no_kind_rather_than_panicking() {
        let s = ScopeId::from_raw("nonsense");
        assert_eq!(s.kind(), None);
        assert_eq!(s.reference(), "");
        assert!(!s.is_shared());
        assert_eq!(s.owner(), None);

        let unknown = ScopeId::from_raw("wat:x");
        assert_eq!(unknown.kind(), None);
        assert_eq!(unknown.reference(), "x");
    }

    #[test]
    fn entry_types_round_trip_through_their_wire_names() {
        for t in [
            EntryType::User,
            EntryType::Assistant,
            EntryType::Thinking,
            EntryType::ToolCall,
            EntryType::ToolResult,
            EntryType::System,
            EntryType::Delivery,
            EntryType::ApprovalRequest,
            EntryType::ApprovalResolved,
        ] {
            assert_eq!(EntryType::parse(t.as_str()), Some(t));
        }
        assert_eq!(EntryType::parse("bogus"), None);
    }

    #[test]
    fn session_titles_fall_back_from_title_to_channel_to_thread() {
        let mut s = Session {
            id: "s1".into(),
            session_type: SessionType::Channel,
            scope_id: ScopeId::channel("eng"),
            thread_ref: "t1".into(),
            surface: "web".into(),
            channel_name: Some("eng".into()),
            title: Some("  ".into()),
            archived: false,
            pinned: false,
            color: None,
            created_at: "now".into(),
            last_activity_at: "now".into(),
        };
        assert_eq!(s.display_title(), "#eng");
        s.title = Some("Deploy plan".into());
        assert_eq!(s.display_title(), "Deploy plan");
        s.title = None;
        s.channel_name = None;
        assert_eq!(s.display_title(), "web · t1");
    }

    #[test]
    fn scope_id_serializes_as_a_plain_string() {
        let json = serde_json::to_string(&ScopeId::channel("eng")).unwrap();
        assert_eq!(json, "\"channel:eng\"");
        let back: ScopeId = serde_json::from_str(&json).unwrap();
        assert_eq!(back, ScopeId::channel("eng"));
    }
}
