-- qm-rs initial schema.
--
-- Ported from QM's Postgres persistence layer onto local SQLite. Table and
-- column names follow the upstream names where they exist (sessions,
-- session_entries, participants, acl_grants, memory_revisions, file_artifacts,
-- audit_log, deliveries) so the two schemas stay recognisably the same shape.
--
-- Conventions in this file:
--   * timestamps are RFC3339 UTC strings ('2026-08-01T09:00:00Z'), written by
--     db::now_rfc3339 or SQLite's strftime, so ORDER BY is lexicographic;
--   * anything QM stores as JSONB is a TEXT column holding JSON;
--   * booleans are INTEGER 0/1.

-- ---------------------------------------------------------------------------
-- Identity: principals and the channel directory
-- ---------------------------------------------------------------------------

CREATE TABLE principals (
    id           TEXT PRIMARY KEY,
    kind         TEXT NOT NULL DEFAULT 'internal',   -- internal | guest
    display_name TEXT,
    email        TEXT,
    team_ids     TEXT NOT NULL DEFAULT '[]',         -- JSON array
    active       INTEGER NOT NULL DEFAULT 1,
    created_at   TEXT NOT NULL
);

CREATE TABLE directory_channels (
    id         TEXT PRIMARY KEY,
    name       TEXT NOT NULL,
    kind       TEXT NOT NULL DEFAULT 'channel',      -- channel | group
    is_private INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL
);

CREATE TABLE directory_channel_members (
    channel_id   TEXT NOT NULL REFERENCES directory_channels(id) ON DELETE CASCADE,
    principal_id TEXT NOT NULL REFERENCES principals(id) ON DELETE CASCADE,
    PRIMARY KEY (channel_id, principal_id)
);

-- ---------------------------------------------------------------------------
-- Scopes: the unit QM resolves configuration, memory, skills and files against.
-- A scope id is '<kind>:<ref>' — personal:u1, channel:eng, org:acme.
-- Rows exist only for scopes carrying non-default configuration; resolution
-- falls back to the org floor for scopes with no row.
-- ---------------------------------------------------------------------------

CREATE TABLE scopes (
    id               TEXT PRIMARY KEY,               -- 'personal:u1'
    kind             TEXT NOT NULL,                  -- personal|channel|team|org|group
    ref              TEXT NOT NULL,
    title            TEXT,
    security_posture TEXT,                           -- strict|auto|dangerous (null = inherit)
    command_policy   TEXT,                           -- JSON CommandPolicy (null = inherit)
    memory_recall    TEXT,                           -- off|writable|visible
    memory_capture   TEXT,                           -- off|writable
    system_prompt    TEXT,                           -- appended to the org prompt
    created_at       TEXT NOT NULL
);

-- Org-level settings and other single-value state (connector cursors, etc).
CREATE TABLE settings (
    key        TEXT PRIMARY KEY,
    value      TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

-- ---------------------------------------------------------------------------
-- Sessions and the append-only entry log
-- ---------------------------------------------------------------------------

CREATE TABLE sessions (
    id               TEXT PRIMARY KEY,
    type             TEXT NOT NULL,                  -- dm | channel | group
    scope_id         TEXT NOT NULL,
    thread_ref       TEXT NOT NULL,
    surface          TEXT NOT NULL DEFAULT 'web',    -- web | telegram | cron | api
    channel_name     TEXT,
    title            TEXT,
    archived         INTEGER NOT NULL DEFAULT 0,
    pinned           INTEGER NOT NULL DEFAULT 0,
    color            TEXT,
    created_at       TEXT NOT NULL,
    last_activity_at TEXT NOT NULL
);

CREATE UNIQUE INDEX sessions_surface_thread ON sessions(surface, thread_ref);
CREATE INDEX sessions_scope ON sessions(scope_id, last_activity_at DESC);

-- The transcript. `seq` is per-session and dense; `parent_seq` links a
-- tool_result back to the tool_call that produced it.
CREATE TABLE session_entries (
    session_id  TEXT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    seq         INTEGER NOT NULL,
    parent_seq  INTEGER,
    type        TEXT NOT NULL,                       -- user|assistant|thinking|tool_call|
                                                     -- tool_result|system|delivery|
                                                     -- approval_request|approval_resolved
    payload     TEXT NOT NULL,                       -- JSON
    scope_label TEXT NOT NULL,
    created_at  TEXT NOT NULL,
    PRIMARY KEY (session_id, seq)
);

CREATE INDEX session_entries_created ON session_entries(session_id, created_at);

CREATE TABLE participants (
    session_id   TEXT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    principal_id TEXT NOT NULL,
    joined_at    TEXT NOT NULL,
    PRIMARY KEY (session_id, principal_id)
);

-- ---------------------------------------------------------------------------
-- Memory: one notebook per scope, with a revision history.
-- ---------------------------------------------------------------------------

CREATE TABLE memory_docs (
    scope_id   TEXT PRIMARY KEY,
    content    TEXT NOT NULL,
    revision   TEXT NOT NULL,                        -- sha256 of content
    updated_at TEXT NOT NULL
);

CREATE TABLE memory_revisions (
    id        TEXT PRIMARY KEY,
    scope_id  TEXT NOT NULL,
    revision  TEXT NOT NULL,
    content   TEXT NOT NULL,
    operation TEXT NOT NULL,                         -- capture | replace | restore
    author    TEXT,
    at        TEXT NOT NULL
);

CREATE INDEX memory_revisions_scope ON memory_revisions(scope_id, at DESC);

-- ---------------------------------------------------------------------------
-- Skills: scope-owned, signed, shareable by grant.
-- ---------------------------------------------------------------------------

CREATE TABLE skills (
    id                    TEXT PRIMARY KEY,
    scope_id              TEXT NOT NULL,
    name                  TEXT NOT NULL,
    description           TEXT NOT NULL DEFAULT '',
    required_capabilities TEXT NOT NULL DEFAULT '[]',
    body                  TEXT NOT NULL DEFAULT '',
    files                 TEXT NOT NULL DEFAULT '[]',
    signature             TEXT NOT NULL,
    status                TEXT NOT NULL DEFAULT 'draft',  -- draft|reviewed|published|archived
    created_by            TEXT NOT NULL,
    version               INTEGER NOT NULL DEFAULT 1,
    granted_capabilities  TEXT NOT NULL DEFAULT '[]',
    approvals             TEXT NOT NULL DEFAULT '[]',
    created_at            TEXT NOT NULL,
    updated_at            TEXT NOT NULL,
    last_used_at          TEXT
);

CREATE UNIQUE INDEX skills_scope_name ON skills(scope_id, name);

-- ---------------------------------------------------------------------------
-- ACL: a grant makes one scope's resource reachable from another scope.
-- `ref` is a resource ref — 'file:notes/plan.md', 'skill:triage', 'cron:<id>'.
-- ---------------------------------------------------------------------------

CREATE TABLE acl_grants (
    owner_scope_id   TEXT NOT NULL,
    ref              TEXT NOT NULL,
    grantee_scope_id TEXT NOT NULL,
    permission       TEXT NOT NULL,                  -- read | write
    granted_by       TEXT NOT NULL,
    created_at       TEXT NOT NULL,
    PRIMARY KEY (owner_scope_id, ref, grantee_scope_id)
);

CREATE INDEX acl_grants_grantee ON acl_grants(grantee_scope_id);

-- ---------------------------------------------------------------------------
-- Crons: background work that runs while nobody is watching.
-- ---------------------------------------------------------------------------

CREATE TABLE crons (
    id             TEXT PRIMARY KEY,
    owner_scope_id TEXT NOT NULL,
    owner          TEXT NOT NULL,
    created_by     TEXT NOT NULL,
    title          TEXT,
    message        TEXT NOT NULL DEFAULT '',
    schedule       TEXT NOT NULL,                    -- JSON CronSchedule
    next_fire_at   TEXT,
    enabled        INTEGER NOT NULL DEFAULT 1,
    archived       INTEGER NOT NULL DEFAULT 0,
    run_as         TEXT NOT NULL DEFAULT 'owner',    -- owner | scopeShared
    destination    TEXT,                             -- JSON Destination
    created_at     TEXT NOT NULL,
    last_fired_at  TEXT
);

CREATE INDEX crons_due ON crons(enabled, archived, next_fire_at);

CREATE TABLE cron_fires (
    id           TEXT PRIMARY KEY,
    cron_id      TEXT NOT NULL REFERENCES crons(id) ON DELETE CASCADE,
    fire_key     TEXT NOT NULL,
    thread_ref   TEXT NOT NULL,
    fired_at     TEXT NOT NULL,
    scheduled_at TEXT,
    status       TEXT,
    note         TEXT,
    reply        TEXT,
    session_id   TEXT
);

-- One row per (cron, scheduled instant): the idempotency guard that stops a
-- restart or a double scheduler tick from firing the same instant twice.
CREATE UNIQUE INDEX cron_fires_key ON cron_fires(cron_id, fire_key);
CREATE INDEX cron_fires_recent ON cron_fires(cron_id, fired_at DESC);

-- ---------------------------------------------------------------------------
-- Files: durable artifacts owned by a scope.
-- ---------------------------------------------------------------------------

CREATE TABLE file_artifacts (
    id         TEXT PRIMARY KEY,
    scope_id   TEXT NOT NULL,
    name       TEXT NOT NULL,
    mimetype   TEXT NOT NULL DEFAULT 'application/octet-stream',
    size_bytes INTEGER NOT NULL DEFAULT 0,
    data       BLOB NOT NULL,
    direction  TEXT NOT NULL DEFAULT 'out',          -- in | out
    author     TEXT,
    created_at TEXT NOT NULL
);

CREATE INDEX file_artifacts_scope ON file_artifacts(scope_id, created_at DESC);

-- ---------------------------------------------------------------------------
-- Keychain: per-scope credentials materialized into the sandbox environment.
-- Values are stored as written; the DB file is the trust boundary (see
-- KNOWLEDGE.md → "Keychain and the trust boundary").
-- ---------------------------------------------------------------------------

CREATE TABLE keychain (
    scope_id    TEXT NOT NULL,
    key         TEXT NOT NULL,
    value       TEXT NOT NULL,
    description TEXT,
    created_by  TEXT NOT NULL,
    created_at  TEXT NOT NULL,
    PRIMARY KEY (scope_id, key)
);

-- ---------------------------------------------------------------------------
-- Approvals: a paused tool call awaiting a human, plus standing grants.
-- ---------------------------------------------------------------------------

CREATE TABLE pending_approvals (
    request_id   TEXT PRIMARY KEY,
    session_id   TEXT NOT NULL,
    command      TEXT NOT NULL,
    reason       TEXT NOT NULL DEFAULT '',
    matched      TEXT,
    purpose      TEXT,
    summary      TEXT,
    approval_key TEXT NOT NULL,
    created_at   TEXT NOT NULL,
    resolved_at  TEXT,
    approved     INTEGER
);

CREATE INDEX pending_approvals_session ON pending_approvals(session_id, resolved_at);

-- `session_id` is '' rather than NULL for an org-wide ("always") grant:
-- SQLite prohibits expressions in a PRIMARY KEY, so it cannot be
-- COALESCE'd into the key, and a NULL would make the key non-unique.
CREATE TABLE command_approval_grants (
    actor_id     TEXT NOT NULL,
    approval_key TEXT NOT NULL,
    grant_scope  TEXT NOT NULL,                      -- session | always
    session_id   TEXT NOT NULL DEFAULT '',
    command      TEXT NOT NULL,
    created_at   TEXT NOT NULL,
    PRIMARY KEY (actor_id, approval_key, grant_scope, session_id)
);

-- ---------------------------------------------------------------------------
-- Deliveries: outbound messages, idempotent per (destination, fire).
-- ---------------------------------------------------------------------------

CREATE TABLE deliveries (
    id              TEXT PRIMARY KEY,
    destination     TEXT NOT NULL,                   -- JSON Destination
    text            TEXT NOT NULL,
    provenance      TEXT,                            -- JSON DeliveryProvenance
    idempotency_key TEXT NOT NULL UNIQUE,
    created_at      TEXT NOT NULL,
    delivered_at    TEXT,
    error           TEXT
);

-- ---------------------------------------------------------------------------
-- Audit: every consequential action, durable by default.
-- ---------------------------------------------------------------------------

CREATE TABLE audit_log (
    id       TEXT PRIMARY KEY,
    at       TEXT NOT NULL,
    actor    TEXT NOT NULL,
    action   TEXT NOT NULL,
    scope_id TEXT,
    target   TEXT,
    detail   TEXT,                                   -- JSON
    ok       INTEGER NOT NULL DEFAULT 1
);

CREATE INDEX audit_log_at ON audit_log(at DESC);
CREATE INDEX audit_log_scope ON audit_log(scope_id, at DESC);
