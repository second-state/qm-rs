-- Web sign-in, API keys, and Slack event bookkeeping.
--
-- Every credential in here is stored as a SHA-256 hash of the value, never the
-- value itself. Read access to this database therefore does not hand an
-- attacker a live session or a usable API key — it is the same reason the
-- skills table stores a signature rather than trusting its own rows.

-- ---------------------------------------------------------------------------
-- Sign-in
-- ---------------------------------------------------------------------------

-- A browser session, keyed by the hash of the cookie value.
CREATE TABLE auth_sessions (
    token_hash   TEXT PRIMARY KEY,
    principal_id TEXT NOT NULL,
    created_at   TEXT NOT NULL,
    expires_at   TEXT NOT NULL,
    last_seen_at TEXT NOT NULL,
    user_agent   TEXT
);

CREATE INDEX auth_sessions_principal ON auth_sessions(principal_id, expires_at);

-- A one-time magic link. `consumed_at` makes it single-use: a link that leaks
-- from an inbox or a proxy log is worthless once it has been followed.
CREATE TABLE auth_login_tokens (
    token_hash   TEXT PRIMARY KEY,
    email        TEXT NOT NULL,
    principal_id TEXT NOT NULL,
    created_at   TEXT NOT NULL,
    expires_at   TEXT NOT NULL,
    consumed_at  TEXT
);

CREATE INDEX auth_login_tokens_email ON auth_login_tokens(email, created_at DESC);

-- ---------------------------------------------------------------------------
-- API keys
-- ---------------------------------------------------------------------------

CREATE TABLE api_keys (
    id           TEXT PRIMARY KEY,
    key_hash     TEXT NOT NULL UNIQUE,
    -- The leading characters, kept so a listing can identify a key without
    -- being able to reconstruct it.
    prefix       TEXT NOT NULL,
    principal_id TEXT NOT NULL,
    name         TEXT,
    created_at   TEXT NOT NULL,
    last_used_at TEXT,
    revoked_at   TEXT
);

CREATE INDEX api_keys_principal ON api_keys(principal_id, revoked_at);

-- ---------------------------------------------------------------------------
-- Slack
-- ---------------------------------------------------------------------------

-- Slack redelivers an event when an ack is slow or lost, and Socket Mode can
-- redeliver on reconnect. One row per event id means a retry is a no-op rather
-- than a second turn.
CREATE TABLE slack_event_dedupe (
    event_id TEXT PRIMARY KEY,
    seen_at  TEXT NOT NULL
);

CREATE INDEX slack_event_dedupe_seen ON slack_event_dedupe(seen_at);
