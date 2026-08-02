-- Directory onboarding: groups, and connector bindings.
--
-- Shapes follow upstream QM's `DirectoryStore` rather than being invented here:
--
--   * A **group** is a set of participants, keyed by the sorted participant
--     list (upstream's `groupParticipantsKey`). That makes a multi-person
--     conversation resolve to the same group every time, whichever surface it
--     arrives on and whatever order the participants are listed in.
--   * Membership is **deactivation-based**, not invite-based: upstream's
--     identity service classifies anyone as internal unless explicitly
--     deactivated, because being in the workspace is the membership. Here the
--     admin plays the part the workspace sync plays there, so `principals`
--     already models it and there is deliberately no `invites` table — an
--     invited person *is* a principal with an email address.
--
-- What differs: upstream syncs the directory wholesale from Slack. A web-first
-- deployment has no workspace to sync from, so the admin curates it, and the
-- connector bindings below let an external account or conversation be attached
-- to a directory entry that already exists.

-- ---------------------------------------------------------------------------
-- Groups
-- ---------------------------------------------------------------------------

CREATE TABLE directory_groups (
    id              TEXT PRIMARY KEY,          -- the ref half of `group:<id>`
    name            TEXT NOT NULL,
    -- Sorted, deduped, comma-joined participant ids. Upstream resolves a
    -- multi-person conversation to a group by exactly this key.
    participant_key TEXT NOT NULL,
    created_by      TEXT NOT NULL,
    created_at      TEXT NOT NULL
);

CREATE UNIQUE INDEX directory_groups_participants ON directory_groups(participant_key);

CREATE TABLE directory_group_members (
    group_id     TEXT NOT NULL REFERENCES directory_groups(id) ON DELETE CASCADE,
    principal_id TEXT NOT NULL REFERENCES principals(id) ON DELETE CASCADE,
    PRIMARY KEY (group_id, principal_id)
);

CREATE INDEX directory_group_members_principal ON directory_group_members(principal_id);

-- ---------------------------------------------------------------------------
-- Connector identities: an external account is this principal.
-- ---------------------------------------------------------------------------
--
-- Upstream carries this as `DirectoryMember.slackId`, populated by the
-- workspace sync. Curated here instead, and per-surface so one person can hold
-- a Slack account and a Telegram account at once.

CREATE TABLE connector_identities (
    surface      TEXT NOT NULL,               -- telegram | slack
    external_id  TEXT NOT NULL,               -- the platform's user id
    principal_id TEXT NOT NULL REFERENCES principals(id) ON DELETE CASCADE,
    label        TEXT,                        -- @handle, for the admin listing
    linked_by    TEXT NOT NULL,
    created_at   TEXT NOT NULL,
    PRIMARY KEY (surface, external_id)
);

CREATE INDEX connector_identities_principal ON connector_identities(principal_id);

-- ---------------------------------------------------------------------------
-- Connector conversations: an external chat is this scope.
-- ---------------------------------------------------------------------------
--
-- Without a binding a connector derives a scope from the chat id
-- (`channel:tg-<chat_id>`). A binding points that conversation at a group or
-- channel the admin already made, so a Telegram group, a Slack channel and the
-- web UI can share one scope — one memory, one set of files.

CREATE TABLE connector_channels (
    surface     TEXT NOT NULL,                -- telegram | slack
    external_id TEXT NOT NULL,                -- chat id / channel id
    scope_id    TEXT NOT NULL,                -- a full scope id, e.g. `group:ops`
    label       TEXT,
    linked_by   TEXT NOT NULL,
    created_at  TEXT NOT NULL,
    PRIMARY KEY (surface, external_id)
);

CREATE INDEX connector_channels_scope ON connector_channels(scope_id);
