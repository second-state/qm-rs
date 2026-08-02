# KNOWLEDGE

Design rationale for qm-rs. `README.md` is the user-facing doc; this file is
why things are the way they are, and what is deliberately not solved.

## The port's shape

Upstream QM is a TypeScript core with Postgres, four plugin packages, a CLI,
and adapters for four agent harnesses. This port keeps the **architecture** and
drops the periphery. What survived is the part that makes QM QM: scopes as the
unit of ownership, one orchestrator every surface flows through, an org floor
that narrower scopes can only tighten, and a small fixed tool surface with
`execute` at its centre.

The substrates that a deployment might reasonably swap sit behind traits —
`Harness`, `Sandbox`, `PluginHost`. The stores are concrete SQLite structs
instead, because a trait per store would be ceremony for one implementation;
they take a pool and can be swapped wholesale by rewriting `store/`.

## Versioned schema migrations

`sql/migrations/NNNN_<what>.sql` files are `include_str!`'d into
`db::MIGRATIONS`, applied in order, each in its own transaction, tracked in
`schema_migrations`.

Why files plus a registry rather than a directory scan: the binary must carry
its schema, so a deployment is one file plus `templates/`. Why a registry
rather than pure `include_str!` inference: the order is explicit and reviewable,
and `cargo test` asserts it stays ordered and unique.

**Never edit an applied migration.** A migration that has run somewhere is
history; changing it makes two databases claiming the same version structurally
different.

`/admin` renders applied against registered, so drift is visible without a
shell.

### SQLite constraints worth knowing

* **Expressions are prohibited in `PRIMARY KEY`.** `command_approval_grants`
  wanted `COALESCE(session_id, '')` in its key; instead `session_id` is
  `NOT NULL DEFAULT ''` and an org-wide grant stores `''`. A nullable column
  in the key would have made it non-unique, because `NULL != NULL`.
* **WAL is set once before the pool spins up.** Two connections racing on the
  journal-mode change of a fresh database both fail with "database is locked".
  `busy_timeout` is set *first* in the connection customizer for the same
  reason.

## Sequence numbers under concurrency

`session_entries.seq` is dense and per-session. `SessionStore::append` reads
`MAX(seq)+1` and inserts inside one `IMMEDIATE` transaction, so two concurrent
turns on the same session cannot be handed the same number. A deferred
transaction would let both read the same max before either writes.

## The command policy

Ported from upstream's `command-policy.ts`, with one deliberate improvement.

Rules match a **normalized** command, not the raw string, so quoting cannot
smuggle a flag past a rule:

```
rm '-rf' /x   →  rm -rf /x
rm \-rf /x    →  rm -rf /x
sh -c 'rm -rf /x'  →  the payload is appended and scanned too
```

Nesting is bounded at depth 8, so a pathological `sh -c "sh -c \"...\""` chain
terminates.

### Where this differs from upstream

Upstream replaces any quoted string that is not a bare word with `''`. That
keeps `echo 'notes about mkfs and disks'` inert — good — but it also erases
`psql -c 'DROP TABLE users'`, so the destructive-SQL rule can essentially never
fire.

Here, quoted arguments are still dropped **except** for a known list of
interpreters and database clients (`CODE_ARG_BINARIES`: shells, `psql`,
`mysql`, `sqlite3`, `python`, `node`, …). For those, quoted arguments are code
and are scanned. Both properties hold:

```
echo 'notes about mkfs'      → allowed
psql -c 'DROP TABLE users'   → approval
sqlite3 app.db 'DROP TABLE x' → approval
```

### Deny is final

Rules are scanned in order and the last match wins, so a scope rule appended
after the org floor can escalate. But a `deny` anywhere in the composed policy
wins outright — a scope cannot append an `allow` that overrides the floor's
`mkfs` denial. `compose_policy` also refuses to let a scope turn an allowlist
floor into a denylist.

### Approval keys are per-rule, not per-command

`rule:<index>:<pattern>`. Approving "always" for `rm -rf build` covers
`rm -rf dist` too, because the human approved the *class*. Keying on the exact
string would make "always" almost useless and train people to approve blindly.

## Security postures and screening

`Ord` on `SecurityPosture` is the ranking (`Dangerous < Auto < Strict`), so
composition is a `max` and a scope can only tighten. An unrecognised posture
string parses to `None`, which *inherits* — a typo must never widen the org's
posture.

Screening fails closed everywhere:

* an unparseable model verdict → `strict`;
* a plugin screener that traps or returns anything but `auto` → `strict`;
* a screener that is *unreachable* → an `unscreened` verdict, and the content
  is prefixed with an explicit "this was NOT security-screened" marker rather
  than passed off as clean. Silence and safety must not look the same.

`first_json_object` scans for a balanced `{...}` ignoring braces inside
strings, because models wrap JSON in prose and code fences.

## Memory

The notebook grammar lives in `src/memory.rs`; persistence in
`src/store/memory.rs`. Keeping them apart means the fold/dedupe/cap rules are
testable without a database, which is most of what there is to get wrong.

### Untrusted provenance

A fact the agent concluded itself is trusted. A fact repeated from a web page,
a tool result, or another person's message is not, and it is *declawed* before
it lands:

```
(2020-01-01) was hired in 2020     →  on 2020-01-01: was hired in 2020
key rotated (said in #ops)         →  key rotated [claimed source: #ops]
```

Only the capture path stamps a real `(YYYY-MM-DD)`. That is what keeps "when
did I learn this" trustworthy: nothing else can write that prefix.

### Revisions are content-addressed

`revision = sha256(content)`. Two writers producing identical content converge
on the same token, so a redundant write is a no-op rather than a spurious
conflict. The web editor compare-and-swaps on the revision it loaded; a stale
one is reported, never silently overwritten.

### The cap keeps the tail

Recall is capped at 6000 characters and the notebook at 300 facts. Both keep
the **tail** — recent context beats old context. `cap_tail` splits on character
boundaries, so a multi-byte notebook does not panic.

## Skills are signed

`HMAC-SHA256` over a canonical encoding of `(scope, name, description, sorted
capabilities, body, sorted files)`, with `\x1f`/`\x1e` separators so text
cannot be moved across a field boundary without changing the signature.

The signing secret is generated once and **persisted in `settings`**.
Regenerating it per boot would invalidate every stored signature, silently
hiding every published skill after a restart — a failure mode that looks like
data loss.

A skill whose signature no longer verifies is **hidden from turns**, not
executed. Skill bodies are instructions to a model; a database-level attacker
who can rewrite one owns the agent otherwise.

Granting a capability updates a separate column and does not re-sign, so the
manifest signature stays valid while permissions change independently.

## Granted file handles

A grant on `file:notes/plan.md` surfaces to the agent as `shared/plan.md`.
Upstream derives that path from the basename alone, so two grants with the same
basename both mount at `shared/plan.md` and the second silently shadows the
first — the agent reads the wrong scope's file.

Here, a collision falls back to `shared/<owner>-<basename>` and then to the
full owner path, which is unique by definition.

## Approvals are durable

A paused tool call is a row in `pending_approvals`, plus an `approval_request`
entry on the transcript. A pause therefore survives a restart, which the
in-memory alternative would not.

`resolve` is a conditional update (`WHERE resolved_at IS NULL`) returning
whether it changed a row, so a double-click cannot approve twice. Resuming
checks that the approval belongs to the session being resumed, so a guessed
request id is not usable from elsewhere.

The **original question** is recovered from the last `user` entry rather than
duplicated into the approval row. One source of truth beats two that can drift.

## Crons fire exactly once

The unique index on `(cron_id, fire_key)` where `fire_key` is the scheduled
instant is the whole mechanism. `claim_fire` inserts with
`ON CONFLICT DO NOTHING` and reports whether it won. A second scheduler tick,
or a restart mid-fire, claims nothing.

The schedule advances **whatever the outcome** — failure, refusal, or a pause
waiting on a human. A cron that failed must still run tomorrow, and an
unattended cron waiting for approval must not block its own schedule.

`max_catchup_secs` skips a fire that is further behind than the window, still
advancing the schedule. Without it, a server that was down for a week fires
seven days of backlog at once.

Re-enabling a disabled cron re-arms from *now*, for the same reason.

Every fire of one cron shares a thread (`cron:<id>`), so the agent sees what it
said last time.

### The cron parser

Hand-written, 5-field, with the standard day-of-month/day-of-week OR semantics
(when both are restricted, either matches; otherwise both must). Timezones go
through `chrono-tz`.

DST is handled explicitly:

* **ambiguous** (fall-back, the hour that happens twice) → the earlier instant,
  so a daily job runs once rather than twice;
* **nonexistent** (spring-forward, the hour that is skipped) → the candidate is
  rejected and the search moves on, so a 02:30 job skips that day rather than
  silently shifting an hour.

The search bound is 4 years, which covers every Feb-29 rule.

## The sandbox

Confinement, not isolation. Commands run as the server's own user in a
per-scope directory. This is the same trade upstream makes for its *local*
sandbox backend; its cloud backends (Fly machines, AWS microVMs) are what
provide real isolation, and they are not ported. **This is why the command
policy is not optional.**

What is enforced:

* `..` and absolute paths are rejected before touching the filesystem;
* the resolved path is then checked against the canonicalized root, which
  catches a **symlink** planted by an earlier turn pointing out of the sandbox;
* scope directory names are sanitized, so a crafted scope ref like
  `personal:../../etc` cannot climb out of the sandbox root;
* `env_clear()` — the server's own environment does not leak into a scope.
  Only the materialized keychain, plus `HOME`/`PATH`/`PWD`/`QM_SCOPE`.

Output is capped keeping the **tail**: errors land at the end of a command's
output far more often than the start.

## Keychain and the trust boundary

Values are stored in the SQLite file as written — not encrypted at rest. The
database file **is** the trust boundary: anyone who can read it can read the
secrets, exactly as anyone who can read it can rewrite a skill.

That is a deliberate scoping decision, not an oversight. Encrypting at rest
without a key-management story (an OS keychain, a KMS, an operator-supplied
passphrase) moves the secret rather than protecting it. What is done instead:

* values are never rendered — the UI shows metadata only;
* values never reach the audit log or any tracing field;
* `Debug` is hand-written for the types holding credentials
  (`OpenAiHarness`, `TelegramConnector`) so a panic or a log line cannot print
  a key;
* keys are validated as shell-safe identifiers, since they become environment
  variable names.

Run the database on a filesystem you would put an `.env` file on.

## The harness seam

`Harness` has two methods: `run_turn` (drives the model and the tool loop) and
`one_shot` (the utility calls — titles, screening). The tool loop lives in the
harness because different providers structure it differently; the *tools*
live outside it, in `ToolContext`, because they are the same everywhere.

`one_shot` returns `Option<String>`. `None` means "unavailable", which callers
must handle explicitly — that is what makes the unscreened path visible rather
than looking like a clean verdict.

History is rendered as plain conversation turns rather than replayed as real
tool messages: replaying `tool_call`/`tool_result` pairs needs the exact call
ids the provider issued, which are not durable across turns. Tool traffic folds
into `[called execute]` / `[tool result] …` notes instead. `thinking` and
approval rows never reach the next prompt.

## The mock harness earns its place

It is not a stub. It drives the real tool surface from directives in the
message text, which is what lets `tests/smoke_test.sh` exercise the entire
pipeline — dispatch, policy, approvals, entry emission, persistence — with no
network and no credentials. Every security property in this document is
verified against a running server that way.

## Plugins: why extension points and not surfaces

Upstream calls two different things "plugins":

* **surfaces** (Slack, web UI, admin, portal) — whole applications holding
  long-lived sockets, timers and OAuth state;
* **deployment extension points** (`BrokeredLayerTool`, the pluggable
  screener, policy hooks) — pure functions over bytes.

WasmEdge fits the second and not the first. A Wasm module is a function; making
it hold a socket means hand-writing a host-import surface for every syscall it
needs. So the web UI and the Telegram connector are native in-process Rust, and
Wasm runs the three hooks where the shape actually matches.

The ABI is `cloud_ai_gateway`'s (`allocate` / `run`, packed
`(ptr << 32) | len`), so modules and authoring tooling carry across the two
projects.

Each call gets a **fresh store and instance**. That costs an instantiation per
call and buys the property that matters for a multi-tenant agent: one scope's
call cannot observe or corrupt another's module state.

A module that fails is logged and skipped — middleware is an extension point,
not a gate. The one exception is `screen`, which fails closed.

Without the `wasm` feature, configured modules are reported as **inert** on
`/admin` rather than silently ignored: an operator who configured their own
screener and got a build without WasmEdge is falling back to the model
screener, and needs to know.

## Templates and assets

CSS and JS are Tera templates served from `/assets/*` by `render_css` /
`render_js`. There is no static directory and no build step; deployment is the
binary plus `templates/`.

Tera auto-escapes HTML, including `/` as `&#x2F;`. That is correct and worth
remembering when grepping rendered output in a test.

A unit test asserts every template the router renders actually parses, so a
missing `{% endblock %}` fails at `cargo test` rather than on the first request
to that page.

## Sign-in

### Nothing replayable is stored

Session cookies, magic links and API keys are 256-bit random values shown to
the holder exactly once and stored **only as a SHA-256 hash**. Read access to
the database therefore does not yield a live credential — the same reasoning
that makes the skills table store a signature rather than trusting its own
rows.

`OsRng`, not a seeded generator: these are credentials, and a predictable one
is a session anyone can mint.

### The allowlist defaults to closed

With no `admin_email`, `allowed_emails` or `allowed_domains`, **nobody** can
sign in, and the server warns at boot. Defaulting to "anyone with an email
address" would make a public deployment an open door; the safe reading is the
one that requires an explicit decision.

Domain rules match exactly, never as a suffix — `acme.test` does not admit
`x@evil-acme.test`.

### The admin's email is attached at boot

`[auth].admin_email` is written onto the `[org].admin` principal on first boot.
Without that, sign-in — which resolves an address to a principal *by email* —
would not find the boot-created admin, and would mint a second principal
(`ada-2`). The configured admin could then never actually be the admin. This
was a real bug, caught by the smoke test.

### The login form is not an oracle

An address that may not sign in gets the same response as one that may: the
same redirect, the same page. Distinguishing them would turn the form into a
membership oracle for the organization. Delivery failures are logged, never
shown.

Requests are rate-limited per address, so the form cannot be used to mail-bomb
someone who *is* allowed to sign in.

### One use, enforced by the database

`consume_login_token` is a conditional `UPDATE ... WHERE consumed_at IS NULL
AND expires_at > now` that reports whether it changed a row. Following the same
link twice — or racing two tabs — yields exactly one session.

### Keys cannot mint keys

Creating an API key requires a browser session. A key that could mint further
keys would turn one leak into permanent access that revoking the original does
not undo.

### The extractor is the enforcement point

`CurrentUser` is an axum extractor that every page and API handler takes as an
argument. A handler cannot forget to authenticate, because it will not compile
without one. Page requests reject to a login redirect carrying `next`; API
requests reject with 401. `next` is validated as a local path, or the login
form becomes an open redirect.

The API used to take its actor from the request body. It no longer does — the
actor is the authenticated principal, and only the org admin may override it,
which is audited.

## Slack

### Two transports, one path through

Socket Mode is the default because it matches the property the Telegram
connector already has: outbound only, no public URL, no inbound port. The
Events API path exists for deployments that already terminate HTTPS.

Both converge on `handle_and_reply`, so routing, dedupe and posting cannot
drift between them.

### Deciding and posting are separate

`handle_event` decides *what* to say and returns it; `handle_and_reply` posts
it. This is not merely tidy: it makes the whole filtering, routing and dedupe
path testable with no network round trip, and it stops a delivery failure being
mistaken for a turn failure. The first version did not split them, and the
tests silently reached out to `slack.com`.

### Signature verification

HMAC-SHA256 over `v0:<timestamp>:<body>` with the app signing secret, compared
in constant time, plus a five-minute age bound. Both halves matter: the HMAC
proves Slack sent it, the timestamp stops a captured request being replayed.
Nothing in the body is parsed until it verifies.

### Ack first, work later

Slack retries anything unacked within three seconds, and a turn takes longer.
So the connector acks immediately and does the work after — which is only safe
because of the dedupe table. `slack_event_dedupe` claims each event id with
`ON CONFLICT DO NOTHING`, exactly like `cron_fires`.

### A thread is a session

A channel maps to one scope but each Slack thread maps to its own session, so
two conversations in the same channel do not interleave into one transcript.

## What live testing caught

The mock harness proves the pipeline works. It cannot prove a real model can
*drive* it, because the mock is told exactly which tool to call. Two things
only showed up against a live model:

### A tool that erred on a recoverable ambiguity

Asked to schedule "09:00 every weekday", the model called `cron` with both a
`cron` expression and an `every_secs` interval. `normalize` correctly refuses
that — but the tool bounced the error back, the model produced identical
arguments, and the turn burned its entire 12-step budget without scheduling
anything.

Two fixes, both needed. The schema now states the exclusivity where the model
reads it, and the tool resolves the ambiguity rather than erroring: a cron
expression is the more specific statement of intent, so it wins and the
redundant interval is dropped. An error a model cannot act on is a bug in the
tool, not in the model.

The general rule: **a tool result that a model will answer identically is a
loop, not a message.** Prefer resolving an ambiguity deterministically over
returning an error the caller cannot fix.

### A journey asserting something the app correctly refuses

The browser journey opened a session in `channel:eng` and failed — because the
scope picker only offers scopes the signed-in principal can actually reach, and
Ada is not a member of that channel. The app was right; the test was wrong. It
now uses `org:acme`, the shared scope every internal principal reaches, which
demonstrates the identical property.

That did surface a real gap, recorded below: there is no UI for creating a
channel or managing its membership.

## Onboarding, learned from upstream

The first version of this was going to be an invites table and an admin form.
Reading upstream's `identity-service.ts` and `onboarding.ts` first changed three
decisions:

**Membership is a deny-list there, not an allow-list.** `classify()` returns
`internal` for anyone who is not explicitly deactivated, because being in the
Slack workspace *is* the membership. A web-first deployment has no workspace to
inherit that from, so `allowlist` is the default here — but `denylist` is
offered too, because upstream's model is right whenever something else already
bounds the perimeter. Deactivation is the offboarding verb in both.

**There is no invites table.** An invited person *is* a principal with an email
address, so `principals` already models it. Sign-in admits a known active
principal by email; the admin form just creates one. That collapses "invite",
"exists" and "offboard" onto rows that already had to exist.

**Onboarding is a conversation, not a form.** Upstream tracks it as a marker
line in the person's own memory notebook — `Onboarding: completed v2 on
2026-01-01.` — and prompts the agent to walk them through setup while no marker
is present. Ported verbatim in `src/onboarding.rs`. Memory as the source of
truth means no second table, and the person can see and edit their own state.
Version-matching is whole-word, so `v1` does not match `v10` and bumping the
version genuinely re-runs onboarding.

**Groups are keyed by participants.** Upstream's `groupParticipantsKey` is the
sorted, deduped, joined participant list, so the same people resolve to the same
group whichever order they are listed in and whichever surface they arrive on.
`upsert_group` returns any existing group over exactly that set rather than
creating a second one.

## The checkbox that silently posted nothing

`axum::Form` deserializes with `serde_urlencoded`, which **cannot** put a
repeated key into a `Vec`. A member picker posts `members=ada&members=dana`, and
the extractor rejected the whole body with `invalid type: string "ada", expected
a sequence` — a 422 the browser showed as a bare error page.

The group form now reads its body through `RawForm` and parses it with
`form_urlencoded`. Anything else that posts a checkbox group must do the same;
`Form` is only safe for flat, single-valued fields.

Worth noting how this was found: the tutorial e2e caught it, because the
tutorial is generated by actually performing it. A unit test over the handler
would have passed a constructed `GroupForm` and proved nothing.

## Known limitations

Beyond the "not ported" list in `README.md`:

* **Single instance.** No leader election and no distributed lock. Two
  processes against one SQLite file will contend; cron claiming is safe, but
  nothing else is designed for it.
* **Keychain secrets are not encrypted at rest** — see above.
* **The sandbox is not isolated** — see above.
* **No streaming replies.** SSE reports turn *progress* (a tool started, a
  reply is being written); the reply itself lands when the turn completes.
* **Entitlement is checked at the surface, not in the store.** `scopes_for` and
  `require_scope_access` gate the web handlers; a store method called with an
  arbitrary scope will happily read it. Fine while the orchestrator is the only
  caller, worth revisiting if that stops being true.
* **No CSRF tokens.** Session cookies are `SameSite=Lax`, which blocks
  cross-site form posts in current browsers, and every mutating route is a
  POST. That is the whole defence; an explicit per-form token would be
  stronger.
* **Sign-in is magic-link only.** Upstream can defer to an external identity
  provider; there is no OIDC path here.
* **Admin is a single principal.** `[org].admin` names one id. There are no
  admin *roles*, and no per-scope delegated administration.
* **Groups are managed, channels are not.** `/admin/groups` creates groups and
  binds external conversations to them. Channels (`channel:<id>`) are still
  created only by the connectors, from the rooms they see. Two shared-scope
  kinds with one management surface is one too many; groups should probably
  absorb channels.
* **No directory sync.** Upstream replaces the whole directory from Slack, and
  deactivates people who left the workspace. Here the admin is the source, so
  offboarding is manual.
