# qm-rs

A multiplayer agent harness for work. On the web, in Slack, and in Telegram.

A Rust port of [QM](https://github.com/yc-software/qm)'s headless core onto
local SQLite. One binary, one database file, no build step.

**Stack:** Rust (2021) · axum + tokio · Tera server-rendered templates ·
rusqlite (bundled SQLite) behind an r2d2 pool · compile-time embedded versioned
migrations · serde/serde_json/toml · reqwest · tracing · WasmEdge for plugins
(optional feature).

## What it is

Most agents are personal assistants. QM is designed for a team: each person
gets their own isolated workspace and works independently, and the same agent
also works with everyone together in shared channels. Every person and every
room has its own scoped memory, files, keychain view, permissions, crons, and
durable sandbox.

That structure is what this port keeps.

```
                       ┌──────────────────────────────┐
   web UI (Tera) ─────▶│                              │
   Slack       ───────▶│        Orchestrator          │──▶ SQLite
   Telegram    ───────▶│  resolve → screen → harness  │    sessions · memory
   cron        ───────▶│        → tools → persist     │    skills · crons · acl
   HTTP API    ───────▶│                              │    sessions · api keys
                       └───────────────┬──────────────┘
                                       │
                              per-scope sandbox
                          (durable dir, policy-gated exec)
```

Every turn — typed, scheduled, or arriving from Slack or Telegram — runs
through one orchestrator. Surfaces never reach past it, which is what keeps one
identity and one policy across all of them.

## Quick start

```bash
cargo run
```

That's it. With no config file the server boots on <http://127.0.0.1:8080>
with the **mock harness**: deterministic, in-process, no credentials, no
network. Open the dashboard and start a session.

The mock harness reads directives out of the message text, so you can drive
the real tool surface without a model:

```
!exec echo hello           run a shell command in the scope's sandbox
!write notes.md hello      write a file
!read notes.md             read it back
!remember Ada likes tea    record a fact in this scope's memory
!recall tea                search memory
!exec rm -rf build         → pauses for approval (the command policy)
```

To use a real model, point it at any OpenAI-compatible endpoint:

```toml
# config.toml
[harness]
kind = "openai"
endpoint = "https://your-gateway.example.com/v1"
model = "openai/gpt-5.4"
```

```bash
export QM_HARNESS_API_KEY=sk-...
cargo run --release
```

`config.example.toml` documents every knob in place.

### Signing in

Set who may sign in, then open the app:

```toml
[org]
admin = "ada"

[auth]
admin_email = "ada@example.com"
public_url = "http://127.0.0.1:8080"
email_mode = "console"     # the link goes to the server log
```

Enter the address, and the sign-in link appears in the log:

```
WARN qm_rs::auth::email: sign-in link (console mode; treat this as a password):
     http://127.0.0.1:8080/auth/callback?token=...
```

For real email, set `email_mode = "resend"`, a verified `from_address`, and
`QM_EMAIL_API_KEY`.

> **Nobody can sign in until you say who may.** With no `admin_email`,
> `allowed_emails` or `allowed_domains`, every address is refused and the server
> warns at boot. "Anyone with an email address" is never the default.

## Core concepts

### Scopes

A **scope** is the unit that owns memory, files, skills, keychain entries,
crons and permissions. Its id is `<kind>:<ref>`:

| Scope | Example | Who reads it |
|---|---|---|
| `personal` | `personal:ada` | Ada alone |
| `channel` | `channel:eng` | everyone in the channel |
| `group` | `group:g1` | everyone in the group |
| `org` | `org:acme` | every internal principal |

A turn resolves to a **layer stack**: the org scope mounted read-only beneath
the turn's own scope, which is writable. A personal turn writes to the person;
a channel turn writes to the channel — so what the agent learns in a channel
belongs to the channel, not to whoever happened to speak.

### The tool surface

Small and fixed, as upstream's is:

| Tool | What it does |
|---|---|
| `execute` | run a shell command in the scope's durable sandbox |
| `read` / `write` / `list` | files in the workspace |
| `memory` | capture, query or read this scope's notebook |
| `history` | search earlier conversations in reachable scopes |
| `cron` | schedule work to run later |
| `skills` | list or read the available skills |
| `share` | grant another scope access to a file |
| `finish_silently` | end the turn without replying |

Plugins can add more (see below). A plugin may not shadow a built-in.

### Authentication

People sign in with an emailed magic link — one use, short expiry, no password
to leak. Programs use bearer API keys minted from `/account`.

Sessions, login links and API keys are all high-entropy random strings shown
once and stored **only as a SHA-256 hash**, so read access to the database does
not hand anyone a live credential. Deactivating a principal invalidates their
sessions and keys immediately.

Every page and API handler takes an authenticated principal as an argument, so
a handler cannot forget to check — it will not compile without one. The only
routes outside that are the sign-in flow, `/api/health`, and `/slack/events`,
which authenticates by request signature instead.

```bash
# Mint a key at /account, then:
curl -X POST localhost:8080/api/turn \
  -H "Authorization: Bearer qmk_..." \
  -H "content-type: application/json" \
  -d '{"text":"what changed in the deploy?"}'
```

A key acts as its owner, with their scopes and permissions. Keys cannot mint
further keys — that requires a signed-in browser, so one leaked key does not
become permanent access.

### Security

An org picks one posture; a scope may only tighten it.

| Posture | Behaviour |
|---|---|
| `strict` | every tool call pauses for a human |
| `auto` (default) | external content and tool output are screened before the model sees them |
| `dangerous` | no screening, no pauses |

The **predeclared command policy** applies in every posture, `dangerous`
included. Recursive deletes, force pushes and destructive SQL ask for
approval; `mkfs` and fork bombs are denied outright. Rules match against a
*normalized* form of the command, so quoting, escaping and nesting do not get
past them:

```
rm -rf /tmp/x          → approval
rm '-rf' /tmp/x        → approval
rm \-rf /tmp/x         → approval
sh -c 'rm -rf /tmp/x'  → approval
psql -c 'DROP TABLE users'  → approval
echo 'notes about mkfs'     → allowed  (quoted prose is not a command)
```

Approvals are durable rows, not process state, so a pause survives a restart.
Approving with scope `session` or `always` records a standing grant so that
class of command stops asking.

### Memory

One Markdown notebook per scope, recalled at the start of every turn. Captures
dedupe and carry a date. Facts arriving from untrusted provenance are rewritten
so they cannot forge the notebook's own grammar — a leading `(2020-01-01)`
becomes prose, and a trailing `(said in #ops)` becomes an explicit
`[claimed source: ...]`. Every write is a revision, and the editor
compare-and-swaps on the revision it loaded, so a concurrent edit is reported
rather than silently overwritten.

### Skills

Scope-owned instruction bundles with YAML-ish frontmatter. Signed on write and
verified on read: a skill whose stored rows were changed outside the app is
hidden from every turn rather than executed. Editing a published skill returns
it to draft. A nearer scope's skill shadows a shared one of the same name.

## Slack

```toml
[slack]
enabled = true
allowed_channels = ["C01234567"]

[slack.principals]
"U01234567" = "ada"
```

```bash
export QM_SLACK_BOT_TOKEN=xoxb-...    # OAuth & Permissions
export QM_SLACK_APP_TOKEN=xapp-...    # app-level token, connections:write
cargo run --release
```

Socket Mode by default: an outbound WebSocket, so **no public URL and no
inbound port**. Scopes the bot needs: `app_mentions:read`, `channels:history`,
`chat:write`, `im:history`, `users:read`.

* A DM → the sender's personal scope.
* A channel → `channel:slack-<channel_id>`, and by default the bot only answers
  when @-mentioned.
* Each Slack thread gets its own session, so two conversations in one channel
  do not interleave.
* An unmapped Slack user becomes a guest principal `slack:<user_id>`.

For a deployment that already terminates HTTPS, set `mode = "events"` and a
`signing_secret`; Slack then POSTs to `/slack/events`. Every request is
signature-verified — HMAC over `v0:<timestamp>:<body>`, with a five-minute
window so a captured request cannot be replayed — before anything in the body
is read. Events are deduplicated by id, so Slack's retries never run a turn
twice.

## Telegram

```toml
[telegram]
enabled = true
allowed_chat_ids = [123456789]

[telegram.principals]
"123456789" = "ada"
```

```bash
export QM_TELEGRAM_BOT_TOKEN=123456:ABC-DEF...
cargo run --release
```

Get a token from [@BotFather](https://t.me/botfather). The connector
long-polls `getUpdates` — no webhook, no public URL, no inbound port.

* A private chat → the sender's personal scope.
* A group → `channel:tg-<chat_id>`, and by default the bot only answers when
  @-mentioned.
* An unmapped Telegram user becomes a guest principal `telegram:<user_id>`.

A bot is addressable by anyone who knows its handle, so leave
`allowed_chat_ids` empty only for a bot nobody else can find.

## Plugins

Upstream's plugins are two different things, and this port treats them
differently:

* **Surfaces** (Slack, web UI, admin, portal upstream) are I/O-driven daemons
  holding sockets and timers. Here the web UI and Telegram connector are
  native in-process Rust.
* **Deployment extension points** — organization-specific tools, the security
  screener, turn middleware — are pure functions over bytes. Those run as
  **WasmEdge** modules, using the same ABI as
  [cloud_ai_gateway](https://github.com/second-state/cloud_ai_gateway), so
  modules and authoring patterns carry across.

```bash
cargo build --release --features wasm
```

Write a module against `plugins/qm_plugin_sdk`:

```rust
use qm_plugin_sdk::{PluginRequest, PluginResponse};

qm_plugin_sdk::handler!(process);

fn process(req: PluginRequest) -> PluginResponse {
    match req.hook.as_str() {
        "screen" if req.content().contains("ignore your instructions") =>
            PluginResponse::quarantine("prompt injection"),
        "screen" => PluginResponse::allow(),
        "turn.before" => PluginResponse::pass().route("openai/gpt-5.4-mini"),
        _ => PluginResponse::failure("unsupported hook"),
    }
}
```

```bash
cd plugins/modules/example_guard
cargo build --release --target wasm32-wasip1
cp target/wasm32-wasip1/release/example_guard.wasm ../
```

```toml
[plugins]
dir = "plugins/modules"
screener = "example_guard.wasm"
turn_middleware = ["example_guard.wasm"]

[[plugins.tools]]
name = "lookup_order"
description = "Look up an order by id"
module = "orders.wasm"
parameters = '{"type":"object","properties":{"order_id":{"type":"string"}}}'
```

Three hooks: `tool:<name>` (a custom agent tool, selectable per scope),
`turn.before` (rewrite the text, route the model, extend the prompt), and
`screen` (the security screener). Each call gets a fresh store and instance, so
one scope's call cannot observe another's. A screener that fails, or returns
anything other than `auto`, **fails closed**.

Without `--features wasm` the binary still builds and runs; configured modules
are reported as inert on `/admin` rather than silently ignored.

## Database migrations

Migrations are `sql/migrations/NNNN_<what>.sql`, embedded at compile time,
applied in order inside their own transactions, and tracked in
`schema_migrations`. They run automatically on every boot, and `/admin` shows
applied versus registered so drift is visible.

To change the schema:

1. add `sql/migrations/NNNN_<what>.sql`;
2. register it in `src/db.rs::MIGRATIONS`.

**Never edit an applied migration.** `cargo test` enforces that the registry
stays ordered and unique.

Deployment needs the binary plus `templates/` — the `sql/` folder is the
canonical, reviewable history, not a runtime dependency.

## HTTP API

```bash
# Run a turn
curl -X POST localhost:8080/api/turn -H 'content-type: application/json' \
  -d '{"actor":"ada","text":"what changed in the deploy?","thread_ref":"t1"}'

# Resolve an approval
curl -X POST localhost:8080/api/turn -H 'content-type: application/json' \
  -d '{"actor":"ada","thread_ref":"t1",
       "approval":{"request_id":"...","approved":true,"scope":"session"}}'

curl localhost:8080/api/sessions/<id>   # full transcript
curl localhost:8080/api/health
curl -N localhost:8080/api/events       # SSE, live turn progress
```

## Development

```bash
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
cargo test
bash tests/smoke_test.sh     # boots the real server, walks the whole pipeline
```

All four must pass. The smoke test needs no network and no credentials: it runs
the mock harness against a temp database and exercises sign-in, tool dispatch,
the command policy, sandbox confinement, approvals, memory, scope isolation,
crons, Slack signature verification, every rendered page, and a restart.

### Live end-to-end tests

Two suites run against a **real model**, ported from the specs the upstream
TypeScript project runs as its own e2e — the agent loop in process
(`pi-harness.e2e.test.ts`), the same behaviour over HTTP (`http.e2e.test.ts`),
and the scenarios this port has (`execute-turn`, `cron-create`).

```bash
cp .env.e2e.example .env.e2e   # endpoint, key, model
bash scripts/e2e.sh            # 14 live tests, in process and over HTTP
bash scripts/e2e_report.sh     # browser journey → an HTML report
```

`.env.e2e` is gitignored and the key is never printed. Without it, `cargo test`
skips these entirely and never reaches the network.

**`scripts/e2e.sh`** asserts the ported specs: generation, `execute` against a
real sandbox, write-then-read, in-session and cross-session memory, the session
log, the resolved system prompt actually reaching the model, a denied command
never running, a policy hit pausing for a human, scope isolation, a published
skill being followed, and screener behaviour under injection.

**`scripts/e2e_report.sh`** drives a real Chrome through 15 workflows in the web
UI, capturing a captioned screenshot per step, and writes a self-contained
report to `e2e-reports/<timestamp>/report.html`:

```
e2e-reports/20260801T181246Z/
├── report.html        # every workflow, pass/fail, screenshots + captions
├── report.json        # the same, machine-readable
├── 01.png … 32.png    # one per step
└── server.log
```

Every agent reply in that report is a genuine turn — no fixtures, no fake
harness. Reports are gitignored; they contain live model output.

`KNOWLEDGE.md` has the design rationale and the deliberate limitations.

## What this port covers, and what it does not

Upstream QM is ~107k lines of TypeScript across a core, four plugin packages
and a CLI. This is a port of its **core architecture**, not a line-by-line
translation.

**Ported:** scopes and the layer stack · sessions and the typed entry log ·
magic-link sign-in and bearer API keys · Slack (Socket Mode and the signed
Events API) ·
the turn pipeline · resolution (prompt, policies, granted handles) ·
security postures and the predeclared command policy with command
normalization · approvals with standing grants · memory notebooks with
revisions and untrusted-provenance handling · scope-owned signed skills ·
ACL grants and `shared/` handles · crons with exactly-once fires · the
per-scope sandbox · files, keychain and a durable audit log · the harness seam ·
a web surface, a JSON API and SSE · a Telegram connector · WasmEdge extension
points.

**Not ported:** the Vite/Lit SPA ·
the vendor harness SDKs (Pi, OpenCode, Codex, Claude Code) — the harness trait
is the seam where those would go, and an OpenAI-compatible implementation
stands in · cloud sandboxes (Fly, AWS microVM) · the deployment directory and
`qm` CLI · web-app publishing · OAuth connectors and the credential broker ·
pluggable external identity providers (sign-in here is magic-link only) ·
Postgres, multi-instance leader election and the distributed queue.

Two places where this port deliberately differs from upstream rather than
merely omitting something:

* **Command normalization is stricter.** Upstream drops quoted arguments
  entirely, which keeps `echo 'notes about mkfs'` inert but also hides
  `psql -c 'DROP TABLE users'`. Here, quoted arguments to known interpreters
  and SQL clients are scanned as code while quoted prose elsewhere still is
  not.
* **Granted file handles are de-collided.** Two grants whose basenames match
  would both mount at `shared/<name>`; the second is renamed rather than
  shadowing the first.

## License

MIT.
