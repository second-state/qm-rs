# qm-rs — session contract

Per-project instructions. The parent `../CLAUDE.md` (Rust guidance) still
applies; this file adds the local contract. Design rationale lives in
**KNOWLEDGE.md**, user docs in **README.md**. Documentation reflects runtime
behaviour rather than duplicating it.

## Verify after changes

```bash
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
cargo test
bash tests/smoke_test.sh        # boots the real server + mock harness, e2e
```

All four must pass before a change is done. The smoke test needs no network and
no credentials — the mock harness is in-process.

If you touched `src/plugin/`, also run the WasmEdge build, which is not in the
default feature set:

```bash
cargo clippy --features wasm --all-targets -- -D warnings
cargo test --features wasm
```

If you touched the tool surface, the harness, or anything a model interacts
with, run the live suites too — they catch what a mock cannot:

```bash
bash scripts/e2e.sh          # ported upstream e2e specs, against a real model
bash scripts/e2e_report.sh   # browser journey → e2e-reports/<ts>/report.html
```

These cost money and need `.env.e2e`. They are not part of the default gate,
but a change to `src/tools.rs` that passes `cargo test` can still be unusable
by a real model — see KNOWLEDGE.md → "What live testing caught".

## Schema changes

Migrations are compile-time embedded and versioned. To change the schema: add
the next `sql/migrations/NNNN_<what>.sql` **and** register it in
`src/db.rs::MIGRATIONS`. **Never edit an applied migration** — `cargo test`
enforces that the registry stays ordered and unique.

SQLite specifics that have already bitten: no expressions in a `PRIMARY KEY`,
and WAL must be set once before the pool spins up. See KNOWLEDGE.md →
"Versioned schema migrations".

## Security invariants (read before touching policy, sandbox or plugins)

These are the properties the tests exist to defend. Do not weaken one without
saying so explicitly.

- **The command policy floor applies in every posture**, `dangerous` included,
  and a scope may only add rules. A `deny` is final: a scope-level `allow`
  cannot override it. See `policy::command::compose_policy`.
- **Rules match a normalized command**, so quoting, escaping and nesting cannot
  smuggle a flag past a rule. If you change `scannable_command`, add a case to
  `quoting_does_not_smuggle_a_flag_past_a_rule` and the smoke test's policy
  loop.
- **A scope can only tighten the security posture**, never loosen it. An
  unrecognised posture string inherits rather than defaulting to something
  permissive.
- **Screening fails closed.** An unparseable verdict, a trapping plugin
  screener, or anything other than an explicit `auto` is `strict`. A screener
  that is *unreachable* yields an `unscreened` verdict, and the content is
  marked as unchecked — silence and safety must not look the same.
- **The sandbox confines paths.** `..` and absolute paths are rejected before
  the filesystem is touched, and the resolved path is re-checked against the
  canonicalized root so a planted symlink cannot escape. Scope directory names
  are sanitized.
- **`exec` uses `env_clear()`.** The server's own environment must never leak
  into a scope; only the materialized keychain plus `HOME`/`PATH`/`PWD`/
  `QM_SCOPE`.
- **Approvals resolve exactly once** and only from the session that owns them.
- **Crons fire exactly once per scheduled instant**, and the schedule advances
  whatever the outcome.
- **Skills are verified before use.** A skill whose signature does not verify is
  hidden from turns, never executed.

## Auth invariants (read before touching src/auth/ or the router)

- **Nothing replayable is stored.** Sessions, magic links and API keys are
  random values kept only as SHA-256 hashes. Never add a column that holds one
  in readable form.
- **The allowlist defaults to closed.** With no `admin_email`,
  `allowed_emails` or `allowed_domains`, nobody signs in. Do not add a
  "permissive when unconfigured" branch.
- **The login form is not an oracle.** An address that may not sign in gets the
  same response as one that may. Keep failures and rejections indistinguishable
  to the sender.
- **A magic link works once**, enforced by a conditional UPDATE, not by a read
  followed by a write.
- **`CurrentUser` is the enforcement point.** Every page and API handler takes
  one. If you add a route that does not, say in the code why it is safe — the
  only current exceptions are the sign-in flow, `/api/health`, and
  `/slack/events`, which verifies a request signature instead.
- **The API actor is the authenticated principal.** Only the org admin may run
  a turn as someone else, and that is audited.
- **API keys cannot mint API keys.** Key creation requires a browser session.
- **Membership has two modes and both must hold.** Under `allowlist` only a
  listed or added person signs in; under `denylist` anyone does *unless
  deactivated*. A deactivated principal is refused in **both** modes — that
  check is not inside `email_allowed`, it is at the call site, because it needs
  the directory.
- **Deactivating revokes.** Offboarding must also drop that principal's live
  sessions, or they keep working until they expire.

## Slack invariants

- **Verify the signature before parsing the body.** HMAC over
  `v0:<timestamp>:<body>` plus a five-minute age bound; both halves are load
  bearing.
- **Ack first, work after** — Slack retries within three seconds. That is only
  safe because `slack_event_dedupe` claims each event id, so keep the claim.
- **`handle_event` decides, `handle_and_reply` posts.** Keep them separate:
  it is what makes the routing path testable without a network call.
- **Never answer a bot**, including ourselves, or two bots in a channel talk
  forever.

## Docs that are generated, not written

`docs/` is the published tutorial and it is **regenerated by performing it**
(`scripts/tutorial.sh`), never hand-edited. If you change a flow the tutorial
walks — sign-in, adding people, groups, sessions — regenerate it and commit the
result. It only replaces the committed guide when all five chapters pass, so a
broken run cannot publish a broken guide.

## Secrets

- Never derive `Debug` on a type holding a credential. `OpenAiHarness`,
  `TelegramConnector`, `SlackClient` and `Mailer` have hand-written `Debug`
  impls that redact; keep them that way and follow the pattern for anything new.
- Keychain values never reach a log line, an audit detail, or a rendered page.
  The UI shows metadata only.
- Real keys and tokens never go in committed files. `config.toml` is
  gitignored; `config.example.toml` carries commented placeholders only. Use
  the `QM_*` env vars (listed at the bottom of `config.example.toml`).
- Live e2e credentials live in `.env.e2e` (gitignored, chmod 600); the template
  is `.env.e2e.example`. The runner prints the endpoint and model but never the
  key, and passes it to the server through the environment rather than the
  config file so it cannot land in a report directory. `e2e-reports/` is
  gitignored — it holds live model output and server logs with sign-in links.
- Never echo a secret value into the conversation — reference the variable name.

## Architecture invariants

- **Surfaces never reach past the orchestrator.** The web handlers and the
  Telegram connector build a `TurnRequest` and call `handle_turn`; they do not
  drive the harness or write session entries themselves. That is what keeps one
  identity and one policy across surfaces.
- **A harness never touches the database.** It receives history, drives the
  model, calls tools through `ToolDispatch`, and emits through `TurnSink`.
- **Anything read back later is durable.** Approvals, cron fires, the audit log,
  the Telegram cursor and resolved config live in SQLite, never in a process
  `HashMap`. RAM is acceptable only as a cache in front of a durable store.
- **Plugins are extension points, not surfaces.** WasmEdge runs `tool:<name>`,
  `turn.before` and `screen`. Anything holding a socket or a timer is native
  Rust. A plugin may not shadow a built-in tool.

## UI conventions

- CSS and JS are Tera templates under `templates/static/`, served at `/assets/*`
  by `render_css`/`render_js`. There is no static directory and no build step.
- Colours are CSS custom properties defined once in `style.css`, with a
  `prefers-color-scheme: dark` block. Do not hardcode a colour in a template.
- Tera auto-escapes HTML, including `/` as `&#x2F;` — remember that when
  grepping rendered output in a test.
- A unit test asserts every template the router renders actually parses. Add
  new templates to that list.

## Testing style

Tests are named for the property they defend, not the function they call
(`a_stale_revision_is_refused`, not `test_replace_if_revision`). A test that
encodes a security property should say so in its assertion message, so a future
failure explains itself.
