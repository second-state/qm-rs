#!/usr/bin/env bash
# End-to-end smoke test: boots the real server against a temp database with the
# mock harness, then walks the whole turn pipeline with curl — sign-in, tool
# dispatch, the command policy, sandbox confinement, approvals, memory, crons,
# Slack signature verification, and every rendered page.
#
# Needs no network and no credentials: the mock harness is in-process and
# sign-in runs in console mode, so the magic link lands in the server log.
#
# Usage: bash tests/smoke_test.sh
set -euo pipefail
# Job control off, so killing the server on the way out does not print a
# "Terminated" line after the result.
set +m

cd "$(dirname "$0")/.."
PORT=18099
BASE="http://127.0.0.1:$PORT"
TMP="$(mktemp -d)"
BOOTSTRAP_KEY="smoke-bootstrap-key-0123456789"
trap 'kill $SERVER_PID 2>/dev/null || true; wait $SERVER_PID 2>/dev/null || true; rm -rf "$TMP"' EXIT

fail() { echo "FAIL: $1" >&2; exit 1; }
ok() { echo "ok: $1"; }

json() { python3 -c "import sys,json; d=json.load(sys.stdin); print($1)"; }

# API calls authenticate with the bootstrap key; browser calls use the cookie
# jar filled in by the sign-in flow below.
turn() {
  curl -sf -X POST "$BASE/api/turn" \
    -H "Authorization: Bearer $BOOTSTRAP_KEY" \
    -H 'content-type: application/json' -d "$1"
}

page() { curl -sf -b "$TMP/cookies" "$@"; }
page_code() { curl -s -o /dev/null -w '%{http_code}' -b "$TMP/cookies" "$@"; }

cat > "$TMP/config.toml" <<EOF
[server]
port = $PORT

[database]
path = "$TMP/qm.db"

[org]
id = "acme"
name = "Acme"
admin = "ada"

[harness]
kind = "mock"

[sandbox]
root_dir = "$TMP/scopes"

[cron]
enabled = true
tick_seconds = 1

[email]
mode = "console"

[auth]
admin_email = "ada@acme.test"
public_url = "$BASE"
bootstrap_api_key = "$BOOTSTRAP_KEY"

[slack]
enabled = false
EOF

cargo build --quiet
QM_CONFIG="$TMP/config.toml" ./target/debug/qm_rs > "$TMP/server.log" 2>&1 &
SERVER_PID=$!

for _ in $(seq 1 60); do
  curl -sf "$BASE/api/health" > /dev/null 2>&1 && break
  sleep 0.2
done
curl -sf "$BASE/api/health" > /dev/null || { cat "$TMP/server.log"; fail "server did not start"; }
ok "server up"

# ---- health and migrations ------------------------------------------------

HEALTH="$(curl -sf "$BASE/api/health")"
echo "$HEALTH" | grep -q '"harness":"mock"' || fail "wrong harness: $HEALTH"
MIGRATIONS="$(echo "$HEALTH" | json 'd["migrations"]')"
[ "$MIGRATIONS" -ge 2 ] || fail "migrations not reported: $HEALTH"
ok "health"

# ---- everything is behind sign-in -----------------------------------------

for path in / /sessions /memory /skills /crons /files /keychain /admin /account; do
  code="$(curl -s -o /dev/null -w '%{http_code}' "$BASE$path")"
  [ "$code" = "303" ] || [ "$code" = "302" ] || fail "$path should redirect to login, got $code"
done
[ "$(curl -s -o /dev/null -w '%{http_code}' "$BASE/api/turn" -X POST \
      -H 'content-type: application/json' -d '{"text":"hi"}')" = "401" ] \
  || fail "the API should refuse an unauthenticated turn"
ok "unauthenticated requests are refused"

# ---- sign in with a magic link --------------------------------------------

# An address that may not sign in gets the same response as one that may.
curl -s -o /dev/null "$BASE/auth/request" --data-urlencode "email=stranger@evil.test"
grep -q "stranger@evil.test" "$TMP/server.log" && \
  grep -q "sign-in link" <(grep "stranger@evil.test" "$TMP/server.log") && \
  fail "a link was minted for a disallowed address"
ok "a disallowed address gets no link"

curl -s -o /dev/null "$BASE/auth/request" --data-urlencode "email=ada@acme.test"
for _ in $(seq 1 40); do
  grep -q "sign-in link" "$TMP/server.log" && break
  sleep 0.2
done
LOGIN_URL="$(grep -o "$BASE/auth/callback?token=[A-Za-z0-9%&=.-]*" "$TMP/server.log" | tail -1)"
[ -n "$LOGIN_URL" ] || { tail -20 "$TMP/server.log"; fail "no sign-in link in the log"; }

curl -s -o /dev/null -c "$TMP/cookies" "$LOGIN_URL"
grep -q "qm_session" "$TMP/cookies" || fail "the callback did not set a session cookie"
ok "signed in with a magic link"

# The same link must not work twice.
curl -s -o /dev/null -c "$TMP/cookies2" "$LOGIN_URL"
grep -q "qm_session" "$TMP/cookies2" 2>/dev/null && fail "a magic link was reusable"
ok "a magic link works exactly once"

# ---- every page renders ---------------------------------------------------

for path in / /sessions /memory /skills /crons /files /keychain /admin /account; do
  code="$(page_code "$BASE$path")"
  [ "$code" = "200" ] || fail "$path returned $code"
done
page "$BASE/assets/style.css" | grep -q -- "--accent" || fail "stylesheet"
page "$BASE/assets/app.js" | grep -q "initLiveEvents" || fail "app.js"
ok "pages and assets"

# ---- API keys -------------------------------------------------------------

page_code -X POST "$BASE/account/keys" --data-urlencode "name=smoke" > /dev/null
page "$BASE/account" | grep -q "smoke" || fail "the new key should be listed"
ok "API keys are mintable from the browser"

[ "$(curl -s -o /dev/null -w '%{http_code}' -X POST "$BASE/api/turn" \
      -H "Authorization: Bearer not-a-real-key" \
      -H 'content-type: application/json' -d '{"text":"hi"}')" = "401" ] \
  || fail "a bogus bearer key should be refused"
ok "a bogus API key is refused"

# ---- a turn runs a tool ---------------------------------------------------

REPLY="$(turn '{"actor":"ada","text":"!exec echo hello-from-sandbox","thread_ref":"t1"}' | json 'd["reply"]')"
echo "$REPLY" | grep -q "hello-from-sandbox" || fail "tool dispatch: $REPLY"
ok "execute runs in the sandbox"

# ---- the command policy floor holds ---------------------------------------

DENIED="$(turn '{"actor":"ada","text":"!exec mkfs.ext4 /dev/sda","thread_ref":"t2"}' | json 'd["reply"]')"
echo "$DENIED" | grep -q "denied" || fail "a hard denial must not run: $DENIED"
ok "destructive commands are denied"

# Quoting must not smuggle a flag past the policy. The commands carry quotes,
# so the text field is JSON-escaped rather than interpolated raw.
json_string() { python3 -c 'import json,sys; print(json.dumps(sys.stdin.read()))'; }

for cmd in "rm -rf /tmp/x" "rm '-rf' /tmp/x" "sh -c 'rm -rf /tmp/x'"; do
  TEXT="$(printf '%s' "!exec $cmd" | json_string)"
  STATUS="$(turn "{\"actor\":\"ada\",\"text\":$TEXT,\"thread_ref\":\"policy\"}" | json 'd["status"]')"
  [ "$STATUS" = "pending_approval" ] || fail "policy missed: $cmd (got $STATUS)"
done
ok "the command policy sees through quoting and nesting"

# ---- sandbox confinement --------------------------------------------------

ESCAPE="$(turn '{"actor":"ada","text":"!read ../../../../etc/passwd","thread_ref":"t3"}' | json 'd["reply"]')"
echo "$ESCAPE" | grep -q "not permitted" || fail "path traversal was not refused: $ESCAPE"
ok "the sandbox confines paths"

# ---- approvals ------------------------------------------------------------

PAUSED="$(turn '{"actor":"ada","text":"!exec rm -rf /tmp/nightly","thread_ref":"approve"}')"
[ "$(echo "$PAUSED" | json 'd["status"]')" = "pending_approval" ] || fail "no pause: $PAUSED"
REQUEST_ID="$(echo "$PAUSED" | json 'd["pending_approvals"][0]["request_id"]')"
ok "a policy hit pauses the turn"

RESUMED="$(turn "{\"actor\":\"ada\",\"thread_ref\":\"approve\",\"approval\":{\"request_id\":\"$REQUEST_ID\",\"approved\":true,\"scope\":\"once\"}}")"
[ "$(echo "$RESUMED" | json 'd["status"]')" = "ok" ] || fail "approval did not resume: $RESUMED"

REPLAY="$(curl -s -o /dev/null -w '%{http_code}' -X POST "$BASE/api/turn" \
  -H "Authorization: Bearer $BOOTSTRAP_KEY" \
  -H 'content-type: application/json' \
  -d "{\"actor\":\"ada\",\"thread_ref\":\"approve\",\"approval\":{\"request_id\":\"$REQUEST_ID\",\"approved\":true,\"scope\":\"once\"}}")"
[ "$REPLAY" = "400" ] || fail "a replayed approval must be refused (got $REPLAY)"
ok "approvals resolve exactly once"

# ---- memory ---------------------------------------------------------------

turn '{"actor":"ada","text":"!remember Ada prefers concise summaries","thread_ref":"mem"}' > /dev/null
RECALL="$(turn '{"actor":"ada","text":"!recall concise","thread_ref":"mem"}' | json 'd["reply"]')"
echo "$RECALL" | grep -q "concise summaries" || fail "recall: $RECALL"
DUPE="$(turn '{"actor":"ada","text":"!remember Ada prefers concise summaries","thread_ref":"mem"}' | json 'd["reply"]')"
echo "$DUPE" | grep -q "already known" || fail "capture should dedupe: $DUPE"
ok "memory captures, recalls and dedupes"

# ---- scope isolation ------------------------------------------------------

turn '{"actor":"bob","text":"!remember Bob has a secret","thread_ref":"bob"}' > /dev/null
LEAK="$(turn '{"actor":"ada","text":"!recall secret","thread_ref":"mem"}' | json 'd["reply"]')"
echo "$LEAK" | grep -q "Bob has a secret" && fail "one scope's memory leaked into another: $LEAK"
ok "scopes do not see each other's memory"

# ---- a channel turn writes to the channel ---------------------------------

turn '{"actor":"ada","scope":"channel:eng","text":"!remember we deploy on Fridays","thread_ref":"chan"}' > /dev/null
CHANNEL="$(turn '{"actor":"ada","scope":"channel:eng","text":"!recall Fridays","thread_ref":"chan"}' | json 'd["reply"]')"
echo "$CHANNEL" | grep -q "channel:eng" || fail "channel memory went to the wrong scope: $CHANNEL"
ok "channel turns write to the channel"

# ---- crons ----------------------------------------------------------------

CRON="$(turn '{"actor":"ada","text":"!tool cron {\"action\":\"create\",\"message\":\"nightly check\",\"every_secs\":60}","thread_ref":"cron"}' | json 'd["reply"]')"
echo "$CRON" | grep -q "scheduled" || fail "cron create: $CRON"
page "$BASE/crons" | grep -q "nightly check" || fail "the crons page should list it"
ok "crons are created and listed"

# ---- the session page renders the transcript ------------------------------

SESSION_ID="$(echo "$PAUSED" | json 'd["session_id"]')"
PAGE="$(page "$BASE/sessions/$SESSION_ID")"
# Tera escapes '/' as &#x2F;, so match on a slash-free fragment.
echo "$PAGE" | grep -q "rm -rf" || fail "the transcript should render the command"
echo "$PAGE" | grep -q 'class="entry tool_call"' || fail "tool calls should render"
echo "$PAGE" | grep -q 'class="entry approval_resolved"' || fail "the approval should render"
ok "the session page renders the transcript"

# ---- the JSON API mirrors it ----------------------------------------------

ENTRIES="$(curl -sf "$BASE/api/sessions/$SESSION_ID" -H "Authorization: Bearer $BOOTSTRAP_KEY" | json 'len(d["entries"])')"
[ "$ENTRIES" -ge 4 ] || fail "session json is missing entries (got $ENTRIES)"
ok "the session API mirrors the transcript"

# ---- input validation -----------------------------------------------------

BAD="$(curl -s -o /dev/null -w '%{http_code}' -X POST "$BASE/api/turn" \
  -H "Authorization: Bearer $BOOTSTRAP_KEY" \
  -H 'content-type: application/json' -d '{"actor":"ada","text":""}')"
[ "$BAD" = "400" ] || fail "an empty turn should be rejected (got $BAD)"

BAD_SCOPE="$(curl -s -o /dev/null -w '%{http_code}' -X POST "$BASE/api/turn" \
  -H "Authorization: Bearer $BOOTSTRAP_KEY" \
  -H 'content-type: application/json' -d '{"actor":"ada","scope":"nonsense","text":"hi"}')"
[ "$BAD_SCOPE" = "400" ] || fail "a malformed scope should be rejected (got $BAD_SCOPE)"
ok "input validation"

# ---- the audit log recorded the consequential actions ---------------------

page "$BASE/admin" | grep -q "execute.denied" || fail "the denial should be audited"
ok "audit log"

# ---- slack refuses unsigned events ----------------------------------------

SLACK_CODE="$(curl -s -o /dev/null -w '%{http_code}' -X POST "$BASE/slack/events" \
  -H 'content-type: application/json' -d '{"type":"event_callback"}')"
# Slack is disabled here, so the route reports 404; with it enabled and no
# valid signature the same request is a 401. Either way it never runs a turn.
[ "$SLACK_CODE" = "404" ] || [ "$SLACK_CODE" = "401" ] \
  || fail "an unsigned slack event returned $SLACK_CODE"
ok "unsigned slack events are refused"

# ---- the database survives a restart --------------------------------------

kill $SERVER_PID 2>/dev/null || true
wait $SERVER_PID 2>/dev/null || true
QM_CONFIG="$TMP/config.toml" ./target/debug/qm_rs > "$TMP/server2.log" 2>&1 &
SERVER_PID=$!
for _ in $(seq 1 60); do
  curl -sf "$BASE/api/health" > /dev/null 2>&1 && break
  sleep 0.2
done
AFTER="$(turn '{"actor":"ada","text":"!recall concise","thread_ref":"mem"}' | json 'd["reply"]')"
echo "$AFTER" | grep -q "concise summaries" || fail "memory did not survive a restart: $AFTER"
page "$BASE/crons" | grep -q "nightly check" || fail "crons did not survive a restart"
page "$BASE/account" | grep -q "smoke" || fail "API keys did not survive a restart"
ok "state and credentials survive a restart"

echo
echo "SMOKE TEST PASSED"
