#!/usr/bin/env bash
# Browser e2e over every key workflow, against a REAL model, producing a
# self-contained timestamped HTML report with a captioned screenshot per step.
#
#   bash scripts/e2e_report.sh        # → e2e-reports/<timestamp>/report.html
#
# Credentials come from .env.e2e (gitignored, chmod 600); the key is never
# printed. Reports are gitignored — they contain live model output.
#
# This costs money: every agent reply in the report is a real turn. For the
# free, deterministic version see tests/smoke_test.sh.
set -euo pipefail
set +m

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

PORT="${PORT:-18110}"
BASE="http://127.0.0.1:$PORT"
TS="$(date -u +%Y%m%dT%H%M%SZ)"
OUT="$ROOT/e2e-reports/$TS"
TMP="$(mktemp -d)"
SERVER_PID=""
cleanup() {
  [ -n "$SERVER_PID" ] && { kill "$SERVER_PID" >/dev/null 2>&1 || true; wait "$SERVER_PID" 2>/dev/null || true; }
  rm -rf "$TMP"
}
trap cleanup EXIT

# ---- credentials ----------------------------------------------------------

if [ ! -f .env.e2e ]; then
  cat >&2 <<'MSG'
No .env.e2e found.

  cp .env.e2e.example .env.e2e
  $EDITOR .env.e2e
MSG
  exit 1
fi
# shellcheck disable=SC1091
source .env.e2e

for var in QM_E2E_ENDPOINT QM_E2E_API_KEY QM_E2E_MODEL; do
  [ -n "${!var:-}" ] || { echo "FAIL: $var is not set in .env.e2e" >&2; exit 1; }
done

echo "endpoint: $QM_E2E_ENDPOINT"
echo "model:    $QM_E2E_MODEL"
echo "key:      (set, ${#QM_E2E_API_KEY} chars)"
echo "report:   e2e-reports/$TS/"
echo

# ---- prerequisites --------------------------------------------------------

command -v node >/dev/null || { echo "FAIL: node is required" >&2; exit 1; }
if ! node -e "import('playwright-core')" >/dev/null 2>&1; then
  echo "Installing playwright-core…"
  npm install --no-save --silent playwright-core
fi

PROBE="$(curl -s -o /dev/null -w '%{http_code}' -X POST "$QM_E2E_ENDPOINT/chat/completions" \
  -H "Authorization: Bearer $QM_E2E_API_KEY" \
  -H 'content-type: application/json' \
  -d "{\"model\":\"$QM_E2E_MODEL\",\"messages\":[{\"role\":\"user\",\"content\":\"ping\"}],\"max_tokens\":5}")"
[ "$PROBE" = "200" ] || { echo "FAIL: the gateway returned $PROBE for $QM_E2E_MODEL" >&2; exit 1; }
echo "ok: gateway reachable"

# ---- boot the server ------------------------------------------------------

cargo build --quiet
mkdir -p "$OUT" "$TMP/scopes"

# The key reaches the server through the environment, never the config file, so
# it cannot end up in the report directory.
cat > "$TMP/config.toml" <<EOF
[server]
host = "127.0.0.1"
port = $PORT

[database]
path = "$TMP/qm.db"

[org]
id = "acme"
name = "Acme"
admin = "ada"
security_posture = "auto"

[harness]
kind = "openai"
endpoint = "$QM_E2E_ENDPOINT"
api_key_env = "QM_HARNESS_API_KEY"
model = "$QM_E2E_MODEL"
timeout_secs = 180
max_steps = 12

[sandbox]
root_dir = "$TMP/scopes"

[cron]
enabled = false

[auth]
admin_email = "ada@acme.test"
email_mode = "console"
public_url = "$BASE"
EOF

QM_CONFIG="$TMP/config.toml" QM_HARNESS_API_KEY="$QM_E2E_API_KEY" \
  ./target/debug/qm_rs > "$TMP/server.log" 2>&1 &
SERVER_PID=$!

for _ in $(seq 1 80); do
  curl -sf "$BASE/api/health" >/dev/null 2>&1 && break
  sleep 0.25
done
curl -sf "$BASE/api/health" >/dev/null || { cat "$TMP/server.log"; echo "FAIL: server did not start" >&2; exit 1; }
echo "ok: server up on $BASE"
echo

# ---- drive the browser ----------------------------------------------------

set +e
BASE="$BASE" OUT="$OUT" LOG="$TMP/server.log" \
  MODEL="$QM_E2E_MODEL" ENDPOINT="$QM_E2E_ENDPOINT" \
  node scripts/ui_journey_e2e.mjs
JOURNEY_STATUS=$?
set -e

# The server log is useful when a workflow failed, but it holds sign-in links,
# so it is copied only alongside the (gitignored) report.
cp "$TMP/server.log" "$OUT/server.log" 2>/dev/null || true

echo
if [ $JOURNEY_STATUS -eq 0 ]; then
  echo "E2E REPORT PASSED → e2e-reports/$TS/report.html"
else
  echo "E2E REPORT HAD FAILURES → e2e-reports/$TS/report.html" >&2
fi
exit $JOURNEY_STATUS
