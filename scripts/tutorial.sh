#!/usr/bin/env bash
# Generate the getting-started tutorial by actually performing it.
#
#   bash scripts/tutorial.sh          # → docs/index.html + docs/README.md
#
# The guide in docs/ is COMMITTED and served by GitHub Pages (Settings → Pages →
# Source: main /docs). It is regenerated rather than written by hand: the
# journey signs in as the admin, adds two people, groups them, then has those
# people work with the agent. If a step stops working the guide fails to build,
# so the documentation cannot silently drift from the application.
#
# The run is staged in a temporary directory and copied into docs/ only when
# every chapter passed — a half-broken guide never replaces a good one.
#
# Credentials come from .env.e2e (gitignored, chmod 600); the key is never
# printed and never reaches the config file. This costs money: every agent reply
# in the guide is a real model turn.
set -euo pipefail
set +m

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

PORT="${PORT:-18120}"
BASE="http://127.0.0.1:$PORT"
FINAL="$ROOT/docs"
TMP="$(mktemp -d)"
STAGE="$TMP/out"
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
echo "guide:    docs/"
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

# ---- build, including the plugin runtime ----------------------------------

# The tutorial installs a WasmEdge plugin, so the server needs the `wasm`
# feature. Without it the module would load as "inert" and that chapter would
# document the wrong thing.
echo "Building with the wasm feature (first run fetches WasmEdge)…"
cargo build --quiet --features wasm

# The example module is compiled here rather than committed as a binary, so the
# guide always shows a module built from the source next to it.
if ! rustup target list --installed 2>/dev/null | grep -q wasm32-wasip1; then
  echo "Adding the wasm32-wasip1 target…"
  rustup target add wasm32-wasip1
fi
# `wasmedge-sdk/standalone` downloads the runtime at build time but does not
# bake an rpath into the binary, so the dynamic loader has to be told where it
# landed. Check the build directory first, then the usual home install.
WASMEDGE_LIB="$(find "$ROOT/target" -type d -path '*standalone*/lib' 2>/dev/null | head -1)"
[ -n "$WASMEDGE_LIB" ] || WASMEDGE_LIB="$HOME/.wasmedge/lib"
if [ ! -f "$WASMEDGE_LIB/libwasmedge.0.dylib" ] && [ ! -f "$WASMEDGE_LIB/libwasmedge.so.0" ]; then
  echo "FAIL: built with --features wasm but libwasmedge was not found." >&2
  echo "      Install it with: curl -sSf https://raw.githubusercontent.com/WasmEdge/WasmEdge/master/utils/install_v2.sh | bash" >&2
  exit 1
fi
export DYLD_FALLBACK_LIBRARY_PATH="$WASMEDGE_LIB:${DYLD_FALLBACK_LIBRARY_PATH:-}"
export LD_LIBRARY_PATH="$WASMEDGE_LIB:${LD_LIBRARY_PATH:-}"
echo "ok: wasmedge runtime at $WASMEDGE_LIB"

PLUGIN_SRC="$ROOT/plugins/modules/service_registry"
( cd "$PLUGIN_SRC" && cargo build --quiet --release --target wasm32-wasip1 )

mkdir -p "$STAGE" "$TMP/scopes" "$TMP/plugins"
cp "$PLUGIN_SRC/target/wasm32-wasip1/release/service_registry.wasm" "$TMP/plugins/"
echo "ok: plugin module built ($(du -h "$TMP/plugins/service_registry.wasm" | cut -f1))"

# The key reaches the server through the environment, never the config file, so
# it cannot be captured in a screenshot of the admin page.
cat > "$TMP/config.toml" <<EOF
[server]
host = "127.0.0.1"
port = $PORT

[database]
path = "$TMP/qm.db"

[org]
id = "acme"
name = "Acme"
admin = "admin"
security_posture = "auto"

[harness]
kind = "openai"
endpoint = "$QM_E2E_ENDPOINT"
api_key_env = "QM_HARNESS_API_KEY"
model = "$QM_E2E_MODEL"
timeout_secs = 240
max_steps = 14

[sandbox]
root_dir = "$TMP/scopes"

[cron]
enabled = false

[email]
mode = "console"

[auth]
membership_mode = "allowlist"
admin_email = "admin@acme.test"
public_url = "$BASE"

[plugins]
dir = "$TMP/plugins"

[[plugins.tools]]
name = "lookup_service"
description = "Look up who owns a service, its runbook, and who is on call."
module = "service_registry.wasm"
parameters = '{"type":"object","properties":{"service":{"type":"string","description":"The service name, e.g. billing"}},"required":["service"]}'
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

# ---- perform the tutorial -------------------------------------------------

set +e
BASE="$BASE" OUT="$STAGE" LOG="$TMP/server.log" \
  MODEL="$QM_E2E_MODEL" ENDPOINT="$QM_E2E_ENDPOINT" \
  node scripts/tutorial_e2e.mjs
STATUS=$?
set -e

echo
if [ $STATUS -ne 0 ]; then
  # Leave the previous good guide in place; keep the broken run for inspection.
  BROKEN="$ROOT/e2e-reports/tutorial-failed-$(date -u +%Y%m%dT%H%M%SZ)"
  mkdir -p "$(dirname "$BROKEN")"
  cp -R "$STAGE" "$BROKEN"
  echo "TUTORIAL HAD FAILURES — docs/ left untouched." >&2
  echo "The failed run is at ${BROKEN#"$ROOT"/} for inspection." >&2
  exit $STATUS
fi

# Every chapter passed: replace the committed guide. Only the generated files
# are removed, so anything else under docs/ survives a regeneration.
mkdir -p "$FINAL"
rm -f "$FINAL"/*.png "$FINAL"/index.html "$FINAL"/README.md "$FINAL"/tutorial.json
cp -R "$STAGE"/. "$FINAL"/

# GitHub Pages runs Jekyll by default, which ignores files it does not
# recognise; .nojekyll turns that off so every asset is served as-is.
touch "$FINAL/.nojekyll"

# The server log holds live sign-in links, so it is deliberately NOT copied
# next to a committed guide.

echo "TUTORIAL GENERATED → docs/index.html"
echo
echo "  $(find "$FINAL" -name '*.png' | wc -l | tr -d ' ') screenshots"
echo "  docs/README.md    renders on GitHub"
echo "  docs/index.html   for GitHub Pages (Settings → Pages → main /docs)"
echo
echo "Commit it:  git add docs && git commit -m 'docs: regenerate the tutorial'"
