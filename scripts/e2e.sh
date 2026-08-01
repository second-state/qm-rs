#!/usr/bin/env bash
# Run the live end-to-end suite against a real model.
#
# These are the specs the original TypeScript project runs as its e2e suite,
# ported to this codebase — the agent loop in process, and the same behaviour
# over HTTP. Unlike `tests/smoke_test.sh`, this one costs money and needs
# network: every turn is a real model call.
#
#   cp .env.e2e.example .env.e2e   # then fill it in
#   bash scripts/e2e.sh            # everything
#   bash scripts/e2e.sh execute    # only tests whose name contains "execute"
#
# Credentials come from .env.e2e, which is gitignored and chmod 600. The values
# are never printed.
set -euo pipefail
set +m

cd "$(dirname "$0")/.."

if [ ! -f .env.e2e ]; then
  cat >&2 <<'MSG'
No .env.e2e found.

  cp .env.e2e.example .env.e2e
  $EDITOR .env.e2e

It needs QM_E2E_ENDPOINT, QM_E2E_API_KEY and QM_E2E_MODEL.
MSG
  exit 1
fi

# shellcheck disable=SC1091
source .env.e2e

for var in QM_E2E_ENDPOINT QM_E2E_API_KEY QM_E2E_MODEL; do
  if [ -z "${!var:-}" ]; then
    echo "FAIL: $var is not set in .env.e2e" >&2
    exit 1
  fi
done

# Report the endpoint and model, never the key.
echo "endpoint: $QM_E2E_ENDPOINT"
echo "model:    $QM_E2E_MODEL"
echo "key:      (set, ${#QM_E2E_API_KEY} chars)"
echo

# Reachability first, so a bad endpoint fails in seconds with a clear message
# rather than as a wall of timed-out turns.
PROBE="$(curl -s -o /dev/null -w '%{http_code}' -X POST "$QM_E2E_ENDPOINT/chat/completions" \
  -H "Authorization: Bearer $QM_E2E_API_KEY" \
  -H 'content-type: application/json' \
  -d "{\"model\":\"$QM_E2E_MODEL\",\"messages\":[{\"role\":\"user\",\"content\":\"ping\"}],\"max_tokens\":5}")"
if [ "$PROBE" != "200" ]; then
  echo "FAIL: the gateway returned $PROBE for $QM_E2E_MODEL — check the endpoint, key and model" >&2
  exit 1
fi
echo "ok: gateway reachable and the model answers"
echo

# Turns are slow and the gateway may rate-limit, so keep concurrency modest.
# Override with E2E_THREADS=1 to serialise.
THREADS="${E2E_THREADS:-4}"

exec cargo test --test e2e ${1:+"$1"} -- --nocapture --test-threads="$THREADS"
