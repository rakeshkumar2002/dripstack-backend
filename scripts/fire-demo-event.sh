#!/usr/bin/env bash
# Fire the sample Metasys API-error event at the inbound webhook with a valid
# HMAC signature, kicking off the whole sequence. Run `uv run seed` first.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [[ ! -f "$HERE/.demo-env" ]]; then
  echo "✗ $HERE/.demo-env not found. Run 'uv run seed' first." >&2
  exit 1
fi
# shellcheck disable=SC1091
source "$HERE/.demo-env"

PAYLOAD_FILE="$HERE/sample-event.json"
BODY="$(cat "$PAYLOAD_FILE")"

# Generic webhook signature scheme: hex HMAC-SHA256 of the raw body.
SIG="$(printf '%s' "$BODY" | openssl dgst -sha256 -hmac "$SIGNING_SECRET" | sed 's/^.* //')"

URL="${INGEST_BASE:-http://localhost:4000}/api/v1/ingest/${EVENT_SOURCE_ID}"
echo "→ POST $URL"

curl -sS -X POST "$URL" \
  -H "content-type: application/json" \
  -H "x-dripstack-signature: sha256=${SIG}" \
  --data-binary "$BODY"

echo
echo "✓ Event fired. Watch it flow:"
echo "  • Rendered email:  ${INGEST_BASE:-http://localhost:4000}/dev/emails"
echo "  • Temporal UI:     http://localhost:8233"
echo "  • Dashboard runs:  http://localhost:3000/runs"
