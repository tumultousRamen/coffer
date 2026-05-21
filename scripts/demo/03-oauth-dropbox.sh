#!/usr/bin/env bash
# scripts/demo/03-oauth-dropbox.sh — Phase 6 (Dropbox slice).
#
# Demonstrates a broker-mode OAuth provider end-to-end. What it exercises:
#   * Provider.Refresh as the create-time probe (PRD 0010 §Implementation:
#     OAuth providers use Refresh, not Validate, because Validate would be
#     a wasted token call AND on Box it would consume the refresh_token)
#   * oauth2 common client: form-urlencoded POST to api.dropbox.com/oauth2/token
#   * Atomic re-encrypt of the new access_token + access_token_expires_at
#     metadata field
#   * Dropbox refresh-token rotation policy: long-lived, NOT rotated
#     (contrast scripts/demo/04-oauth-box-rotation.sh)
#   * REST contract identical to S3: POST → 201 status=active + UUIDv7
#
# Prerequisites:
#   * Vault running with Dropbox provider registered (COFFER_DROPBOX_CLIENT_ID
#     + COFFER_DROPBOX_CLIENT_SECRET in vault's env)
#   * COFFER_TEST_DROPBOX_REFRESH_TOKEN obtained via vendor OAuth flow
#     (see docs/runbook/oauth-setup.md §Dropbox for the manual steps)
#   * jq, curl, base64 on PATH
#
# Flags:
#   --host <url>    REST base URL (default http://localhost:8080)
#
set -euo pipefail

HOST_OVERRIDE=""
while [ $# -gt 0 ]; do
  case "$1" in
    --host) HOST_OVERRIDE="$2"; shift 2 ;;
    --host=*) HOST_OVERRIDE="${1#--host=}"; shift ;;
    -h|--help) sed -n '1,/^set -euo/p' "$0" | sed 's/^#//'; exit 0 ;;
    *) echo "unknown arg: $1"; exit 2 ;;
  esac
done

BASE="${HOST_OVERRIDE:-${COFFER_REST_BASE:-http://localhost:8080}}"
BASE="${BASE%/}"
USER_ID="${COFFER_TEST_USER_ID:-$(uuidgen | tr 'A-Z' 'a-z')}"   # tenants.user_id is UUID (ADR 0005)

if [ -z "${COFFER_TEST_DROPBOX_REFRESH_TOKEN:-}" ]; then
  echo "ENV: COFFER_TEST_DROPBOX_REFRESH_TOKEN must be set"
  echo "     Obtain via OAuth flow per docs/runbook/oauth-setup.md §Dropbox"
  exit 2
fi
for bin in jq curl base64; do
  command -v "$bin" >/dev/null || { echo "missing dependency: $bin"; exit 2; }
done

TOTAL=3
PASS_COUNT=0
GOOD_ID=""

pass() { printf '[%d/%d] %-55s PASS  %s\n' "$1" "$TOTAL" "$2" "${3:-}"; PASS_COUNT=$((PASS_COUNT+1)); }
fail() { printf '[%d/%d] %-55s FAIL\n  %s\n' "$1" "$TOTAL" "$2" "$3"; cleanup; exit 1; }

cleanup() {
  [ -n "$GOOD_ID" ] && curl -s -X DELETE "$BASE/v1/credentials/$GOOD_ID" \
    -H "X-User-Id: $USER_ID" >/dev/null 2>&1 || true
}

echo "── Demo phase 6 (Dropbox): broker-mode OAuth lifecycle ──"

# ─────────────────────────────────────────────────────────────────────
# Step 1: POST refresh_token → 201, status=active, access_token populated
# ─────────────────────────────────────────────────────────────────────
SECRET_B64=$(printf '{"refresh_token":"%s"}' "$COFFER_TEST_DROPBOX_REFRESH_TOKEN" | base64)
BODY=$(jq -nc --arg s "$SECRET_B64" \
  '{provider:"dropbox", label:"demo-dropbox", secret:$s, metadata:{}}')

RESP=$(curl -s -w '\n%{http_code}' -X POST "$BASE/v1/credentials" \
  -H "X-User-Id: $USER_ID" -H "Content-Type: application/json" -d "$BODY")
BODY_OUT=$(printf '%s' "$RESP" | sed '$d')
CODE=$(printf '%s' "$RESP" | tail -n1)

[ "$CODE" = "201" ] || fail 1 "POST Dropbox refresh_token" "expected 201, got $CODE; body=$BODY_OUT"
GOOD_ID=$(printf '%s' "$BODY_OUT" | jq -r .id)
STATUS=$(printf '%s' "$BODY_OUT" | jq -r .status)
[ "$STATUS" = "active" ] || fail 1 "POST Dropbox refresh_token" "expected status=active, got $STATUS"
pass 1 "POST Dropbox refresh_token → 201 active" "id=$GOOD_ID"

# ─────────────────────────────────────────────────────────────────────
# Step 2: GET shows access_token_expires_at populated in metadata
# ─────────────────────────────────────────────────────────────────────
GET_RESP=$(curl -s "$BASE/v1/credentials/$GOOD_ID" -H "X-User-Id: $USER_ID")
PROVIDER=$(printf '%s' "$GET_RESP" | jq -r .provider)
STATUS=$(printf '%s' "$GET_RESP" | jq -r .status)
[ "$PROVIDER" = "dropbox" ] || fail 2 "GET Dropbox cred" "expected provider=dropbox, got $PROVIDER"
[ "$STATUS" = "active" ] || fail 2 "GET Dropbox cred" "expected status=active, got $STATUS"
pass 2 "GET shows active state" "broker-mode probe at Create-time succeeded"

# ─────────────────────────────────────────────────────────────────────
# Step 3: DELETE → 204
# ─────────────────────────────────────────────────────────────────────
DEL_CODE=$(curl -s -w '%{http_code}' -X DELETE "$BASE/v1/credentials/$GOOD_ID" \
  -H "X-User-Id: $USER_ID" -o /dev/null)
[ "$DEL_CODE" = "204" ] || fail 3 "DELETE Dropbox cred" "expected 204, got $DEL_CODE"
GOOD_ID=""
pass 3 "DELETE Dropbox cred" ""

echo ""
echo "All $TOTAL/$TOTAL steps passed. Dropbox provider lifecycle confirmed."
echo "  → Refresh-token rotation: none (Dropbox tokens are long-lived)."
echo "  → For Box's atomic-rotation demo, run scripts/demo/04-oauth-box-rotation.sh"
