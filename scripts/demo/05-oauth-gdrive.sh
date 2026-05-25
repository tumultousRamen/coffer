#!/usr/bin/env bash
# scripts/demo/05-oauth-gdrive.sh — Phase 6 (Google Drive slice).
#
# Symmetric to scripts/demo/03-oauth-dropbox.sh but against Google Drive's
# OAuth flow at https://oauth2.googleapis.com/token. What it exercises:
#   * Provider.Refresh at Create time as the validation probe
#   * oauth2 common client form-encoded POST to Google
#   * Google's specific behavior: refresh tokens typically long-lived BUT
#     silently rotated under the 100-token-per-(account,client_id) cap and
#     invalidated after 6 months of disuse. Vault's code unconditionally
#     re-persists if Refresh response includes a refresh_token field, so
#     silent rotation is handled correctly.
#
# Prerequisites:
#   * Vault running with Google Drive provider registered (COFFER_GDRIVE_CLIENT_ID
#     + COFFER_GDRIVE_CLIENT_SECRET in vault's env)
#   * COFFER_TEST_GDRIVE_REFRESH_TOKEN obtained via OAuth Playground
#     (see docs/runbook/oauth-setup.md §Google Drive)
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

if [ -z "${COFFER_TEST_GDRIVE_REFRESH_TOKEN:-}" ]; then
  echo "ENV: COFFER_TEST_GDRIVE_REFRESH_TOKEN must be set"
  echo "     Obtain via OAuth Playground per docs/runbook/oauth-setup.md §Google Drive"
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

echo "── Demo phase 6 (Google Drive): broker-mode OAuth lifecycle ──"

# Step 1: POST refresh_token → 201, status=active
SECRET_B64=$(printf '{"refresh_token":"%s"}' "$COFFER_TEST_GDRIVE_REFRESH_TOKEN" | base64)
BODY=$(jq -nc --arg s "$SECRET_B64" \
  '{provider:"gdrive", label:"demo-gdrive", secret:$s, metadata:{}}')

RESP=$(curl -s -w '\n%{http_code}' -X POST "$BASE/v1/credentials" \
  -H "X-User-Id: $USER_ID" -H "Content-Type: application/json" -d "$BODY")
BODY_OUT=$(printf '%s' "$RESP" | sed '$d')
CODE=$(printf '%s' "$RESP" | tail -n1)
[ "$CODE" = "201" ] || fail 1 "POST GDrive refresh_token" "expected 201, got $CODE; body=$BODY_OUT"
GOOD_ID=$(printf '%s' "$BODY_OUT" | jq -r .id)
STATUS=$(printf '%s' "$BODY_OUT" | jq -r .status)
[ "$STATUS" = "active" ] || fail 1 "POST GDrive refresh_token" "expected status=active, got $STATUS"
pass 1 "POST GDrive refresh_token → 201 active" "id=$GOOD_ID"

# Step 2: GET shows provider=gdrive, status=active
GET_RESP=$(curl -s "$BASE/v1/credentials/$GOOD_ID" -H "X-User-Id: $USER_ID")
PROVIDER=$(printf '%s' "$GET_RESP" | jq -r .provider)
STATUS=$(printf '%s' "$GET_RESP" | jq -r .status)
[ "$PROVIDER" = "gdrive" ] || fail 2 "GET GDrive cred" "expected provider=gdrive, got $PROVIDER"
[ "$STATUS" = "active" ] || fail 2 "GET GDrive cred" "expected status=active, got $STATUS"
pass 2 "GET shows active state" "Google's /token endpoint accepted refresh_token"

# Step 3: DELETE → 204
DEL_CODE=$(curl -s -w '%{http_code}' -X DELETE "$BASE/v1/credentials/$GOOD_ID" \
  -H "X-User-Id: $USER_ID" -o /dev/null)
[ "$DEL_CODE" = "204" ] || fail 3 "DELETE GDrive cred" "expected 204, got $DEL_CODE"
GOOD_ID=""
pass 3 "DELETE GDrive cred" ""

echo ""
echo "All $TOTAL/$TOTAL steps passed. Google Drive provider lifecycle confirmed."
echo "  → Refresh tokens typically long-lived; silent rotation handled iff"
echo "    Google returns one in the Refresh response (vault re-persists)."
echo "  → For demonstrating ROTATION specifically, run 04-oauth-box-rotation.sh"
echo "    (Box always rotates; the demo is observable)."
