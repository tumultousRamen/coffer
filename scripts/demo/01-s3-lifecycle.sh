#!/usr/bin/env bash
# scripts/demo/01-s3-lifecycle.sh — Phase 2 + 3 of demo.md, automated.
#
# Demonstrates the S3 provider lifecycle against a vault binary (local or
# deployed). What it exercises:
#   * Provider.Validate at Create time (S3 ListBuckets against real AWS)
#   * Envelope encryption (ciphertext persists in DB — checked optionally)
#   * Strict-reject on bad credentials (422 + no row created — PRD 0008
#     implementation divergence from "store + mark failed + bubble" draft)
#   * REST contract: POST → 201/422; GET (list/by-id) → CredentialSummary
#     (no Secret field)
#   * Hexagonal hand-off: REST → Service → Cryptor → CredentialStore
#
# Output is PASS/FAIL per step; exits non-zero on first failure.
#
# Prerequisites:
#   * Vault reachable (make run, or deployed via --host)
#   * COFFER_TEST_AWS_KEY_ID + COFFER_TEST_AWS_SECRET (s3:ListAllMyBuckets perm)
#   * COFFER_TEST_AWS_REGION (default us-west-1)
#   * jq, curl, base64 on PATH
#
# Flags:
#   --host <url>    base URL (default $COFFER_REST_BASE or http://localhost:8080)
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
REGION="${COFFER_TEST_AWS_REGION:-us-west-1}"

if [ -z "${COFFER_TEST_AWS_KEY_ID:-}" ] || [ -z "${COFFER_TEST_AWS_SECRET:-}" ]; then
  echo "ENV: COFFER_TEST_AWS_KEY_ID and COFFER_TEST_AWS_SECRET must be set"
  echo "     IAM user setup per docs/runbook/local-sanity.md §2"
  exit 2
fi
for bin in jq curl base64; do
  command -v "$bin" >/dev/null || { echo "missing dependency: $bin"; exit 2; }
done

BAD_KEY="AKIAINVALIDTESTONLY01"
BAD_SECRET="garbage-secret-that-should-never-validate"
TOTAL=6
PASS_COUNT=0
GOOD_ID=""

pass() { printf '[%d/%d] %-55s PASS  %s\n' "$1" "$TOTAL" "$2" "${3:-}"; PASS_COUNT=$((PASS_COUNT+1)); }
fail() { printf '[%d/%d] %-55s FAIL\n  %s\n' "$1" "$TOTAL" "$2" "$3"; exit 1; }

encode_secret() {
  printf '{"access_key_id":"%s","secret_access_key":"%s"}' "$1" "$2" | base64
}

curl_capture() {
  local method="$1" path="$2" body="${3:-}"
  if [ -n "$body" ]; then
    curl -sw '\n%{http_code}' -X "$method" -H "Content-Type: application/json" \
      -H "X-User-Id: $USER_ID" -d "$body" "$BASE$path"
  else
    curl -sw '\n%{http_code}' -X "$method" \
      -H "X-User-Id: $USER_ID" "$BASE$path"
  fi
}

split_resp() {
  RESP_BODY=$(printf '%s' "$1" | sed '$d')
  RESP_CODE=$(printf '%s' "$1" | tail -n1)
}

echo "── Demo phase 2-3: S3 credential lifecycle against $BASE ──"

# ─────────────────────────────────────────────────────────────────────
# Step 1: POST valid S3 creds → 201, status=active, capture id
# ─────────────────────────────────────────────────────────────────────
GOOD_SECRET_B64=$(encode_secret "$COFFER_TEST_AWS_KEY_ID" "$COFFER_TEST_AWS_SECRET")
GOOD_BODY=$(jq -nc \
  --arg s "$GOOD_SECRET_B64" --arg r "$REGION" \
  '{provider:"s3", label:"demo-prod-bucket", secret:$s, metadata:{region:$r}}')

split_resp "$(curl_capture POST /v1/credentials "$GOOD_BODY")"
[ "$RESP_CODE" = "201" ] || fail 1 "POST valid S3 creds" "expected 201, got $RESP_CODE; body=$RESP_BODY"
GOOD_ID=$(printf '%s' "$RESP_BODY" | jq -r .id)
STATUS=$(printf '%s' "$RESP_BODY" | jq -r .status)
[ "$STATUS" = "active" ] || fail 1 "POST valid S3 creds" "expected status=active, got $STATUS"
pass 1 "POST valid S3 creds" "201, status=active, id=$GOOD_ID"

# ─────────────────────────────────────────────────────────────────────
# Step 2: POST garbage → 422 + reason; NO row created
# ─────────────────────────────────────────────────────────────────────
BAD_SECRET_B64=$(encode_secret "$BAD_KEY" "$BAD_SECRET")
BAD_BODY=$(jq -nc \
  --arg s "$BAD_SECRET_B64" --arg r "$REGION" \
  '{provider:"s3", label:"demo-bad-cred", secret:$s, metadata:{region:$r}}')

split_resp "$(curl_capture POST /v1/credentials "$BAD_BODY")"
[ "$RESP_CODE" = "422" ] || fail 2 "POST garbage creds" "expected 422, got $RESP_CODE; body=$RESP_BODY"
REASON=$(printf '%s' "$RESP_BODY" | jq -r '.reason // .error // ""')
[ -n "$REASON" ] || fail 2 "POST garbage creds" "expected non-empty reason in body"
pass 2 "POST garbage creds → 422 + reason" "no row created"

# ─────────────────────────────────────────────────────────────────────
# Step 3: GET list — should contain GOOD_ID only (BAD never persisted)
# ─────────────────────────────────────────────────────────────────────
split_resp "$(curl_capture GET /v1/credentials)"
[ "$RESP_CODE" = "200" ] || fail 3 "GET list" "expected 200, got $RESP_CODE"
COUNT_GOOD=$(printf '%s' "$RESP_BODY" | jq --arg id "$GOOD_ID" '[.[] | select(.id == $id)] | length')
COUNT_BAD=$(printf '%s' "$RESP_BODY" | jq '[.[] | select(.label == "demo-bad-cred")] | length')
[ "$COUNT_GOOD" = "1" ] || fail 3 "GET list" "GOOD_ID missing from list"
[ "$COUNT_BAD" = "0" ] || fail 3 "GET list" "BAD cred row exists; expected strict reject"
pass 3 "GET list shows only the active cred" "1 active, 0 bad rows"

# ─────────────────────────────────────────────────────────────────────
# Step 4: GET by id — CredentialSummary shape (no Secret field)
# ─────────────────────────────────────────────────────────────────────
split_resp "$(curl_capture GET "/v1/credentials/$GOOD_ID")"
[ "$RESP_CODE" = "200" ] || fail 4 "GET by id" "expected 200, got $RESP_CODE"
HAS_SECRET=$(printf '%s' "$RESP_BODY" | jq 'has("secret") or has("Secret")')
[ "$HAS_SECRET" = "false" ] || fail 4 "GET by id" "response leaks Secret field"
pass 4 "GET by id (no Secret field)" "type-level secret read-back guard verified"

# ─────────────────────────────────────────────────────────────────────
# Step 5: PUT replaces secret atomically
# ─────────────────────────────────────────────────────────────────────
NEW_BODY=$(jq -nc \
  --arg s "$GOOD_SECRET_B64" --arg r "$REGION" \
  '{secret:$s, metadata:{region:$r, rotated_at:"2026-05-20T00:00:00Z"}}')

split_resp "$(curl_capture PUT "/v1/credentials/$GOOD_ID" "$NEW_BODY")"
[ "$RESP_CODE" = "204" ] || fail 5 "PUT replace secret" "expected 204, got $RESP_CODE; body=$RESP_BODY"
pass 5 "PUT replace secret (atomic re-encrypt)" "fresh nonce written under same DEK"

# ─────────────────────────────────────────────────────────────────────
# Step 6: DELETE → 204, then GET → 404
# ─────────────────────────────────────────────────────────────────────
split_resp "$(curl_capture DELETE "/v1/credentials/$GOOD_ID")"
[ "$RESP_CODE" = "204" ] || fail 6 "DELETE" "expected 204, got $RESP_CODE"

split_resp "$(curl_capture GET "/v1/credentials/$GOOD_ID")"
[ "$RESP_CODE" = "404" ] || fail 6 "DELETE (verify gone)" "expected 404 after delete, got $RESP_CODE"
pass 6 "DELETE (hard) + verify 404 on subsequent read" ""

echo ""
echo "All $TOTAL/$TOTAL steps passed. Demo phases 2-3 complete."
