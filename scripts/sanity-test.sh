#!/usr/bin/env bash
# scripts/sanity-test.sh — REST lifecycle sanity walker (PRD 0008.5).
#
# Walks POST → GET → POST (bad) → GET → PUT → DELETE against a vault
# binary listening on $COFFER_REST_BASE (default http://localhost:8080).
# Verifies the full provider-validation + KMS + Postgres chain end to
# end with real AWS S3 credentials, in one PASS/FAIL line per step.
#
# Important divergence from the PRD draft: the shipped REST contract
# (internal/transport/rest/errors.go + internal/vault/service.go)
# returns 422 + reason for invalid provider credentials and persists
# NO row. The PRD draft assumed 201 + status="failed" + a follow-up
# PUT to fix the row; that flow does not exist in code. This script
# verifies what the code actually does.
#
# Prerequisites:
#   * `make run` listening on :8080 in another terminal.
#   * Migrations applied (`make migrate-up`).
#   * Real AWS access key + secret with at least s3:ListAllMyBuckets:
#       COFFER_TEST_AWS_KEY_ID
#       COFFER_TEST_AWS_SECRET
#       COFFER_TEST_AWS_REGION   (default us-west-1)
#   * `jq`, `curl`, `base64` on PATH.
#
# Optional:
#   COFFER_REST_BASE      override host (default http://localhost:8080)
#   COFFER_TEST_USER_ID   override caller (default sanity-test-user)
#
# Flags:
#   --host <url>          override base URL (e.g. http://<alb-dns>).
#                         Takes precedence over COFFER_REST_BASE.
#                         Lets the same script verify localhost and a
#                         deployed ECS service with identical output
#                         (PRD 0009 §4).
#
# Exit codes: 0 on full success; non-zero on the first failing step.
set -euo pipefail

HOST_OVERRIDE=""
while [ $# -gt 0 ]; do
  case "$1" in
    --host)
      [ $# -ge 2 ] || { echo "--host requires a URL"; exit 2; }
      HOST_OVERRIDE="$2"
      shift 2
      ;;
    --host=*)
      HOST_OVERRIDE="${1#--host=}"
      shift
      ;;
    -h|--help)
      sed -n '1,/^set -euo/p' "$0" | sed 's/^#//'
      exit 0
      ;;
    *)
      echo "unknown arg: $1"
      exit 2
      ;;
  esac
done

BASE="${HOST_OVERRIDE:-${COFFER_REST_BASE:-http://localhost:8080}}"
BASE="${BASE%/}"   # strip trailing slash so $BASE$path doesn't double up
USER_ID="${COFFER_TEST_USER_ID:-sanity-test-user}"
REGION="${COFFER_TEST_AWS_REGION:-us-west-1}"

if [ -z "${COFFER_TEST_AWS_KEY_ID:-}" ] || [ -z "${COFFER_TEST_AWS_SECRET:-}" ]; then
  echo "ENV: COFFER_TEST_AWS_KEY_ID and COFFER_TEST_AWS_SECRET must be set"
  echo "     see docs/runbook/local-sanity.md §2 for the one-time IAM setup"
  exit 2
fi
for bin in jq curl base64; do
  command -v "$bin" >/dev/null 2>&1 || { echo "missing dependency: $bin"; exit 2; }
done

PASS_COUNT=0
TOTAL_STEPS=7
GOOD_ID=""

# Hardcoded garbage credentials — see PRD 0008.5 Implementation Decisions.
# Determinism: every developer's failure path is byte-identical. The
# AKIA-prefixed key passes the AWS SDK's surface-level shape check so
# the failure originates from STS / S3, not the client.
BAD_KEY="AKIAINVALIDTESTONLY01"
BAD_SECRET="garbage-secret-that-should-never-validate"

pass() { printf '[%d/%d] %-55s PASS  %s\n' "$1" "$TOTAL_STEPS" "$2" "${3:-}"; PASS_COUNT=$((PASS_COUNT+1)); }
fail() { printf '[%d/%d] %-55s FAIL\n  %s\n' "$1" "$TOTAL_STEPS" "$2" "$3"; exit 1; }

# encode_secret <access-key-id> <secret-access-key>
# Builds the JSON-shaped secret payload that S3Provider.Validate
# expects and base64-encodes it for the REST `secret` field. The
# nested JSON shape is pinned by S3Provider implementation, not by
# this script.
encode_secret() {
  printf '{"access_key_id":"%s","secret_access_key":"%s"}' "$1" "$2" \
    | base64 | tr -d '\n'
}

# curl_capture METHOD PATH [BODY]
# Prints `<http_code>\n<body>` so callers can split. -s silences the
# progress bar; -w prints status separately so jq sees clean JSON.
curl_capture() {
  local method="$1" path="$2" body="${3:-}"
  if [ -n "$body" ]; then
    curl -sS -X "$method" "$BASE$path" \
      -H "X-User-Id: $USER_ID" \
      -H "Content-Type: application/json" \
      -w "\n__HTTP__%{http_code}" \
      -d "$body"
  else
    curl -sS -X "$method" "$BASE$path" \
      -H "X-User-Id: $USER_ID" \
      -w "\n__HTTP__%{http_code}"
  fi
}

split_resp() {
  local raw="$1"
  RESP_BODY=$(printf '%s' "$raw" | sed 's/__HTTP__.*//')
  RESP_CODE=$(printf '%s' "$raw" | sed -n 's/.*__HTTP__\([0-9]*\)$/\1/p')
}

LABEL_SUFFIX="$(date +%s)"

# ────────────────────────────────────────────────────────────────────
# Step 1: POST with real S3 credentials → 201 + id
# ────────────────────────────────────────────────────────────────────
GOOD_SECRET_B64=$(encode_secret "$COFFER_TEST_AWS_KEY_ID" "$COFFER_TEST_AWS_SECRET")
BODY=$(jq -nc \
  --arg s "$GOOD_SECRET_B64" \
  --arg label "sanity-good-$LABEL_SUFFIX" \
  --arg region "$REGION" \
  '{provider:"s3", label:$label, secret:$s, metadata:{region:$region}}')
split_resp "$(curl_capture POST /v1/credentials "$BODY")"
if [ "$RESP_CODE" != "201" ]; then
  fail 1 "POST real S3 credentials" "expected 201, got $RESP_CODE; body=$RESP_BODY"
fi
GOOD_ID=$(echo "$RESP_BODY" | jq -r '.id')
if [ -z "$GOOD_ID" ] || [ "$GOOD_ID" = "null" ]; then
  fail 1 "POST real S3 credentials" "no id in response: $RESP_BODY"
fi
pass 1 "POST real S3 credentials" "201, id=$GOOD_ID"

# Cleanup hook — runs on any future failure so we don't leak rows.
cleanup() {
  if [ -n "$GOOD_ID" ]; then
    curl -sS -X DELETE "$BASE/v1/credentials/$GOOD_ID" \
      -H "X-User-Id: $USER_ID" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

# ────────────────────────────────────────────────────────────────────
# Step 2: POST with garbage keys → 422 + non-empty reason, no row
# ────────────────────────────────────────────────────────────────────
BAD_SECRET_B64=$(encode_secret "$BAD_KEY" "$BAD_SECRET")
BAD_BODY=$(jq -nc \
  --arg s "$BAD_SECRET_B64" \
  --arg label "sanity-bad-$LABEL_SUFFIX" \
  --arg region "$REGION" \
  '{provider:"s3", label:$label, secret:$s, metadata:{region:$region}}')
split_resp "$(curl_capture POST /v1/credentials "$BAD_BODY")"
if [ "$RESP_CODE" != "422" ]; then
  fail 2 "POST garbage credentials" "expected 422 (provider validation), got $RESP_CODE; body=$RESP_BODY"
fi
REASON=$(echo "$RESP_BODY" | jq -r '.reason // empty')
if [ -z "$REASON" ]; then
  fail 2 "POST garbage credentials" "422 ok but body missing reason: $RESP_BODY"
fi
pass 2 "POST garbage credentials" "422, reason=$REASON"

# ────────────────────────────────────────────────────────────────────
# Step 3: GET list → expect exactly 1 (the good one; bad was rejected)
# ────────────────────────────────────────────────────────────────────
split_resp "$(curl_capture GET /v1/credentials)"
if [ "$RESP_CODE" != "200" ]; then
  fail 3 "GET list after good + rejected POST" "expected 200, got $RESP_CODE; body=$RESP_BODY"
fi
COUNT=$(echo "$RESP_BODY" | jq '.credentials | length')
if [ "$COUNT" != "1" ]; then
  fail 3 "GET list after good + rejected POST" "expected 1 credential (bad POST rejected), got $COUNT; body=$RESP_BODY"
fi
pass 3 "GET list after good + rejected POST" "200, 1 credential"

# ────────────────────────────────────────────────────────────────────
# Step 4: GET by id → status="active"
# ────────────────────────────────────────────────────────────────────
split_resp "$(curl_capture GET "/v1/credentials/$GOOD_ID")"
if [ "$RESP_CODE" != "200" ]; then
  fail 4 "GET good credential by id" "expected 200, got $RESP_CODE; body=$RESP_BODY"
fi
STATUS=$(echo "$RESP_BODY" | jq -r '.status')
if [ "$STATUS" != "active" ]; then
  fail 4 "GET good credential by id" "expected status=active, got $STATUS; body=$RESP_BODY"
fi
pass 4 "GET good credential by id" "status=active"

# ────────────────────────────────────────────────────────────────────
# Step 5: PUT real keys (re-encrypts under tenant DEK) → 204
# ────────────────────────────────────────────────────────────────────
PUT_BODY=$(jq -nc \
  --arg s "$GOOD_SECRET_B64" \
  --arg region "$REGION" \
  '{secret:$s, metadata:{region:$region}}')
split_resp "$(curl_capture PUT "/v1/credentials/$GOOD_ID" "$PUT_BODY")"
if [ "$RESP_CODE" != "204" ]; then
  fail 5 "PUT replace secret (re-encrypt)" "expected 204, got $RESP_CODE; body=$RESP_BODY"
fi
pass 5 "PUT replace secret (re-encrypt)" "204"

# ────────────────────────────────────────────────────────────────────
# Step 6: DELETE → 204
# ────────────────────────────────────────────────────────────────────
split_resp "$(curl_capture DELETE "/v1/credentials/$GOOD_ID")"
if [ "$RESP_CODE" != "204" ]; then
  fail 6 "DELETE credential" "expected 204, got $RESP_CODE; body=$RESP_BODY"
fi
# Successfully deleted — clear so cleanup trap doesn't re-DELETE.
GOOD_ID=""
pass 6 "DELETE credential" "204"

# ────────────────────────────────────────────────────────────────────
# Step 7: GET list → empty
# ────────────────────────────────────────────────────────────────────
split_resp "$(curl_capture GET /v1/credentials)"
if [ "$RESP_CODE" != "200" ]; then
  fail 7 "GET list after DELETE" "expected 200, got $RESP_CODE; body=$RESP_BODY"
fi
COUNT=$(echo "$RESP_BODY" | jq '.credentials | length')
if [ "$COUNT" != "0" ]; then
  fail 7 "GET list after DELETE" "expected 0 credentials, got $COUNT; body=$RESP_BODY"
fi
pass 7 "GET list after DELETE" "200, 0 credentials"

echo
echo "All $PASS_COUNT/$TOTAL_STEPS steps passed."
