#!/usr/bin/env bash
# scripts/demo/02-worker-fetch.sh — Phase 4 + 5 of demo.md, automated.
#
# Demonstrates the worker-facing gRPC path against a vault binary (local
# or deployed). What it exercises:
#   * Capability token minting via cmd/mint-grant (uses your local privkey)
#   * gRPC GetCredentials with grant token
#   * ed25519 signature verify at transport (interceptor) AND service layer
#     (defense in depth per PRD 0006 update)
#   * Per-credential-ID scope enforcement; reject-whole on unauthorized
#   * Envelope decrypt: DEK cache lookup → KMS Decrypt if cold → AES-GCM
#     Open with AAD verification
#   * The returned plaintext successfully authenticates against real S3
#     (proves end-to-end correctness, not just code passes tests)
#
# Output is PASS/FAIL per step.
#
# Prerequisites:
#   * Vault reachable; both REST and gRPC endpoints
#   * COFFER_GRANT_PRIVKEY_PEM in .env.local (or set in env directly)
#   * COFFER_TEST_AWS_KEY_ID + COFFER_TEST_AWS_SECRET (for the S3 POST + the
#     final aws s3 ls)
#   * jq, curl, grpcurl, aws, base64 on PATH
#
# Flags:
#   --host <url>           REST base URL (default $COFFER_REST_BASE or localhost:8080)
#
# Env vars:
#   COFFER_GRPC_HOST       gRPC host:port (default localhost:8443).
#                          For deployed: <nlb-dns>:443
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

REST_BASE="${HOST_OVERRIDE:-${COFFER_REST_BASE:-http://localhost:8080}}"
REST_BASE="${REST_BASE%/}"
GRPC_HOST="${COFFER_GRPC_HOST:-localhost:8443}"
USER_ID="${COFFER_TEST_USER_ID:-$(uuidgen | tr 'A-Z' 'a-z')}"   # tenants.user_id is UUID (ADR 0005)
REGION="${COFFER_TEST_AWS_REGION:-us-west-1}"

# Source .env.local for COFFER_GRANT_PRIVKEY_PEM if available
if [ -f .env.local ] && [ -z "${COFFER_GRANT_PRIVKEY_PEM:-}" ]; then
  set -a; source .env.local; set +a
fi

if [ -z "${COFFER_TEST_AWS_KEY_ID:-}" ] || [ -z "${COFFER_TEST_AWS_SECRET:-}" ]; then
  echo "ENV: COFFER_TEST_AWS_KEY_ID and COFFER_TEST_AWS_SECRET must be set"
  exit 2
fi
if [ -z "${COFFER_GRANT_PRIVKEY_PEM:-}" ]; then
  echo "ENV: COFFER_GRANT_PRIVKEY_PEM not set; run 'make gen-keys' and paste into .env.local"
  exit 2
fi
for bin in jq curl base64 grpcurl aws; do
  command -v "$bin" >/dev/null || { echo "missing dependency: $bin"; exit 2; }
done

TOTAL=5
PASS_COUNT=0
GOOD_ID=""

pass() { printf '[%d/%d] %-55s PASS  %s\n' "$1" "$TOTAL" "$2" "${3:-}"; PASS_COUNT=$((PASS_COUNT+1)); }
fail() { printf '[%d/%d] %-55s FAIL\n  %s\n' "$1" "$TOTAL" "$2" "$3"; cleanup; exit 1; }

cleanup() {
  [ -n "$GOOD_ID" ] && curl -s -X DELETE "$REST_BASE/v1/credentials/$GOOD_ID" \
    -H "X-User-Id: $USER_ID" >/dev/null 2>&1 || true
}

echo "── Demo phase 4-5: worker gRPC fetch against $GRPC_HOST ──"

# ─────────────────────────────────────────────────────────────────────
# Step 1: POST a real S3 credential so we have something to fetch
# ─────────────────────────────────────────────────────────────────────
SECRET_B64=$(printf '{"access_key_id":"%s","secret_access_key":"%s"}' \
  "$COFFER_TEST_AWS_KEY_ID" "$COFFER_TEST_AWS_SECRET" | base64)
BODY=$(jq -nc --arg s "$SECRET_B64" --arg r "$REGION" \
  '{provider:"s3", label:"demo-worker-fetch", secret:$s, metadata:{region:$r}}')

RESP=$(curl -s -X POST "$REST_BASE/v1/credentials" \
  -H "X-User-Id: $USER_ID" -H "Content-Type: application/json" -d "$BODY")
GOOD_ID=$(printf '%s' "$RESP" | jq -r .id 2>/dev/null || true)
[ -n "$GOOD_ID" ] && [ "$GOOD_ID" != "null" ] || fail 1 "POST a credential to fetch" "no id in response: $RESP"
pass 1 "POST seed credential" "id=$GOOD_ID"

# ─────────────────────────────────────────────────────────────────────
# Step 2: Mint a capability token authorizing GOOD_ID for USER_ID
# ─────────────────────────────────────────────────────────────────────
TOKEN=$(go run ./cmd/mint-grant --user-id "$USER_ID" --ids "$GOOD_ID" --ttl 15m 2>/dev/null || true)
[ -n "$TOKEN" ] || fail 2 "Mint capability token" "mint-grant returned empty"
# Sanity: looks like a JWT (three base64 segments joined by dots)
DOTS=$(printf '%s' "$TOKEN" | tr -cd '.' | wc -c | tr -d ' ')
[ "$DOTS" = "2" ] || fail 2 "Mint capability token" "doesn't look like JWT: $TOKEN"
pass 2 "Mint ed25519-signed grant token" "ttl=15m, scope=[$GOOD_ID]"

# ─────────────────────────────────────────────────────────────────────
# Step 3: gRPC GetCredentials with valid token
# ─────────────────────────────────────────────────────────────────────
GRPC_REQ=$(jq -nc --arg t "$TOKEN" --arg id "$GOOD_ID" \
  '{grant_token:$t, credential_ids:[$id]}')

GRPC_RESP=$(grpcurl -plaintext -d "$GRPC_REQ" \
  "$GRPC_HOST" coffer.v1.Vault/GetCredentials 2>&1 || true)
if printf '%s' "$GRPC_RESP" | grep -q "code = "; then
  fail 3 "gRPC GetCredentials (valid token)" "$GRPC_RESP"
fi
RETURNED_ID=$(printf '%s' "$GRPC_RESP" | jq -r '.credentials[0].id' 2>/dev/null || true)
[ "$RETURNED_ID" = "$GOOD_ID" ] || fail 3 "gRPC GetCredentials" "expected id $GOOD_ID, got $RETURNED_ID"
pass 3 "gRPC fetch returns plaintext" "id=$RETURNED_ID"

# ─────────────────────────────────────────────────────────────────────
# Step 4: Wrong-scope token → PermissionDenied (proves reject-whole)
# ─────────────────────────────────────────────────────────────────────
EVIL_ID=$(uuidgen 2>/dev/null | tr 'A-Z' 'a-z' || python3 -c 'import uuid;print(uuid.uuid4())')
EVIL_TOKEN=$(go run ./cmd/mint-grant --user-id "$USER_ID" --ids "$EVIL_ID" --ttl 15m 2>/dev/null || true)
EVIL_REQ=$(jq -nc --arg t "$EVIL_TOKEN" --arg id "$GOOD_ID" \
  '{grant_token:$t, credential_ids:[$id]}')

EVIL_RESP=$(grpcurl -plaintext -d "$EVIL_REQ" \
  "$GRPC_HOST" coffer.v1.Vault/GetCredentials 2>&1 || true)
echo "$EVIL_RESP" | grep -qE 'PermissionDenied|code = (Permission|7)' \
  || fail 4 "wrong-scope token → PermissionDenied" "got: $EVIL_RESP"
pass 4 "Wrong-scope token → PermissionDenied" "reject-whole rule honored"

# ─────────────────────────────────────────────────────────────────────
# Step 5: Use returned plaintext to actually list S3 buckets
# ─────────────────────────────────────────────────────────────────────
SECRET_RAW=$(printf '%s' "$GRPC_RESP" | jq -r '.credentials[0].secret' | base64 -d)
KEY=$(printf '%s' "$SECRET_RAW" | jq -r .access_key_id)
SEC=$(printf '%s' "$SECRET_RAW" | jq -r .secret_access_key)

[ "$KEY" = "$COFFER_TEST_AWS_KEY_ID" ] \
  || fail 5 "round-trip verify" "decrypted access_key_id ≠ originally POSTed"

LS_OUT=$(AWS_ACCESS_KEY_ID="$KEY" AWS_SECRET_ACCESS_KEY="$SEC" \
  aws s3 ls --region "$REGION" 2>&1 || true)
if printf '%s' "$LS_OUT" | grep -qi "InvalidAccessKeyId\|SignatureDoesNotMatch\|Forbidden"; then
  fail 5 "aws s3 ls with returned creds" "AWS rejected: $LS_OUT"
fi
BUCKET_COUNT=$(printf '%s' "$LS_OUT" | grep -cE '^[0-9]{4}-[0-9]{2}-[0-9]{2}' || true)
pass 5 "End-to-end: returned plaintext authenticates against S3" "buckets visible: $BUCKET_COUNT"

# ─────────────────────────────────────────────────────────────────────
# Cleanup
# ─────────────────────────────────────────────────────────────────────
cleanup
echo ""
echo "All $TOTAL/$TOTAL steps passed. Demo phases 4-5 complete."
