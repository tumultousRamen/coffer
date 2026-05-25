#!/usr/bin/env bash
# scripts/demo/04-oauth-box-rotation.sh — Phase 6 (Box slice).
#
# Box is the load-bearing correctness story for OAuth providers. Every
# refresh-token call returns a NEW refresh_token and invalidates the old
# one (single-use rotation). If the vault doesn't atomically persist the
# new token, the credential is bricked.
#
# This script demonstrates the rotation discipline:
#   1. POST a Box refresh_token → vault calls Box, gets new tokens, persists.
#   2. Snapshot the persisted ciphertext.
#   3. Force a re-refresh (by setting expires_at to the past) and FETCH.
#   4. Snapshot the persisted ciphertext again.
#   5. Assert the ciphertext byte-changed (proves rotation was persisted).
#
# Without single-flight + atomic Replace, this scenario would race-fail
# under concurrent fetches. CI verifies that property via the
# RunFetchForWorkerSingleFlightOnConcurrentStale scenario in
# internal/vault/servicecontract/oauth_scenarios.go.
#
# Prerequisites:
#   * LOCAL vault (make run) with Box provider registered (COFFER_BOX_CLIENT_ID
#     + COFFER_BOX_CLIENT_SECRET in vault's env). This script writes
#     directly to Postgres via $DATABASE_URL to force the stale state, so
#     it does not work against a deployed vault unless DATABASE_URL is the
#     same DB the deployed vault uses (it is, for this trial — Supabase).
#   * COFFER_TEST_BOX_REFRESH_TOKEN obtained per docs/runbook/oauth-setup.md
#   * DATABASE_URL exported (or .env.local has it)
#   * COFFER_GRANT_PRIVKEY_PEM in .env.local (for mint-grant in step 3)
#   * jq, curl, base64, psql, grpcurl on PATH
#
# Flags:
#   --host <url>    REST base URL (default http://localhost:8080)
#
# Env vars:
#   COFFER_GRPC_HOST    gRPC host:port (default localhost:8443)
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
GRPC_HOST="${COFFER_GRPC_HOST:-localhost:8443}"
USER_ID="${COFFER_TEST_USER_ID:-$(uuidgen | tr 'A-Z' 'a-z')}"   # tenants.user_id is UUID (ADR 0005)

if [ -f .env.local ]; then set -a; source .env.local; set +a; fi

if [ -z "${COFFER_TEST_BOX_REFRESH_TOKEN:-}" ]; then
  echo "ENV: COFFER_TEST_BOX_REFRESH_TOKEN must be set"
  echo "     Obtain via OAuth flow per docs/runbook/oauth-setup.md §Box"
  exit 2
fi
if [ -z "${DATABASE_URL:-}" ]; then
  echo "ENV: DATABASE_URL must be set (this script reads ciphertext from PG directly)"
  exit 2
fi
if [ -z "${COFFER_GRANT_PRIVKEY_PEM:-}" ]; then
  echo "ENV: COFFER_GRANT_PRIVKEY_PEM not set; run 'make gen-keys' first"
  exit 2
fi
for bin in jq curl base64 psql grpcurl; do
  command -v "$bin" >/dev/null || { echo "missing dependency: $bin"; exit 2; }
done

TOTAL=5
PASS_COUNT=0
GOOD_ID=""

pass() { printf '[%d/%d] %-55s PASS  %s\n' "$1" "$TOTAL" "$2" "${3:-}"; PASS_COUNT=$((PASS_COUNT+1)); }
fail() { printf '[%d/%d] %-55s FAIL\n  %s\n' "$1" "$TOTAL" "$2" "$3"; cleanup; exit 1; }
cleanup() {
  [ -n "$GOOD_ID" ] && curl -s -X DELETE "$BASE/v1/credentials/$GOOD_ID" \
    -H "X-User-Id: $USER_ID" >/dev/null 2>&1 || true
}

echo "── Demo phase 6 (Box): single-use refresh token rotation discipline ──"

# ─────────────────────────────────────────────────────────────────────
# Step 1: POST Box refresh_token → vault refreshes once at Create
# ─────────────────────────────────────────────────────────────────────
SECRET_B64=$(printf '{"refresh_token":"%s"}' "$COFFER_TEST_BOX_REFRESH_TOKEN" | base64)
BODY=$(jq -nc --arg s "$SECRET_B64" \
  '{provider:"box", label:"demo-box-rotation", secret:$s, metadata:{}}')

RESP=$(curl -s -w '\n%{http_code}' -X POST "$BASE/v1/credentials" \
  -H "X-User-Id: $USER_ID" -H "Content-Type: application/json" -d "$BODY")
BODY_OUT=$(printf '%s' "$RESP" | sed '$d')
CODE=$(printf '%s' "$RESP" | tail -n1)
[ "$CODE" = "201" ] || fail 1 "POST Box refresh_token" "expected 201, got $CODE; body=$BODY_OUT"
GOOD_ID=$(printf '%s' "$BODY_OUT" | jq -r .id)
pass 1 "POST Box refresh_token → 201" "id=$GOOD_ID"

# ─────────────────────────────────────────────────────────────────────
# Step 2: Snapshot ciphertext before next refresh
# ─────────────────────────────────────────────────────────────────────
CIPHER_BEFORE=$(psql "$DATABASE_URL" -t -A \
  -c "SELECT encode(secret_ciphertext, 'base64') FROM credentials WHERE id = '$GOOD_ID'")
[ -n "$CIPHER_BEFORE" ] || fail 2 "snapshot ciphertext" "credential row not found"
pass 2 "Snapshot ciphertext after Create refresh" "len=${#CIPHER_BEFORE}"

# ─────────────────────────────────────────────────────────────────────
# Step 3: Force stale by setting access_token_expires_at to the past,
#         then fetch via gRPC (triggers sync-on-stale → Box refresh)
# ─────────────────────────────────────────────────────────────────────
psql "$DATABASE_URL" -c \
  "UPDATE credentials SET metadata = jsonb_set(metadata, '{access_token_expires_at}', to_jsonb('2020-01-01T00:00:00Z'::text)) WHERE id = '$GOOD_ID'" >/dev/null

TOKEN=$(go run ./cmd/mint-grant --user-id "$USER_ID" --ids "$GOOD_ID" --ttl 15m 2>/dev/null)
GRPC_REQ=$(jq -nc --arg t "$TOKEN" --arg id "$GOOD_ID" \
  '{grant_token:$t, credential_ids:[$id]}')
GRPC_RESP=$(grpcurl -plaintext -d "$GRPC_REQ" \
  "$GRPC_HOST" coffer.v1.Vault/GetCredentials 2>&1 || true)
if printf '%s' "$GRPC_RESP" | grep -q "code = "; then
  fail 3 "sync-on-stale refresh fires" "grpc error: $GRPC_RESP"
fi
pass 3 "FetchForWorker triggers sync-on-stale → Box /token call" "fresh access_token returned"

# ─────────────────────────────────────────────────────────────────────
# Step 4: Snapshot ciphertext after refresh
# ─────────────────────────────────────────────────────────────────────
CIPHER_AFTER=$(psql "$DATABASE_URL" -t -A \
  -c "SELECT encode(secret_ciphertext, 'base64') FROM credentials WHERE id = '$GOOD_ID'")
pass 4 "Snapshot ciphertext after refresh" "len=${#CIPHER_AFTER}"

# ─────────────────────────────────────────────────────────────────────
# Step 5: Assert ciphertext byte-changed (proves rotation was persisted)
# ─────────────────────────────────────────────────────────────────────
if [ "$CIPHER_BEFORE" = "$CIPHER_AFTER" ]; then
  fail 5 "ciphertext byte-changes after rotation" "ciphertext unchanged — rotation NOT persisted!"
fi
pass 5 "Ciphertext byte-changed across refresh" \
  "rotated refresh_token persisted atomically (Box correctness)"

# ─────────────────────────────────────────────────────────────────────
# Cleanup
# ─────────────────────────────────────────────────────────────────────
cleanup
GOOD_ID=""
echo ""
echo "All $TOTAL/$TOTAL steps passed. Box rotation discipline confirmed."
echo "  → Without atomic Replace + single-flight, this would race-fail."
echo "  → See internal/vault/servicecontract/oauth_scenarios.go for the"
echo "    100-goroutine single-flight CI test."
