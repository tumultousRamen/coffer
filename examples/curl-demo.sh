#!/usr/bin/env bash
# examples/curl-demo.sh — trial-mode REST lifecycle demo.
#
# Exercises the five /v1/credentials endpoints against a running
# `make run` binary. Trial-mode auth: the X-User-Id header is the
# caller identity. Production gateway will JWT-verify and inject
# this header (ADR 0007 §2).
#
# Expected end state: POST 201 → GET list 200 (1 entry) → GET by-id
# 200 → PUT 204 → DELETE 204 → GET by-id 404. Each step prints the
# status code; a non-2xx (except the deliberate final 404) is a fail.
#
# Prerequisites:
#   * `make run` running in another terminal (vault binary on :8080).
#   * `jq` on PATH for parsing the create response.
#   * `base64` on PATH (BSD or GNU).
#
# Usage:
#   bash examples/curl-demo.sh           # default host http://localhost:8080
#   COFFER_REST_BASE=http://… bash …     # override host
#
set -euo pipefail

BASE="${COFFER_REST_BASE:-http://localhost:8080}"
USER_ID="${COFFER_DEMO_USER:-divya-demo}"
PROVIDER="${COFFER_DEMO_PROVIDER:-s3}"
LABEL="curl-demo-$(date +%s)"

# Encode a fake AWS-secret-shaped JSON payload as base64 for the
# secret field. The REST handler's []byte tag base64-decodes it on
# the way in; AES-GCM encrypts the raw bytes server-side.
SECRET_BYTES='{"access_key_id":"AKIAEXAMPLE","secret_access_key":"sk-EXAMPLE"}'
SECRET_B64=$(printf %s "$SECRET_BYTES" | base64 | tr -d '\n')

bold() { printf '\033[1m%s\033[0m\n' "$*"; }
hr()   { printf -- '----------------------------------------\n'; }

bold "1. POST /v1/credentials  (create)"
CREATE_BODY=$(jq -nc \
    --arg p "$PROVIDER" --arg l "$LABEL" --arg s "$SECRET_B64" \
    '{provider:$p, label:$l, secret:$s, metadata:{region:"us-west-1"}}')
CREATE_RESP=$(curl -sS -X POST "$BASE/v1/credentials" \
    -H "X-User-Id: $USER_ID" \
    -H "Content-Type: application/json" \
    -w "\n__HTTP__%{http_code}" \
    -d "$CREATE_BODY")
echo "$CREATE_RESP" | sed 's/__HTTP__/  HTTP /'
CREATE_JSON=$(echo "$CREATE_RESP" | sed 's/__HTTP__.*//')
CRED_ID=$(echo "$CREATE_JSON" | jq -r '.id')
[ -n "$CRED_ID" ] && [ "$CRED_ID" != "null" ] || { echo "no id in response"; exit 1; }
echo "  id=$CRED_ID"
hr

bold "2. GET /v1/credentials  (list)"
curl -sS "$BASE/v1/credentials" -H "X-User-Id: $USER_ID" -w "\n  HTTP %{http_code}\n"
hr

bold "3. GET /v1/credentials/{id}  (detail)"
curl -sS "$BASE/v1/credentials/$CRED_ID" -H "X-User-Id: $USER_ID" -w "\n  HTTP %{http_code}\n"
hr

bold "4. PUT /v1/credentials/{id}  (replace secret)"
REPLACE_SECRET=$(printf 'rotated-%s' "$(date +%s)" | base64 | tr -d '\n')
PUT_BODY=$(jq -nc --arg s "$REPLACE_SECRET" '{secret:$s, metadata:{region:"us-east-1"}}')
curl -sS -X PUT "$BASE/v1/credentials/$CRED_ID" \
    -H "X-User-Id: $USER_ID" \
    -H "Content-Type: application/json" \
    -w "  HTTP %{http_code}\n" \
    -d "$PUT_BODY"
hr

bold "5. GET /v1/credentials/{id}  (verify still present)"
curl -sS "$BASE/v1/credentials/$CRED_ID" -H "X-User-Id: $USER_ID" -w "\n  HTTP %{http_code}\n"
hr

bold "6. DELETE /v1/credentials/{id}"
curl -sS -X DELETE "$BASE/v1/credentials/$CRED_ID" \
    -H "X-User-Id: $USER_ID" -w "  HTTP %{http_code}\n"
hr

bold "7. GET /v1/credentials/{id}  (verify 404 post-delete)"
curl -sS "$BASE/v1/credentials/$CRED_ID" -H "X-User-Id: $USER_ID" -w "\n  HTTP %{http_code}\n"
hr

bold "demo complete"
