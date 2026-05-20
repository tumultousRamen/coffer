# Runbook: Local sanity test

End-to-end verification that PRDs 0007 (REST transport) + 0008 (S3 provider) work against real Postgres + real KMS + real AWS S3. Follow once after a clean checkout; re-run any time the vault binary changes substantially.

Acceptance: `make sanity-test` prints all `PASS` lines and exits 0; the optional Phase C snippet completes with `aws s3 ls` returning your actual buckets.

## 1. Prerequisites (one-time)

- Go ≥ 1.22 (`go version`)
- AWS CLI v2 + SSO configured per the [foundation runbook](foundation.md) (`aws sso login --profile coffer-dev`)
- `psql` installed; `DATABASE_URL` in `.env.local` (per foundation runbook)
- `grpcurl` (`brew install grpcurl`) — only needed for the optional Phase C
- `jq`, `curl`, `base64` — standard on macOS; `brew install jq` if missing

## 2. One-time AWS IAM setup for test S3 credentials (~5 min)

> **What you're doing:** creating an AWS IAM user with a long-lived access key that the vault's S3 Provider will validate against. This is separate from the SSO identity the vault uses for KMS. AWS recommends avoiding long-term keys generally — but the whole point of this test is "can the vault validate user-supplied static keys", so the static key is the test fixture, not a workload pattern.

Steps (current AWS console UI as of May 2026; wording is approximate but the structure holds):

1. AWS Console → search **IAM** → IAM dashboard.
2. Left nav → **Users** → **Create user**.
3. **User name**: `coffer-test-s3` (any name works). Leave **Provide user access to the AWS Management Console** unchecked. Click **Next**.
4. **Set permissions** page → **Attach policies directly** → **Create policy** (opens a new tab).
5. Switch to the **JSON** tab and paste:
   ```json
   {
     "Version": "2012-10-17",
     "Statement": [
       {
         "Effect": "Allow",
         "Action": "s3:ListAllMyBuckets",
         "Resource": "*"
       }
     ]
   }
   ```
   > **Note:** the IAM action is `s3:ListAllMyBuckets`, even though the AWS SDK call is `ListBuckets`. `s3:ListBuckets` is **not** a valid IAM action; a policy using it would silently fail.
6. **Next** → name the policy `CofferTestS3ListBuckets` → **Create policy**. Close the tab.
7. Back on **Set permissions**, refresh the policy list and tick `CofferTestS3ListBuckets`. **Next** → **Create user**.
8. From the **Users** list → click `coffer-test-s3` → **Security credentials** tab → scroll to **Access keys** → **Create access key**.
9. **Access key best practices & alternatives**: select **Third-party service**, tick the acknowledgment checkbox at the bottom. **Next**.
10. (Optional) Description tag like `coffer-local-sanity-test`. **Create access key**.
11. **Retrieve access keys**: copy **Access key** and reveal+copy **Secret access key**. Save both in 1Password — **the secret can never be retrieved from the console again**. **Done**.

## 3. Generate the capability-token keypair (one-time)

```bash
make gen-keys
```

Two PEM blocks print to stdout. Open `.env.local` and paste the **PUBLIC** block between the `$'...'` markers of `COFFER_GRANT_PUBKEY_PEM`, and the **PRIVATE** block between the markers of `COFFER_GRANT_PRIVKEY_PEM`. The `$'...'` quoting preserves the embedded newlines when the Makefile sources the file. Save.

> **Why both keys are in `.env.local`:** trial-only convenience. In production, the private key lives at the control-plane signing service and the vault sees only the public half (ADR 0002). The `cmd/mint-grant` CLI exists so you can locally mint tokens for grpcurl — it has no production analogue.

## 4. Apply database migrations (if not already)

```bash
make migrate-up
```

## 5. Run the sanity test

**Terminal A** — start the vault:
```bash
make run
# wait for the startup log; the binary listens on :8080 (REST) and :8443 (gRPC).
```

**Terminal B** — supply the test AWS keys + run the script:
```bash
export COFFER_TEST_AWS_KEY_ID="<paste from step 2.11>"
export COFFER_TEST_AWS_SECRET="<paste from step 2.11>"
export COFFER_TEST_AWS_REGION=us-west-1   # default; override if needed

make sanity-test
```

Expected output:

```
[1/7] POST real S3 credentials                          PASS  201, id=01928…
[2/7] POST garbage credentials                          PASS  422, reason=…InvalidAccessKeyId…
[3/7] GET list after good + rejected POST               PASS  200, 1 credential
[4/7] GET good credential by id                         PASS  status=active
[5/7] PUT replace secret (re-encrypt)                   PASS  204
[6/7] DELETE credential                                 PASS  204
[7/7] GET list after DELETE                             PASS  200, 0 credentials

All 7/7 steps passed.
```

If any step prints `FAIL`, the diagnostic line under it has the HTTP code and response body. Common causes:
- Step 1 or 5 fails 422 → real S3 key not yet propagated (IAM lag); wait 30s and re-run.
- Step 1 fails with `412` → `make migrate-up` not applied.
- Step 2 fails because reason is empty → S3 provider returned an empty error string; rare, file a bug.

> **Divergence from the PRD draft:** the PRD wrote the bad-creds step as "expect 201 + status=failed". The shipped REST contract returns 422 + reason and persists no row. The script verifies what the code actually does.

## 6. (Optional) Phase C — full worker round-trip with grpcurl

Confirms that the gRPC fetch path works AND that the returned plaintext is actually usable against real S3.

With the vault still running in terminal A and the same env vars exported in terminal B:

```bash
# 1. Re-register a real credential, capture its id.
GOOD_ID=$(curl -sS -X POST http://localhost:8080/v1/credentials \
  -H "X-User-Id: ${COFFER_TEST_USER_ID:-sanity-test-user}" \
  -H "Content-Type: application/json" \
  -d "$(jq -nc \
        --arg s "$(printf '{"access_key_id":"%s","secret_access_key":"%s"}' \
                          "$COFFER_TEST_AWS_KEY_ID" "$COFFER_TEST_AWS_SECRET" \
                   | base64 | tr -d '\n')" \
        --arg r "$COFFER_TEST_AWS_REGION" \
        '{provider:"s3", label:"phase-c", secret:$s, metadata:{region:$r}}')" \
  | jq -r .id)
echo "GOOD_ID=$GOOD_ID"

# 2. Mint a grant token for that id.
TOKEN=$(make mint-grant USER="${COFFER_TEST_USER_ID:-sanity-test-user}" IDS="$GOOD_ID" TTL=15m)

# 3. Worker-side gRPC fetch.
RESP=$(grpcurl -plaintext \
  -d "{\"grant_token\":\"$TOKEN\",\"credential_ids\":[\"$GOOD_ID\"]}" \
  localhost:8443 coffer.v1.Vault/GetCredentials)
echo "$RESP" | jq .

# 4. Extract the plaintext keys and verify against real S3.
SECRET_B64=$(echo "$RESP" | jq -r .credentials[0].secret)
SECRET_JSON=$(echo "$SECRET_B64" | base64 -d)
KEY=$(echo "$SECRET_JSON" | jq -r .access_key_id)
SEC=$(echo "$SECRET_JSON" | jq -r .secret_access_key)

AWS_ACCESS_KEY_ID="$KEY" AWS_SECRET_ACCESS_KEY="$SEC" \
  aws s3 ls --region "$COFFER_TEST_AWS_REGION"
# Expected: list of your S3 buckets.

# 5. Cleanup.
curl -sS -X DELETE "http://localhost:8080/v1/credentials/$GOOD_ID" \
  -H "X-User-Id: ${COFFER_TEST_USER_ID:-sanity-test-user}"
```

Verify field names against the current proto (`api/coffer/v1/vault.proto`) if the grpcurl payload shape ever drifts.

## 7. Tear-down

- Kill the `make run` process in terminal A.
- (Optional) `psql "$DATABASE_URL" -c "TRUNCATE credentials, tenants CASCADE"` if rows accumulated.
- The IAM user from §2 is reusable — leave it for future runs.
