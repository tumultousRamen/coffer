# OAuth provider setup (Dropbox / Google Drive / Box)

PRD 0010 adds three OAuth-based providers. Each requires a one-time
developer-console setup to obtain an `app credentials` pair
(client_id / client_secret) that the vault uses to mint access tokens
for all users of that provider, plus a per-user `refresh_token` that
the vault stores and refreshes on demand.

This runbook is operator-facing: register the app, capture a
refresh_token, paste it into the vault. The user-facing "browser
authorization dance" (RFC 6749 §4.1 authorization code flow) is
out-of-band per PRD 0010 §Out of Scope and uses each vendor's
provided developer flow.

A vault deployment only needs to set the env vars for the providers it
serves — unset providers are silently not registered.

---

## Dropbox

1. **Register an app.** Go to https://www.dropbox.com/developers/apps
   → Create app → "Scoped access" → "Full Dropbox" (or "App folder"
   per your use case). Set `token_access_type` to `offline` so the
   authorization flow returns a refresh_token.
2. **Configure redirect URI.** Add `http://localhost` (trial) or your
   production redirect handler URL under OAuth 2 → Redirect URIs.
3. **Obtain initial refresh_token.** Run the manual flow:
   - Visit `https://www.dropbox.com/oauth2/authorize?client_id=<CLIENT_ID>&token_access_type=offline&response_type=code&redirect_uri=http://localhost`
   - Approve, copy the `code` from the redirect URL.
   - `curl -X POST https://api.dropbox.com/oauth2/token -d grant_type=authorization_code -d code=<CODE> -d redirect_uri=http://localhost -u <CLIENT_ID>:<CLIENT_SECRET>`
   - The response's `refresh_token` is what you paste into the vault.
4. **Configure the vault.** Set in `.env.local` (or Secrets Manager):
   ```
   COFFER_DROPBOX_CLIENT_ID=...
   COFFER_DROPBOX_CLIENT_SECRET=...
   ```
   Restart the vault. POST `/v1/credentials` with `provider: "dropbox"`
   and `secret: {"refresh_token": "<from step 3>"}`.

---

## Google Drive

1. **Register an OAuth 2.0 Client ID.** In
   https://console.cloud.google.com/apis/credentials → Create
   Credentials → OAuth client ID → "Web application". Enable the
   Drive API on the project first if it isn't already.
2. **Configure redirect URI.** Add
   `https://developers.google.com/oauthplayground` (for the easy
   initial-flow path) and your production redirect URL.
3. **Obtain initial refresh_token.** Use OAuth Playground:
   - Open https://developers.google.com/oauthplayground
   - Gear icon → check "Use your own OAuth credentials" → paste your
     client_id / client_secret.
   - Select the scopes you need under "Drive API v3".
   - Authorize → Exchange authorization code for tokens. The
     refresh_token in the response is what you paste into the vault.
4. **Configure the vault.** Set in `.env.local` (or Secrets Manager):
   ```
   COFFER_GDRIVE_CLIENT_ID=...
   COFFER_GDRIVE_CLIENT_SECRET=...
   ```
   Restart the vault. POST `/v1/credentials` with `provider: "gdrive"`
   and `secret: {"refresh_token": "<from step 3>"}`.

   **Heads-up: Google has a 100-refresh-token-per-client cap.** If
   your refresh_token suddenly fails with `invalid_grant`, this is
   the likely cause — re-authorize via OAuth Playground to mint a
   fresh one.

---

## Box

**Box rotates the refresh_token on every refresh call** (single-use).
The vault handles rotation atomically (PRD 0010 §4 invariant); the
operator-facing implication is that the refresh_token you paste into
the vault is consumed the first time the vault calls Refresh — after
that, only the vault knows the current value.

1. **Register an app.** Go to https://app.box.com/developers/console
   → Create New App → "Custom App" → "User Authentication (OAuth 2.0)".
   Under "Application Scopes" select what you need (typically "Read
   all files and folders" + "Write all files and folders").
2. **Configure redirect URI.** Add `http://localhost` (trial) under
   OAuth 2.0 Redirect URIs.
3. **Obtain initial refresh_token.** Box's dev console has a built-in
   "Generate Developer Token" but that issues a short-lived
   access_token, NOT a refresh_token. For a refresh_token use the
   authorization-code flow manually:
   - Visit `https://account.box.com/api/oauth2/authorize?response_type=code&client_id=<CLIENT_ID>&redirect_uri=http://localhost`
   - Approve, copy the `code` from the redirect URL.
   - `curl -X POST https://api.box.com/oauth2/token -d grant_type=authorization_code -d code=<CODE> -d client_id=<CLIENT_ID> -d client_secret=<CLIENT_SECRET>`
   - The response's `refresh_token` is what you paste into the vault.
     (The `access_token` you can discard — the vault will mint its own
     on first Refresh.)
4. **Configure the vault.** Set in `.env.local` (or Secrets Manager):
   ```
   COFFER_BOX_CLIENT_ID=...
   COFFER_BOX_CLIENT_SECRET=...
   ```
   Restart the vault. POST `/v1/credentials` with `provider: "box"`
   and `secret: {"refresh_token": "<from step 3>"}`. The first POST
   consumes the token and the vault stores the rotated value.

---

## Verifying end-to-end after setup

For each provider you configured:

1. POST `/v1/credentials` with the refresh_token. Expect `201` and a
   summary whose `status` is `active` and whose metadata carries
   `access_token_expires_at`.
2. Mint a grant token via `cmd/mint-grant` for the new credential ID.
3. `grpcurl ... FetchForWorker` with the grant. The returned plaintext
   contains a fresh `access_token`. Sync-on-stale (PRD 0010 §4) fires
   automatically when the cached access_token expires.
4. (Box only) After step 3, fetch the row from Postgres directly and
   confirm the `secret_ciphertext` byte-changed across the call — the
   rotated refresh_token is now persisted.

## Integration tests

Per-provider integration tests under
`internal/adapters/providers/{dropbox,gdrive,box}/integration_test.go`
exercise the real `/token` endpoint. They are gated on the provider's
env-var triple — set
`COFFER_TEST_{PROVIDER}_REFRESH_TOKEN=<valid-rt>` alongside the
CLIENT_ID/SECRET pair and run `make integration`. Each test
self-skips if its env var is absent, so you only run the providers
you have credentials for.

**Box integration test caveat:** it consumes the refresh_token in env
because Box rotates. Re-mint via the manual flow above between runs.
