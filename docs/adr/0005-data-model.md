# ADR 0005 — Data Model & Schema


Credentials have **fundamentally different shapes across providers** — S3 is `{access_key_id, secret_access_key}` plus `region`; OAuth providers (Dropbox, Google Drive, Box) are `{refresh_token, access_token, access_token_expires_at}` plus `scopes` and `account_email`. The schema must accommodate this without forcing a migration per provider and without forcing KMS decrypts to read non-secret config.

Options considered (see grilling notes):
- **A. Polymorphic JSON blob** — everything inside ciphertext. Reading any field requires decrypt.
- **B. Parent + per-provider sub-tables** — typed columns per provider. Strong typing, but every new provider is a migration and the hot path is a JOIN.
- **C. Two-blob model** — secret fields in `secret_ciphertext`, non-secret config in plaintext `metadata JSONB`. Single table, no joins, no migrations for new providers.

## Decision

**Option C — two-blob model.** Schema:

```sql
CREATE TABLE tenants (
  user_id        UUID PRIMARY KEY,
  encrypted_dek  BYTEA       NOT NULL,
  dek_version    INT         NOT NULL DEFAULT 1,
  created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE credentials (
  id                UUID        PRIMARY KEY,              -- UUIDv7 (time-ordered)
  user_id           UUID        NOT NULL REFERENCES tenants(user_id),
  provider          TEXT        NOT NULL,                 -- 's3' | 'dropbox' | 'gdrive' | 'box'
  label             TEXT        NOT NULL,                 -- 'prod_parley_bucket'
  secret_ciphertext BYTEA       NOT NULL,                 -- AES-256-GCM(secret_json, dek, nonce, aad)
  nonce             BYTEA       NOT NULL,                 -- 12 bytes, per ADR 0003
  dek_version       INT         NOT NULL,                 -- which DEK epoch encrypted this row
  metadata          JSONB       NOT NULL DEFAULT '{}',    -- non-secret config (region, scopes, etc.)
  status            TEXT        NOT NULL DEFAULT 'active',-- 'active' | 'failed'
  created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at        TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX credentials_user_provider_label ON credentials (user_id, provider, label);
CREATE INDEX        credentials_user_provider       ON credentials (user_id, provider);
```

### Companion decisions

| Decision | Choice | Reasoning |
|---|---|---|
| Primary key | UUIDv7 | Time-ordered → index locality at 5M rows; no enumeration leak vs. monotonic int. |
| Tenancy | `user_id` only | Brief specifies "1M users, 5 creds per user". `org_id` is purely additive later — no preemptive column. |
| Row-Level Security (RLS) | **Not used** | The vault service is the sole DB consumer; authz lives at the service layer against the capability token. RLS would add `SET LOCAL` overhead on every query, complicate connection pooling, and provide redundant defense at material complexity cost. |
| Delete semantics | **Hard delete** on user-initiated DELETE | A user revoking a credential expects the ciphertext gone. Crypto-shred at the tenant level is handled by DEK retirement (ADR 0003). |
| Migration tool | `golang-migrate/migrate` | Plain SQL `.up.sql` / `.down.sql` files under `internal/adapters/postgres/migrations/`. Embedded into the binary via `//go:embed` and run on boot. No ORM. Compatible with Aurora Postgres out of the box. |

## Consequences

**Accepted:**
- The secret payload is a blob — DB-side type checking of secret fields is impossible. Type safety lives in Go provider structs + a per-provider validator.
- Reading non-secret config (region, scopes, account_email) requires no decrypt. Useful for the OAuth refresh queue and for observability.
- New providers require a Go-side struct + validator only; no migration.

**Trade-offs vs. alternatives:**
- vs. (A): added a JSONB column to avoid decrypting on every read of non-secret config.
- vs. (B): gave up DB-side type safety on provider config in exchange for no migrations and no joins on the hot path.

**Implications for downstream design:**
- The provider-adapter interface (future ADR) defines, per provider, which fields are "secret" (go into `secret_ciphertext`) vs. "config" (go into `metadata`).
- The AAD on `secret_ciphertext` is `user_id || credential_id || provider` (per ADR 0003) — `credential_id` is the row's `id`.
- DEK rotation iterates `credentials WHERE user_id = $1 AND dek_version = $old`, re-encrypts, updates `dek_version`. Single transaction per tenant; ≤5 rows.

## Update — PRD 0004 (2026-05-17)

Two deferrals to flag for the service-layer PRD, both deliberate scope cuts in PRD 0004 (storage-only):

- **`credentials.nonce` is written as empty bytes.** The schema column is `NOT NULL` and accepts a zero-length BYTEA, so the constraint holds. The current `vault.Credential` type has no `Nonce` field; the service-layer PRD reshapes the type and the call site simultaneously so storage round-trips both ciphertext and nonce as ADR 0003 requires.
- **`credentials.dek_version` is hardcoded to 1 at insert time.** The live version lives on the `tenants` row; once the service layer plumbs the `tenants.dek_version` through `Cryptor.Encrypt`, the adapter writes the real value. Rotation logic (per "DEK rotation iterates ..." above) is not yet implemented and remains a future PRD.

Also: `CredentialStore.Get` returns whichever requested IDs exist and silently drops the rest, with no order guarantee. Order-of-IDs and reject-whole-on-miss are now service-layer concerns — see ADR 0007's PRD-0004 update for the reasoning.

## Update — PRD 0005 (2026-05-17)

Both PRD-0004 deferrals are now resolved:

- **`credentials.nonce`** carries the fresh 12-byte AES-GCM nonce that the service layer's `Cryptor.Encrypt` produces on every Create and Replace. The `vault.Credential` type now has a `Nonce []byte` field that round-trips through both adapters.
- **`credentials.dek_version`** carries the live `tenants.dek_version` as of the row's write time. `TenantStore.GetEncryptedDEK` was extended to return `(dek, version, err)`; the service stamps `version` onto the credential row in the same operation.

One additional schema-adjacent decision that affected the storage layer: **`TenantStore.PutEncryptedDEK` is now load-or-store**, not upsert. First call inserts at `dek_version = 1` and returns the inserted DEK; subsequent calls return the existing `(encrypted_dek, dek_version)` and discard the caller's argument. This was needed to fix a concurrent first-credential race the original spec missed (two goroutines could each `Cryptor.Provision` and overwrite each other's DEK, leaving credentials encrypted under an orphaned DEK). DEK rotation, which previously would have used the same method to overwrite the DEK, will need its own explicit `RotateEncryptedDEK` method when that PRD lands — provisioning and rotation are now distinct entry points.

The Postgres implementation uses `INSERT … ON CONFLICT (user_id) DO NOTHING RETURNING …` plus a fallback `SELECT` on the no-op path. Memstore uses a mutex-guarded "if exists return existing, else store new" check. Both are exercised by the `portcontract.TestPutSecondLoadsExisting` and `TestConcurrentPutExactlyOneCanonicalDEK` scenarios — adapter equivalence is preserved.

## On RLS specifically

The default Aurora Postgres posture is RLS-on for every table. We deliberately disable it for `tenants` and `credentials`. The vault service connects to Postgres with a single dedicated role that has direct access. Authz is enforced **before** the query, against the per-job capability token (ADR 0002) — by the time a query is constructed, the user_id has already been authorized. RLS in this architecture would either be redundant (same check, twice) or actively wrong (would block legitimate cross-tenant work like the refresh queue).
