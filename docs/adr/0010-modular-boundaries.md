# ADR 0010 — Modular & Replaceable Boundaries

The brief's loudest signal is that Byteport must be able to extract this service and integrate it into their production system with minimal coupling. "Modular and replaceable" needs concrete boundaries — not a slogan. Three things have to be true:

1. The **code** is structured so that infrastructure dependencies (KMS, DB, providers, telemetry) are behind small interfaces that Byteport can re-implement.
2. The **config** is swappable without code changes — credentials and endpoints move from "Divya's AWS account" to "Byteport's AWS account" by changing env vars.
3. The **data** is portable — there is a documented, demonstrated path to move tenant rows + DEKs from this Postgres + KMS to Byteport's Postgres + KMS.

## Decisions

### 1. Repository layout — hexagonal / ports & adapters

```
coffer/
├── api/
│   └── coffer/v1/vault.proto # gRPC service definition (per ADR 0007)
├── cmd/
│   ├── vault/                # main: wires adapters into the core (gRPC + REST)
│   ├── gateway/              # stub API gateway — JWT verify, rate-limit, idempotency
│   └── coffer-migrate/       # one-shot migration CLI (data export/import)
├── internal/
│   ├── vault/                # CORE — domain logic; defines port interfaces
│   │   ├── credential.go     # Credential, CredentialSummary, SecretBlob types
│   │   ├── service.go        # Service orchestration (the "use cases")
│   │   └── ports.go          # KeyManager, CredentialStore, Provider, Telemetry interfaces
│   ├── adapters/             # IMPL — one folder per port
│   │   ├── awskms/           # KeyManager implementation
│   │   ├── postgres/         # CredentialStore implementation + migrations/
│   │   ├── providers/        # Provider implementations
│   │   │   ├── s3.go
│   │   │   ├── dropbox.go
│   │   │   ├── gdrive.go
│   │   │   └── box.go
│   │   └── telemetry/        # Telemetry implementation (OTel + stdout audit)
│   └── transport/            # protocol layer — consumes core, NEVER adapters
│       ├── grpc/             # worker-facing service (called directly by workers)
│       └── rest/             # user-facing REST handlers (called by the gateway)
└── docs/
```

**Two binaries, one repo.** `cmd/vault/` is the core service exposing both gRPC (workers) and REST (gateway-proxied). `cmd/gateway/` is the thin user-facing edge that wraps the vault's REST transport with JWT verification, rate limiting, and idempotency-key handling — explicitly the "minimal API gateway scaffolding" called out in the brief. Reviewer / Byteport replaces it with their real Envoy/Fly edge in production; the seam is clean.

**Dependency rules (enforced):**
- `internal/vault` imports nothing in `internal/adapters` or `internal/transport`. One-way only.
- `internal/adapters/*` imports `internal/vault` (to implement port interfaces) and external SDKs (AWS, pgx, etc.).
- `internal/transport/*` imports `internal/vault` (to call the service) and protocol libs (grpc, net/http). **Transport does NOT import adapters.**
- `cmd/vault/main.go` is the single composition root: it imports everything and wires concrete adapters into the core service (~50 lines).

A pre-merge CI check (or a comment + reviewer discipline if CI is too much for the trial) enforces the import rule.

**Consequence for Byteport:** they can swap any adapter — KMS, DB, providers, telemetry — by replacing one folder and re-wiring `main.go`. They can lift `internal/vault/` into their monorepo as a library; it has no infra dependencies.

### 2. Config — env vars only, with `dev_no_kms` build tag for local dev

All runtime config from environment:

```bash
COFFER_PG_URL=postgres://...
COFFER_AWS_KMS_KEY_ID=alias/coffer-tenant-kek
COFFER_AWS_REGION=us-east-1
COFFER_GRANT_TOKEN_PUBKEY_PEM=...        # for verifying capability tokens
COFFER_REFRESH_MARGIN_MINUTES=10
COFFER_DEK_CACHE_TTL_SECONDS=300
COFFER_DEK_CACHE_MAX_ENTRIES=100000
COFFER_GRPC_LISTEN=:8443
COFFER_REST_LISTEN=:8080
COFFER_LOG_LEVEL=info
```

Build tag `dev_no_kms` swaps the `awskms` adapter with a file-based AES key for local development only. Never deployed. Documented in the dev README.

**Swap from this deployment to Byteport's:** change env vars (DB URL, AWS account, KMS key ID, grant-token pubkey). No code change.

### 3. `coffer-migrate` CLI — built, not stubbed

A standalone binary in `cmd/coffer-migrate/` that demonstrates "data is portable." Workflow:

1. Reads `--source-pg-url`, `--source-aws-region`, `--source-kms-key-id`, and corresponding `--dest-*` flags.
2. For each tenant:
   - `kms:Decrypt(encrypted_dek_v_old)` against source KMS → plaintext DEK.
   - `kms:Encrypt(plaintext_dek)` against destination KMS → `encrypted_dek_v_new`.
   - Writes the new `encrypted_dek` and bumps `dek_version` on the tenant row in destination DB. **Ciphertexts on credential rows are unchanged** — they're already encrypted under the (still-the-same) DEK. Only the DEK wrapper changes.
3. Streams credential rows to destination DB.
4. Verifies a sample (e.g. 1% of credentials) by decrypting end-to-end on the destination side.
5. Emits a structured progress log + per-tenant audit trail: `(user_id, dek_version_old, dek_version_new, credentials_migrated, status)`.

Cutover model: the destination vault is configured with the new `COFFER_AWS_KMS_KEY_ID` and reads `dek_version_new`. Source remains read-only during cutover until verified. Atomic: failed migration = retry; no half-state.

~300 lines of Go. **This is the artifact that proves "replaceable" to the reviewer.** Without it, modularity is a slogan.

### 4. Explicitly rejected

- **Plugin systems / dynamic loading.** Adapters are compiled in. Simpler, faster, no dynamic-loading attack surface.
- **Config-driven provider DSL.** Each provider is hand-written Go in `adapters/providers/`. Trying to express OAuth refresh flows as YAML is a known mistake.
- **Multi-region replication.** Out of scope for the trial. Documented as future work in the PRD.

## Consequences

**Accepted:**
- The composition root (`cmd/vault/main.go`) is a single point of coupling. Acceptable — it's small, explicit, and Byteport will rewrite it anyway when they integrate.
- The migration CLI is real engineering investment (~half a day). Worth it: it's the difference between "I claim this is replaceable" and "here's the binary that proves it."

**Implications:**
- The `Telemetry` port (per ADR 0009) joins `KeyManager`, `CredentialStore`, and `Provider` as one of the four core abstractions. Calling code never imports OTel, the logger, or AWS SDK directly.
- The repo structure is the first thing a reviewer will look at. The hexagonal layout signals architectural intent before any code is read.
- **The `Provider` port is intrinsically broker-shaped.** Its `Refresh()` method is the mint primitive — for OAuth providers it calls `/oauth/token`; for a future S3-STS adapter it would call `AssumeRole`; for any new short-lived-token-issuing provider it implements the same shape (per [ADR 0001](0001-secret-store-vs-broker.md)). Moving a provider from secret-store mode to broker mode is therefore a single-file change.

## Out of scope here

- Multi-region active-active deployment.
- Live migration (zero-downtime cutover). Current design assumes a brief read-only window on the source during migration.
- Cross-cloud migration story (different KMS provider on each side). Current model assumes both sides are AWS KMS; abstract-KMS migration is a future ADR if needed.
