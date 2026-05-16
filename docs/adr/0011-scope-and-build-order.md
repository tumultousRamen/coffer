# ADR 0011 — Scope & Build Order (Work-Trial Plan)

The work-trial deliverable spans the full design across ADRs 0001–0010. A naive build of everything in those ADRs is ~6 working days. The realistic time budget is ~19 hours of focused work spread across Thu 2026-05-14 → Wed 2026-05-20, with Monday hard-blocked. Modules are implemented test-driven with an AI coding assistant; human time goes to test design, infrastructure setup, integration debugging, and review.

This ADR pins the scope cuts and the day-by-day build order.

## Decisions

### 1. Time budget

| Day | Date | Hours | Focus |
|---|---|---|---|
| Thursday | 2026-05-14 | 0 | Rest. Avoid half-starting tired. |
| Friday | 2026-05-15 | ~4 | Infra + foundation (low risk, low energy) |
| Saturday | 2026-05-16 | ~8 | Crypto + service core + S3 (highest-risk modules) |
| Sunday | 2026-05-17 | ~4 | Dropbox provider + refresh worker + gRPC wiring |
| Monday | 2026-05-18 | 0 | Hard-blocked |
| Tuesday | 2026-05-19 | ~3 | Gateway + migrate CLI + end-to-end dry-run |
| Wednesday | 2026-05-20 | demo | — |

**Risk-front-loaded:** the hardest modules (KMS envelope encryption, OAuth refresh) live on the highest-energy days (Saturday, Sunday). If only one day worked out, Saturday is the day that must.

### 2. Build order — by module, in dependency order

| # | Module | Day | Est. h |
|---|---|---|---|
| 1 | Infra setup (AWS+KMS, Supabase, docker-compose, protobuf) | Fri | 1.5 |
| 2 | Repo scaffold + hexagonal layout + `go mod` | Fri | 0.5 |
| 3 | Core domain types (`Credential`, `CredentialSummary`, `SecretBlob`) + redaction tests | Fri | 1.0 |
| 4 | Port interfaces (`KeyManager`, `CredentialStore`, `Provider`, `Telemetry`) | Fri | 0.5 |
| 5 | Postgres adapter skeleton + migration files + testcontainers | Fri | 0.5 |
| 6 | **AWS KMS adapter** — envelope encryption, DEK cache, single-flight, simple breaker | Sat | 3.0 |
| 7 | Service layer — orchestration logic | Sat | 1.5 |
| 8 | Capability token verification | Sat | 0.5 |
| 9 | S3 provider (static key) | Sat | 0.75 |
| 10 | Telemetry impl — OTel wiring + metrics + audit log writer | Sat | 2.0 |
| 11 | **Dropbox provider** — token endpoint, error classification, refresh-token rotation invariant | Sun | 2.0 |
| 12 | Refresh worker — `refresh_jobs` table, advisory lock, scan loop | Sun | 1.5 |
| 13 | gRPC service — `GetCredentials` with capability token | Sun | 0.5 |
| 14 | REST gateway — JWT verify + idempotency-key | Tue | 1.0 |
| 15 | `coffer-migrate` CLI — happy-path flow only | Tue | 1.0 |
| 16 | End-to-end demo + docker-compose + dry-run | Tue | 1.0 |

### 3. TDD discipline — strict on the core, smoke elsewhere

**Strict TDD** (test-first, red-green-refactor):
- Core domain types — secret redaction, type-level invariants.
- Crypto path — envelope round-trip, AAD enforcement, nonce uniqueness, AES-GCM correctness.
- Refresh worker state machine — transient vs. terminal classification, rotation persistence.
- Capability token verification — signature, claim match, expiry.

**Smoke tests only**:
- gRPC and REST handler wiring (one happy + one auth-failure per surface).
- OTel exporter wiring (does it start).
- Health endpoints.
- `coffer-migrate` happy path.

**Skip**:
- Load testing, fuzz testing, real third-party API integration tests.

### 4. Built (real) vs. stubbed vs. cut

**Built end-to-end:**
- Hexagonal layout with one composition root in `cmd/vault/main.go`.
- AWS KMS adapter with envelope encryption + DEK cache + single-flight + circuit breaker.
- Postgres adapter (schema, migrations, queries).
- S3 provider — full.
- Dropbox provider — full, with refresh.
- Refresh worker — full, including advisory-lock leader election.
- gRPC service `GetCredentials` with capability token authz.
- REST gateway with JWT + idempotency-key on POST.
- Telemetry facade with OTel metrics, audit log, type-level secret redaction.
- `coffer-migrate` CLI — happy-path export/import.
- docker-compose for local run, plus a demo script.

**Stubbed (file exists, method returns "not implemented"):**
- Google Drive provider.
- Box provider.

**Documented but not wired:**
- CI rule for secret-leak linter — `go vet` analyzer / `grep` rule written; not added to a GitHub Actions workflow.
- KMS breaker half-open probe — basic open/closed transitions only.

**Cut, with PRD notes:**
- Multi-region active-active deployment.
- Postgres read-replica fallback.
- `coffer-migrate` verification-sample step (1% decrypt-and-verify on destination).
- Plugin / DSL-based provider system.
- Granular permissions / org-level tenancy.
- SIEM integration of audit logs.
- Sync-on-read OAuth fallback (per ADR 0006).

### 5. Demo script

A single `demo/run.sh` that:
1. Brings up vault + stub gateway + Postgres + (optionally) Redis via docker-compose.
2. Mints a stub JWT for a fake user.
3. POSTs a fake S3 credential.
4. POSTs a fake Dropbox credential (with synthetic refresh token; refresh endpoint is mocked locally).
5. Mints a capability token claiming both credential_ids.
6. Test client makes one gRPC `GetCredentials` call presenting the capability token. Decrypted plaintexts are printed.
7. Manually triggers the refresh worker; shows the Dropbox access token rotates.
8. Runs `coffer-migrate` against a second Postgres + KMS key; shows tenant rows + DEKs migrate.

5–7 minute walkthrough end-to-end. Reviewer runs it once, sees the full system work.

## Consequences

**Accepted:**
- GDrive and Box are stubs. Reviewer sees the shape and understands the addition is mechanical (a new file in `adapters/providers/`).
- `coffer-migrate` is happy-path only. Failure recovery and verification cut. The CLI exists as a demonstration of portability, not a production migration tool.
- Tuesday is the only integration day. Anything not conceptually working by Sunday night fights for ~3 hours Tuesday.

**Implications:**
- The Saturday block is non-negotiable. If Saturday gets disrupted, the whole plan slips — Sunday cannot absorb both KMS + Dropbox + refresh worker in 4 hours.
- The Tuesday dry-run is the safety net. Block the first hour for it; remaining time fixes whatever breaks.

## Out of scope here

- Post-trial extension plans (a separate doc once Byteport gives feedback).
- Cost analysis of KMS calls at scale (mentioned in ADR 0003 / 0004; not a build item).
