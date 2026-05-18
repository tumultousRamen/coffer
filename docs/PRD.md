# PRD — coffer (credentials vault microservice)

## 1. Problem

Byteport's DART transfer protocol moves files between external storage providers (S3, Dropbox, Google Drive, Box, etc.) on behalf of customers. To do this, transfer workers need authenticated access to those storage accounts. Customers must be able to register their credentials with Byteport once, then trust that workers can use them at transfer time without ever exposing the raw secret back to the user or leaking it from the database.

The vault service is the system of record for those credentials. It must:
1. Accept credentials from users via a control-plane API.
2. Store them encrypted at rest, with no path for an end user to read the raw secret back.
3. Deliver them to transfer workers over gRPC at transfer time, fast enough that the worker doesn't block.
4. Survive a Postgres compromise — leaking the DB must not leak the secrets.

## 2. Scale & KPIs

| Metric | Target |
|---|---|
| Users | 1M |
| Credentials per user | 5 |
| Total credentials | ~5M |
| `GetCredentials` P99 latency (worker → vault, end-to-end) | **50ms** |
| Credential write P99 latency (POST/PUT) | **200ms** |
| Availability | High — vault down = transfers down |

The 50ms read P99 is **end-to-end and system-wide**, not just hot-path. It is **conditional on refresh-worker health**: the sync-on-stale OAuth refresh path ([ADR 0006](adr/0006-provider-adapter-and-refresh.md)) can take ~500ms, but is expected to fire on <1% of reads, so lives in P99.9+ territory. If refresh-lag rises and sync-refresh becomes common, P99 degrades — `coffer_refresh_lag_seconds` is therefore an SLO-load-bearing alert ([ADR 0009](adr/0009-observability.md)).

The 50ms SLO assumes the vault is deployed regionally per [ADR 0012](adr/0012-multi-region-topology.md). Cross-region requests cannot meet this SLO.

## 3. Functional Requirements

Users must be able to:
1. Add / update / delete credentials for an external storage provider, scoped to themselves.
2. Never read the raw secret back through any control-plane API.

Workers must be able to:
3. Fetch credentials for a given `(user_id, provider)` at transfer time.
4. Fetch both source and destination credentials within a single transfer job.

System must:
5. Handle per-provider credential shapes (S3 keys, OAuth refresh tokens, etc.) without leaking provider knowledge across the service.

## 4. Non-Functional Requirements

1. **Security.** Credentials encrypted at rest (envelope encryption via AWS KMS) and in transit (TLS / mTLS). DB compromise alone must not expose plaintext.
2. **Availability.** Vault is on the critical path for all transfers. Design for graceful degradation when KMS or DB is degraded.
3. **Low latency.** Workers must not block. P99 200ms end-to-end for `GetCredentials`.
4. **Modular / replaceable.** Byteport must be able to lift this into their production stack with minimal coupling — clean ports for KMS, DB, and gateway.

## 5. Tech Stack

- **Language:** Go
- **Service interface:** gRPC (worker-facing) + minimal REST gateway (user-facing)
- **Datastore:** Aurora Postgres (primary + per-region read replicas; see [ADR 0012](adr/0012-multi-region-topology.md))
- **Key management:** AWS KMS
- **Supporting (optional):** Redis cache, refresh queue
- **Observability:** OpenTelemetry → Grafana

## 6. Out of Scope

- Worker / transfer-worker nodes.
- Byteport's real production API gateway stack (dummy gateway is sufficient).
- Production Slack / alerting integrations.
- Full auditability (acknowledged as nice-to-have but explicitly de-scoped on the whiteboard).

## 7. Design Decisions

See [docs/adr/](adr/). Each load-bearing decision is captured as a numbered ADR.

| # | Decision | Pinned to NFR |
|---|---|---|
| [0001](adr/0001-secret-store-vs-broker.md) | Secret-store model with OAuth-side broker pattern; production evolution to full broker | Security |
| [0002](adr/0002-worker-auth-capability-token.md) | mTLS + per-job capability token (claims include `credential_ids`) | Security |
| [0003](adr/0003-envelope-encryption-shape.md) | Per-tenant DEK, AES-256-GCM, KEK in AWS KMS, AAD bound to row identity | Security |
| [0004](adr/0004-dek-cache.md) | In-process LRU only, 5-min TTL, single-flight on miss; no Redis for DEKs | Latency, Security |
| [0005](adr/0005-data-model.md) | Two-blob schema (secret_ciphertext + metadata JSONB); UUIDv7; no RLS; hard delete | Replaceability |
| [0006](adr/0006-provider-adapter-and-refresh.md) | Self-scheduling per-credential refresh jobs; **sync-on-stale fallback** for safety net; refresh-token rotation is a load-bearing invariant | Latency, Availability |
| [0007](adr/0007-api-surface.md) | gRPC batch fetch by `credential_ids`; REST gateway with JWT + idempotency; compile-time secret read-back guard | Security |
| [0008](adr/0008-failure-modes.md) | KMS circuit breaker + extended cache TTL; **Aurora primary + regional replicas with primary-fallback-on-miss**; regional replica outage = fail-and-alert; defined worker retry contract; split `/healthz` and `/readyz` | Availability |
| [0009](adr/0009-observability.md) | Unified telemetry facade; OTel metrics + tracing; structured stdout audit log; type-level secret redaction | Replaceability |
| [0010](adr/0010-modular-boundaries.md) | Hexagonal layout (`internal/vault` core, `internal/adapters/*`, `internal/transport/*`); env-var config; `coffer-migrate` CLI | Replaceability |
| [0011](adr/0011-scope-and-build-order.md) | Work-trial plan: day-by-day order, strict-TDD scope, built-vs-stubbed-vs-cut surface, demo script | — |
| [0012](adr/0012-multi-region-topology.md) | Vault deploys per region; Aurora primary + regional read replicas; read-after-write resolved via primary-fallback-on-miss; single-region KMS for trial, multi-region key for production | Latency, Availability |

## 8. Production Evolution

Items deliberately deferred, captured here so a future maintainer can see the shape of what we'd build next:

- **Full broker model.** Move S3 onto STS-issued temporary credentials so plaintext long-lived keys never reach workers ([ADR 0001](adr/0001-secret-store-vs-broker.md)).
- **Sharded refresh workers.** Hash by `user_id` and run N worker pools when OAuth credentials exceed ~10M ([ADR 0006](adr/0006-provider-adapter-and-refresh.md)).
- **Multi-region replication.** Out-of-region read replicas for vault; KMS multi-region keys; out of scope for the trial.
- **Read replica failover.** With careful replication-lag handling on the write path ([ADR 0008](adr/0008-failure-modes.md)).
- **Full audit subsystem.** SIEM integration, retention policy, queryable audit DB.
- **Pre-merge CI for the secret-leak linter and the hexagonal import direction.**
