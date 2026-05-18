# Architecture Decision Records

Each load-bearing design choice gets a numbered ADR. Format: context → options considered → decision → consequences.

| # | Title | Status |
|---|---|---|
| [0001](0001-secret-store-vs-broker.md) | Secret Store vs. Credential Broker | Accepted |
| [0002](0002-worker-auth-capability-token.md) | Worker Authentication: Per-Job Capability Token | Accepted |
| [0003](0003-envelope-encryption-shape.md) | Envelope Encryption Shape (per-tenant DEK, AES-256-GCM) | Accepted |
| [0004](0004-dek-cache.md) | DEK Cache Design (in-process LRU, 5-min TTL, single-flight) | Accepted |
| [0005](0005-data-model.md) | Data Model & Schema (two-blob, no RLS, hard delete) | Accepted |
| [0006](0006-provider-adapter-and-refresh.md) | Provider Adapter & OAuth Refresh (self-scheduling jobs, no sync fallback) | Accepted |
| [0007](0007-api-surface.md) | API Surface (gRPC batch fetch, REST, compile-time secret guard, idempotency) | Accepted |
| [0008](0008-failure-modes.md) | Failure Modes & Availability (KMS breaker, single-primary PG, retry policy) | Accepted |
| [0009](0009-observability.md) | Observability (unified telemetry facade, OTel, audit log, type-level secret redaction) | Accepted |
| [0010](0010-modular-boundaries.md) | Modular & Replaceable Boundaries (hexagonal layout, env config, coffer-migrate CLI) | Accepted |
| [0011](0011-scope-and-build-order.md) | Scope & Build Order (work-trial plan, day-by-day, TDD discipline, demo script) | Accepted |
| [0012](0012-multi-region-topology.md) | Multi-Region Deployment Topology (Aurora primary + regional replicas, primary-fallback-on-miss) | Accepted |
