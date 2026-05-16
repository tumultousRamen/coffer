# ADR 0008 — Failure Modes & Availability

The vault is on the critical path for all transfers — when it's down, transfers fail. The non-functional requirement isn't "never go down" (impossible), it's "fail gracefully and minimize the blast radius of dependency outages." Four failure surfaces need explicit decisions:

1. AWS KMS outage (regional AWS issue, transient throttling, network partition to KMS).
2. Postgres outage / failover (Supabase-managed primary election).
3. Worker-side timeout and retry policy on the gRPC read path.
4. Refresh worker outage (already partially specified in [ADR 0006](0006-provider-adapter-and-refresh.md)).

## Decisions

### 1. KMS outage — circuit breaker + extended cache TTL

Wrap the KMS client with `sony/gobreaker`. Settings:

| Parameter | Value |
|---|---|
| Threshold | 5 consecutive failures, or >50% failure rate over 30s with min 20 reqs |
| Open duration | 30s before half-open probe |
| On open: TTL extension | Existing cache entries' TTL bumped to 1 hour |
| On open: cold reads | Return `UNAVAILABLE` with retry-after hint; **do not** call KMS |
| Metric | `coffer_kms_breaker_state{state="open|half_open|closed"}` (gauge) |
| Log | Breaker state transitions logged at WARN |

**Behavior:**
- During a KMS blip, hot tenants keep being served from cached DEKs.
- Cold-tenant reads fail fast (no piling on retries to a sick KMS).
- When KMS recovers (half-open probe succeeds), normal 5-min TTL resumes.

**Cost: ~30 lines over no-breaker. Half day of implementation.** Worth it: the resilience story for "hot path doesn't notice transient KMS issues" is a clean senior signal.

### 2. Postgres outage — single primary, ride failover

- Single Supabase-managed primary. No read replica fallback.
- Connection pool through pgBouncer with retry-on-failover client (e.g. `pgx` with reconnect).
- Expected failover duration: ~30s. Worker gRPC calls return `UNAVAILABLE` during the window; workers retry; transfers resume.

**Rejected alternatives:**
- **Read replica fallback.** Replication lag breaks just-written credentials — worker fetches a credential the user just created and gets "not found." Adding logic to wait for replication catches up complicates writes for marginal benefit during a rare event.
- **Ciphertext cache in Redis.** Same trust-boundary problems as plaintext DEK caching (covered in ADR 0004), plus stale-on-write inconsistency.

The senior call here is: **30s of failover blip is the cost of using a managed DB.** Retries on the worker side handle it. Document, don't engineer around.

### 3. Worker gRPC deadline & retry policy

| Setting | Value |
|---|---|
| Per-call deadline | **250ms** (slight buffer over the 200ms P99 KPI) |
| Retry count | 2 |
| Backoff | 50ms + jitter |
| Retry on | `UNAVAILABLE`, `DEADLINE_EXCEEDED` |
| **Do not retry on** | `FAILED_PRECONDITION` (expired token — see ADR 0006), `PERMISSION_DENIED` (bad grant token), `INVALID_ARGUMENT` |

Retries on idempotent reads are safe. Retrying on `PERMISSION_DENIED` leaks nothing useful and burns budget; retrying on `FAILED_PRECONDITION` won't help (the refresh job is the only thing that can resolve it).

Document this contract in the SDK README so Byteport workers implement it consistently.

### 4. Refresh worker outage (cross-reference)

Already covered in [ADR 0006](0006-provider-adapter-and-refresh.md): if the refresh worker falls behind and `GetCredentials` finds an expired access_token, return `FAILED_PRECONDITION`; worker retries; refresh job catches up on the next tick.

**Observability addition:** `coffer_refresh_lag_seconds = max(0, now() - min(run_at) where attempts < max_attempts)`. Page if it exceeds `2 × refresh_margin` for more than one refresh cycle.

### 5. Health endpoints

```
GET /healthz   — liveness   — 200 iff the process is up.
GET /readyz    — readiness  — 200 iff:
                              - Postgres reachable
                              - KMS reachable OR breaker open with non-empty cache
                              - refresh worker alive (heartbeat within 60s)
```

Used by Fly.io / Kubernetes to route traffic. Critical during rollout: a fresh instance returns `readyz=503` until its KMS, DB, and refresh-worker connections are established, preventing premature traffic.

## Consequences

**Accepted trade-offs:**
- **30s Postgres failover blip is part of our SLO budget**, not engineered around. Workers retry, transfers resume.
- **Cold reads fail during KMS outage** (after breaker opens). Hot tenants survive. Acceptable: cold reads are intrinsically dependent on KMS; the only alternative is caching plaintext DEKs more aggressively, which we've already ruled out.
- **No multi-region failover for the vault itself.** Single-region for the trial. Multi-region adds DEK replication problems (KMS keys are region-scoped) that deserve their own design.

**Implications:**
- The SLO worth advertising is something like **99.9% availability for hot tenants, 99.5% for cold reads**, with degradation gracefully reported via gRPC status codes. Worker authors can write defensive retry code against a published error contract.
- Page conditions: KMS breaker open >5min, refresh lag exceeds threshold, `/readyz` failing across >25% of instances.

## Out of scope here

- Multi-region active-active vault deployment.
- Postgres logical-replica failover playbook (Supabase managed).
- DR / restore-from-backup story (separate ops doc; not an architectural decision).
