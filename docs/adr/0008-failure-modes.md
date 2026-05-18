# ADR 0008 — Failure Modes & Availability

The vault is on the critical path for all transfers — when it's down, transfers fail. The non-functional requirement isn't "never go down" (impossible), it's "fail gracefully and minimize the blast radius of dependency outages." Four failure surfaces need explicit decisions:

1. AWS KMS outage (regional AWS issue, transient throttling, network partition to KMS).
2. Postgres outage / failover (Aurora primary; per-region read replicas per [ADR 0012](0012-multi-region-topology.md)).
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

### 2. Postgres — Aurora primary + per-region read replicas

Per [ADR 0012](0012-multi-region-topology.md), Byteport deploys an Aurora primary in one region and a read replica per additional region. Each regional vault instance reads from its **local** replica and writes to the **single primary**. Replication lag P99 ≈ 1 second.

**Read-after-write inconsistency — handled by primary-fallback-on-miss.**

```
GetCredentials(ids):
    rows = regional_replica.SELECT ids
    missing = ids \ rows.ids
    if missing and primary_reachable:
        rows ∪= primary.SELECT missing           # one extra hop, only on miss
    return rows
```

Steady-state reads are unaffected; only genuine 404s and rare in-replication-window reads pay the extra cross-region primary round-trip. This eliminates the read-after-write window entirely, with no write-side logic needed. The trade is justified because misses are rare and tolerating an extra hop on the miss path is cheaper than any read-your-writes write-side mechanism (origin-region stamping, replication-wait, etc.).

**Trade-offs:**
- Genuine 404s pay one extra primary round-trip (~50–150ms cross-region). Acceptable — misses are rare in steady state.
- If primary is unreachable AND replica is stale, the read returns a false 404. Same failure mode as before for that intersection; documented, not engineered around.

**Regional read replica outage — fail and alert, no auto-failover.**

If a regional vault loses its local replica, requests in that region fail with `UNAVAILABLE` and the outage is surfaced via observability. The vault **does not** auto-fallback to another region's replica. Reasoning:
- Cross-region failover would mask the outage and prevent the right operational response (replace the replica, reroute traffic at the load balancer level).
- Steady-state cross-region reads break the 50ms P99 read SLO ([PRD §2](../PRD.md), [ADR 0012](0012-multi-region-topology.md)).
- Cache-hot tenants in that region also fail, because every credential read needs the row from DB (the DEK cache alone is not sufficient to serve a read).

Page condition: `coffer_pg_replica_reachable{region=X} == 0` for >60s.

**Aurora primary failover.** Aurora handles primary failover automatically (~10–15s typical). Vault gRPC calls return `UNAVAILABLE` during the window; workers retry; transfers resume. **Document, don't engineer around.** Connection pool uses `pgx` with reconnect.

**Rejected alternatives:**
- **Synchronous wait-for-replication on writes.** Would block every user-facing POST until propagation completes; degrades write SLO from 200ms to seconds. Rejected.
- **Ciphertext cache in Redis as failover.** Same trust-boundary problems as plaintext DEK caching ([ADR 0004](0004-dek-cache.md)), plus stale-on-write inconsistency.

### 3. Worker gRPC deadline & retry policy

| Setting | Value |
|---|---|
| Per-call deadline | **75ms** (~25ms buffer over the 50ms P99 read SLO) |
| Retry count | 2 |
| Backoff | 50ms + jitter |
| Retry on | `UNAVAILABLE`, `DEADLINE_EXCEEDED` |
| **Do not retry on** | `FAILED_PRECONDITION` (expired token — see ADR 0006), `PERMISSION_DENIED` (bad grant token), `INVALID_ARGUMENT` |

Retries on idempotent reads are safe. Retrying on `PERMISSION_DENIED` leaks nothing useful and burns budget; retrying on `FAILED_PRECONDITION` won't help (the refresh job is the only thing that can resolve it).

Document this contract in the SDK README so Byteport workers implement it consistently.

### 4. Refresh worker outage (cross-reference)

Per [ADR 0006](0006-provider-adapter-and-refresh.md): if the refresh worker falls behind and `GetCredentials` finds an expired access_token, the vault **inline-refreshes against the OAuth provider** (sync-on-stale fallback), persists the new token, schedules a new refresh job, and returns the fresh token to the worker. The sync-refresh path is allowed to live outside the 50ms read P99 SLO — Dropbox/Google `/oauth/token` is ~200–800ms — because it only fires when the refresh worker has fallen behind, which should be rare.

**The SLO depends on refresh-worker health.** As long as sync-refresh fires on <1% of reads, P99 is dominated by cache-hot + cold-KMS paths and the 50ms SLO holds. If sync-refresh frequency rises, P99 degrades — which is why `coffer_refresh_lag_seconds` is a first-class alert.

**Observability:** `coffer_refresh_lag_seconds = max(0, now() - min(run_at) where attempts < max_attempts)`. Page if it exceeds `2 × refresh_margin` for more than one refresh cycle.

### 5. Health endpoints

```
GET /healthz   — liveness   — 200 iff the process is up.
GET /readyz    — readiness  — 200 iff:
                              - Local regional Postgres replica reachable
                              - KMS reachable OR breaker open with non-empty cache
                              - refresh worker alive (heartbeat within 60s)
```

Used by Fly.io / Kubernetes to route traffic. Critical during rollout: a fresh instance returns `readyz=503` until its KMS, DB, and refresh-worker connections are established, preventing premature traffic.

## Consequences

**Accepted trade-offs:**
- **Aurora failover (~10–15s) is part of our SLO budget**, not engineered around. Workers retry, transfers resume.
- **Cold reads fail during KMS outage** (after breaker opens). Hot tenants survive. Acceptable: cold reads are intrinsically dependent on KMS; the only alternative is caching plaintext DEKs more aggressively, which we've already ruled out.
- **Regional replica outage = fail in that region.** No auto-failover to another region. Operational response (replace replica, reroute) is the correct lever.
- **Read-after-write false 404 only at the intersection of "primary unreachable" + "replica stale".** Vanishingly rare; documented, not engineered around.

**Implications:**
- The SLO worth advertising is something like **99.9% availability for hot tenants, 99.5% for cold reads**, with degradation gracefully reported via gRPC status codes. Worker authors can write defensive retry code against a published error contract.
- Page conditions: KMS breaker open >5min, refresh lag exceeds threshold, `/readyz` failing across >25% of instances.

## Out of scope here

- Multi-region active-active vault deployment.
- Aurora cluster operations playbook (managed by Byteport's existing DBA tooling).
- DR / restore-from-backup story (separate ops doc; not an architectural decision).
