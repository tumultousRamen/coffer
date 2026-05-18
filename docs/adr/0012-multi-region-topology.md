# ADR 0012 — Multi-Region Deployment Topology

**Status:** Accepted
**Date:** 2026-05-17

## Context

The 50ms read P99 SLO ([PRD §2](../PRD.md)) cannot be honored from a single-region vault when workers run in distant regions — Sydney → US-West round-trip alone is ~160ms. Byteport's existing platform topology already addresses this with regional infrastructure:

- **Aurora primary in one region** (initial: `us-east-1`), with **per-region read replicas** in every additional region.
- **Two Redis instances per region** (ElastiCache): one hosted no-eviction node for stateful state (rate limit, idempotency); one serverless LRU instance for cache-like state.
- **Workers** run regionally; they hit the nearest regional vault.

Initial scale: **4 regions, growing to ~10 within 6 months.**

The vault must fit this topology — deployed as a microservice per region — and the read/write paths must split accordingly.

## Decision

**Vault deploys as a regional microservice.** Each region hosts:
- A vault binary (gRPC + REST + in-process refresh worker pool).
- A connection to the **local Aurora read replica** (for reads).
- A connection to the **single Aurora primary** (for writes and primary-fallback-on-miss).
- Connections to the two regional Redis instances.
- An in-process DEK cache ([ADR 0004](0004-dek-cache.md)) — independent per regional instance.

### Read path

Every credential read targets the local regional replica:

```
GetCredentials(ids):
    rows = local_replica.SELECT credentials WHERE id IN (ids)
    missing = ids \ rows.ids
    if missing and primary_reachable:
        rows ∪= primary.SELECT credentials WHERE id IN (missing)   # extra hop, only on miss
    return rows
```

The primary-fallback-on-miss handles the read-after-write window. See [ADR 0008 §2](0008-failure-modes.md).

### Write path

Every credential write (POST/PUT/DELETE) goes to the **primary**, regardless of which region the request originated from. The primary asynchronously replicates to all regional replicas (P99 lag ≈ 1 second). The originating region's vault returns success as soon as the primary commit completes; it does **not** wait for propagation.

```
CreateCredential(user_id, cred):
    encrypt and INSERT against primary
    response returned to caller as soon as primary commit
    (regional replicas catch up async ~1s P99)
```

This means a user who creates a credential in `ap-southeast-2` and immediately starts a transfer in the same region may, for ~1s, see a 404 from the regional replica. The primary-fallback-on-miss on the read path resolves this: the read sees no row in the replica, falls back to primary, finds the row, returns it.

### Refresh worker placement

The refresh worker (per [ADR 0006](0006-provider-adapter-and-refresh.md)) is leader-elected via Postgres advisory lock **against the primary**. Exactly one refresh worker pool runs across all regions. This is correct because:
- Refresh writes go to the primary anyway.
- Running per-region refresh workers would multiply the OAuth provider call volume by N and risk hitting provider rate limits.
- The advisory lock is held on the primary; only the leader's region sees the work.

A future optimization (10M+ users, see ADR 0006) is to shard refresh workers by `user_id` hash across regions, each holding a per-shard advisory lock. Not built.

### KMS placement

AWS KMS keys are region-scoped. Two viable options:
- **A. Single-region KMS.** All vault instances call the KMS in `us-east-1` (or wherever the primary lives). Cross-region KMS calls add ~50ms; cold-tenant reads from other regions blow the SLO. Acceptable only if cold-tenant frequency is low.
- **B. Multi-region KMS keys** (AWS feature). KMS replicates the key material to other regions; vault calls its local KMS. No cross-region penalty.

For the trial (single-region build): **A**, single-region KMS. For production rollout to multi-region: **B**, multi-region KMS keys — and the `coffer-migrate` CLI gains a "promote to multi-region key" mode. Documented in [PRD §8](../PRD.md).

### Regional outage handling

Per [ADR 0008 §2](0008-failure-modes.md):
- **Regional Aurora replica down** → requests in that region fail with `UNAVAILABLE`. No auto-failover to another region. Operational response (replace replica, reroute traffic at the load balancer layer) is the correct lever.
- **Aurora primary down** → all writes fail globally during failover (~10–15s Aurora typical); reads from regional replicas continue serving cache-hot tenants. Cold reads that need primary-fallback-on-miss also fail.
- **A region's vault binary down** → load balancer routes traffic to the nearest healthy region. Increased cross-region latency for that traffic; SLO degraded for affected users but service available.

## Consequences

**Accepted:**
- **Read-after-write inconsistency window** (~1s) is real, handled transparently by primary-fallback-on-miss. The only failure intersection is "primary unreachable + replica stale" — extremely rare.
- **Refresh worker centralization on primary** trades off per-region resilience for provider-rate-limit safety. Correct for current scale.
- **Single-region KMS for the trial** is a known SLO risk for cold-tenant reads from non-primary regions. Mitigated by aggressive DEK caching (per [ADR 0004](0004-dek-cache.md)) and acknowledged as a production-evolution item.

**Implications:**
- The vault binary needs **two Postgres connection pools**: one to the local replica, one to the primary. Adapter (`internal/adapters/postgres`) exposes both.
- Configuration adds a `COFFER_PG_PRIMARY_URL` env var alongside `COFFER_PG_URL` (which now means the regional replica). [ADR 0010](0010-modular-boundaries.md) env-var list extended accordingly.
- The `coffer-migrate` CLI continues to target Aurora; multi-region promotion is a separate future mode.
- Observability adds `coffer_pg_replica_reachable{region=X}` and `coffer_pg_primary_reachable` gauges.

## Trial scope

The trial build is **single-region only**. The multi-region deployment is documented as the production target, with the code shaped to support it (two PG connections, sharded refresh worker would slot in cleanly). Building the actual multi-region deployment is out of scope for the trial timeline ([ADR 0011](0011-scope-and-build-order.md)).

## Out of scope

- Cross-region Redis replication (we don't use Redis for anything that needs cross-region consistency).
- Active-active primary (multi-master). Not provided by Aurora's default config; out of scope.
- Per-region KMS key rotation procedures (future ops doc).
- DR / restore-from-backup story across regions.
