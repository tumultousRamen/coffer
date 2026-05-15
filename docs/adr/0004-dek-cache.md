# ADR 0004 — DEK Cache Design

**Status:** Accepted
**Date:** 2026-05-14

## Context

[ADR 0003](0003-envelope-encryption-shape.md) commits to per-tenant DEKs with caching, but did not specify where they live. The choice matters because the cache is a copy of plaintext key material — the more places it lives, the larger the attack surface.

Options:

| Option | Plaintext DEK location | KMS calls @ steady state | Cold-start behavior |
|---|---|---|---|
| A. In-process LRU only | RAM of each vault instance | ~0 hot, 1 cold per instance | Brief burst on rollout |
| B. Redis only (plaintext) | Redis | ~0 | Hot from first request | 
| C. Redis (encrypted DEK) | Vault RAM only; Redis caches encrypted blob | 1 KMS call per cold read | Same as A — Redis doesn't save the expensive hop |
| D. Two-tier: in-process L1 + Redis (encrypted) L2 | Vault RAM + Redis | ~0 hot, 1 KMS on cold | Better than A only on the DB round-trip, not KMS |

Putting **plaintext** DEKs in Redis is unacceptable — a Redis compromise plus DB access decrypts the entire vault. Putting **encrypted** DEKs in Redis only saves a DB round-trip, not the KMS round-trip that dominates the latency, so the operational complexity isn't justified.

## Decision

**In-process LRU only.** No Redis tier for DEKs.

- **Implementation:** `golang-lru/v2`, concurrent.
- **Capacity:** ~100K entries (≈3 MB resident).
- **TTL:** 5 minutes. Bounds the staleness of revocation and rotation events across instances.
- **Cache key:** `user_id`. Value: `{plaintext_dek, dek_version, expires_at}`.
- **Single-flight on miss:** use `golang.org/x/sync/singleflight` keyed by `user_id`. A thundering herd of concurrent reads for the same user fires exactly one KMS `Decrypt`. Critical on cold rollout.
- **Eviction:** LRU + TTL. On DEK rotation, the rotating instance evicts its own entry; other instances pick up the new DEK on TTL expiry.
- **No cross-instance invalidation signal.** Pubsub fan-out is not worth the complexity at 1M users; the 5-min TTL is the propagation bound.

## Redis: what it actually does in this system

Redis remains in the architecture, but **not as the DEK cache**. Its jobs are:

1. **Rate limiting** at the gateway (per user, per API key, per IP).
2. **OAuth access-token cache** — short-lived access tokens minted from stored refresh tokens (see future ADR on provider abstraction).
3. **Idempotency keys** on credential write paths (POST/PUT) to make retries safe.

These are use cases where Redis's strengths (shared state, fast TTL semantics, atomic ops) actually fit, without crossing the trust boundary into plaintext key material.

## Consequences

**Accepted trade-offs:**
- Each vault instance warms its own DEK cache. After a rolling deploy, expect a brief KMS `Decrypt` burst per new instance. Single-flight makes this manageable at 1M users.
- Revocation propagation is bounded by the 5-min TTL, not instantaneous. Acceptable: revocation is rare; the worst case is a 5-min window where a revoked credential is still readable via a cached DEK.

**Implications for downstream design:**
- A vault instance's RAM holds plaintext DEKs for hot tenants. Process memory protection (no swap, no core dumps in prod, `mlock` if paranoid) is a deployment concern, not a code concern — note in ops docs.
- KMS request quotas must accommodate cold-start bursts. Default `Decrypt` quota is 10K req/s; a fresh instance seeing 100K unique tenants in the first minute is well under that even without single-flight.
