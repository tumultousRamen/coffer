# ADR 0006 — Provider Adapter & OAuth Refresh Strategy

S3 credentials are static; OAuth credentials (Dropbox, Google Drive, Box) expire and must be refreshed using a long-lived refresh token. The 200ms P99 read budget cannot absorb a synchronous call to a third-party OAuth endpoint (Dropbox/Google `/oauth/token` P99 is often >800ms). Refresh must therefore happen out-of-band so that `GetCredentials` is always a fast read of an already-fresh token.

Refresh-policy options considered:
- **Sync-on-read** — refresh inline on `GetCredentials` if the token is near expiry. Easiest to implement but blows the P99 budget.
- **Scan-based async** — a background loop periodically scans for credentials expiring soon. Simple, no extra schema, but does polling work for negative results.
- **Self-scheduling per-credential job (chosen)** — each successful refresh schedules its own successor at `new_access_token_expires_at − X`. No polling; each credential carries its own absolute next-fire timestamp.

## Decision

**Self-scheduling, per-credential refresh jobs**, materialized in a `refresh_jobs` table. No sync fallback on the read path.

### Mechanics

1. **On credential write (OAuth providers only):** create a `refresh_jobs` row with `run_at = access_token_expires_at - X` where `X` is the refresh margin (default: 10 minutes; configurable per-provider).
2. **A refresh worker pool** (goroutines in the vault binary, leader-elected via Postgres advisory lock so only one worker pool is active across all vault instances) runs a tight loop:
   ```sql
   SELECT credential_id FROM refresh_jobs
   WHERE run_at <= now() AND attempts < max_attempts
   ORDER BY run_at
   LIMIT 100
   FOR UPDATE SKIP LOCKED;
   ```
   Each claimed job: load credential → call provider's token endpoint → re-encrypt with the tenant DEK → atomically update credential + reschedule the job to `new_expires_at - X`.
3. **`run_at` is absolute, not relative.** If `X = 10 min` and the new token expires 60 min after refresh, the next job's `run_at` is `now() + 50 min`. Successor scheduling is always anchored to the provider's stated expiry, never to the previous job's fire time. This prevents drift if a refresh runs late.
4. **No sync-on-read fallback.** If `GetCredentials` finds an expired access_token (background fell behind, refresh failed, token was revoked at the provider), the vault returns `FAILED_PRECONDITION` with a retry-after hint. The worker retries; the refresh job catches up. This is a deliberate choice — see Consequences.

### Schema

```sql
CREATE TABLE refresh_jobs (
  credential_id  UUID         PRIMARY KEY REFERENCES credentials(id) ON DELETE CASCADE,
  run_at         TIMESTAMPTZ  NOT NULL,
  attempts       INT          NOT NULL DEFAULT 0,
  last_error     TEXT,
  last_attempt_at TIMESTAMPTZ
);

CREATE INDEX refresh_jobs_run_at ON refresh_jobs (run_at) WHERE attempts < 10;
```

`ON DELETE CASCADE` handles user-initiated credential deletion automatically — no orphan jobs.

### Failure classification

The provider adapter MUST classify errors from the token endpoint:

| Error class | Action |
|---|---|
| 2xx with new tokens | Persist atomically, reschedule successor job, reset `attempts`. |
| 4xx with `invalid_grant` / `unauthorized_client` (refresh token revoked at provider) | Set `credentials.status = 'failed'`. Delete the `refresh_jobs` row. Log loudly. No further retries. |
| 429 / 5xx (transient) | Increment `attempts`, bump `run_at` with exponential backoff + jitter, retain the row. |
| Network / timeout | Same as transient. |

After `max_attempts` (default 10) on transient errors, set `credentials.status = 'failed'` and stop. `status='failed'` is the dead-letter state — **no separate DLQ table is needed.** Ops inspect `credentials WHERE status='failed'`.

### Refresh-token rotation (correctness invariant)

OAuth providers MAY return a new refresh token alongside the new access token (Google, Dropbox, and Box all can do this). The refresh logic MUST persist the rotated refresh token atomically with the new access token in a single transaction. **Losing a rotated refresh token bricks the credential** — the old refresh token is dead at the provider, the new one was never persisted, and no further refresh is possible. This is the #1 OAuth correctness bug in production systems and is documented here as a load-bearing invariant.

```go
newSecret := SecretBlob{
    RefreshToken:         pickNotEmpty(resp.RefreshToken, prev.RefreshToken),
    AccessToken:          resp.AccessToken,
    AccessTokenExpiresAt: now().Add(resp.ExpiresIn),
}
// Re-encrypt with tenant DEK and persist in one transaction with the refresh_jobs reschedule.
```

### Provider adapter port

```go
type Provider interface {
    Name() string
    ValidateOnWrite(secret SecretBlob, metadata Metadata) error
    NeedsScheduledRefresh() bool                                  // false for S3
    Refresh(ctx context.Context, secret SecretBlob, metadata Metadata) (SecretBlob, Metadata, error)
}
```

S3 implements `NeedsScheduledRefresh() bool { return false }` and writing an S3 credential does not create a `refresh_jobs` row. OAuth providers implement both methods for real.

## Consequences

**Accepted trade-offs:**
- **No sync fallback on the read path.** If the background refresher falls behind or a token is revoked between scheduled runs, `GetCredentials` returns an error and the worker retries. This was a deliberate choice over a hybrid sync+async model: sync-on-read couples the read-path P99 to the OAuth provider's P99 and is the single biggest threat to the 200ms KPI. The cost is operational — the refresh worker must stay healthy, and observability on `refresh_jobs.run_at < now() - margin` is a first-class alert.
- **Postgres is the job queue.** No Redis-Streams / SQS / Kafka. Justified by scale (≤3M OAuth credentials, ~830 refreshes/sec average even if all tokens were 1-hour) and by `FOR UPDATE SKIP LOCKED` providing safe concurrent job claiming. Scaling to 10M+ users would justify revisiting — sharding the scan by `user_id` hash is the natural next step. Noted, not built.
- **Leader-elected single worker pool (Postgres advisory lock).** Avoids double-running across rolling deploys. Trivial to implement; trivial to remove if we want to shard later.

**Why this design over scan-based async:**
- Scan-based works fine functionally. The self-scheduling model is preferred because (a) it makes the job's intent explicit (one row per pending refresh, queryable for "how behind are we"), (b) it avoids polling-for-negative-results, (c) it's how the candidate originally drew it, and the design carries through coherently.

**Implications:**
- `refresh_jobs.run_at` is a first-class observability signal. Metric: `coffer_refresh_lag_seconds = max(0, now() - run_at)` across the table. Page if it exceeds the refresh margin `X` for more than one cycle.
- Atomicity matters: the refresh transaction updates `credentials` (new ciphertext, new metadata) AND `refresh_jobs` (new run_at, reset attempts) in a single Postgres transaction. Partial success is not allowed.

## Out of scope here

- Multi-region refresh worker placement (a single-region worker is fine for the trial).
- Provider-specific quotas and circuit-breakers (future ADR if needed).
- Backfill / migration of existing credentials if the refresh margin `X` is changed (run a one-shot SQL update; not worth its own ADR).
