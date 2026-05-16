# ADR 0001 — Secret Store vs. Credential Broker

**Status:** Accepted
**Date:** 2026-05-14

## Context

Two conceptual models for delivering credentials to transfer workers:

- **Secret store** — vault returns the long-lived plaintext secret; worker uses it directly against the storage provider.
- **Credential broker** — long-lived secret never leaves the vault; vault returns a short-lived, scope-limited token minted from it.

Broker is materially safer: a compromised worker's blast radius is bounded by the short-lived token's TTL, not by the long-lived secret's lifetime. The catch is that broker mode requires a per-provider "mint" primitive — STS `AssumeRole` for S3, OAuth `/oauth/token` refresh for Dropbox / Google Drive / Box, etc. Building that across every provider is expensive.

The earlier framing of this ADR treated the choice as service-wide. That was wrong. **The choice is per-provider**, and it falls out cleanly from whether the provider's protocol gives us a short-lived-token primitive for free.

## Decision

**The vault is architecturally a credential broker.** Per-provider mode is determined by what the protocol provides.

| Provider | Stored (long-lived) | Returned to worker | Mode |
|---|---|---|---|
| Dropbox | `refresh_token` | `access_token` (~4h TTL) | Broker |
| Google Drive | `refresh_token` | `access_token` (~1h TTL) | Broker |
| Box | `refresh_token` (60-day) | `access_token` (~1h TTL) | Broker |
| **S3 (trial scope)** | `access_key_id` + `secret_access_key` | same (long-lived) | **Secret-store** |
| S3 (production evolution) | IAM role / root key | STS temporary credentials (15min–12h) | Broker |

For OAuth providers, broker mode comes for free — the refresh-token flow is the mint primitive, and the vault's refresh worker (ADR 0006) is the mint implementation. Long-lived refresh tokens never leave the vault; workers only ever receive short-lived access tokens.

S3 is the single hold-out — AWS access-key auth has no built-in short-lived primitive, and we have not built the STS adapter for this trial. S3 therefore operates in secret-store mode as a deliberate fallback.

The `Provider` port (ADR 0010) is intrinsically broker-shaped: its `Refresh()` method is the mint function. Adding broker mode to a new provider = implementing that one method.

## Consequences

- **Today's security posture** is broker for 3 of 4 providers. A compromised worker that touched an OAuth credential only exfiltrates a short-lived access token; long-lived refresh tokens are unreachable.
- **The remaining gap** is S3 in secret-store mode. Production evolution is narrowly scoped: add an STS-based adapter behind the existing `Provider` port. No other code changes.
- **Caveat — token TTL varies.** Dropbox / GDrive access tokens (~1–4h) are well-bounded brokered tokens. Box refresh tokens valid 60 days are a softer guarantee; the mint cadence still bounds blast radius but less aggressively than STS (15min–12h). Worth honest naming in the writeup.
- **Audit log** records every read with `job_id`, `credential_id`, `provider`, `outcome` — works identically for broker and secret-store modes (ADR 0009).

## Production evolution

Add an S3-STS adapter that swaps the stored long-lived key for STS-minted temporary credentials on each `GetCredentials` call. The capability token's `job_id` is the natural session-name to bind STS calls against. After this, the vault is broker mode end-to-end.
