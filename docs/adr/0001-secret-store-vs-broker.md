# ADR 0001 — Secret Store vs. Credential Broker

## Context

The vault delivers credentials to transfer workers at transfer time. Two fundamentally different models are possible:

1. **Secret store.** Worker calls `GetCredentials(user_id, provider)`; vault returns the **plaintext** secret over a mutually-authenticated channel; worker uses the plaintext to call S3/Dropbox/etc.
2. **Credential broker.** Worker never sees the long-lived secret. Vault either (a) mints a short-lived scoped token on demand (STS AssumeRole for S3, fresh OAuth access token minted from a stored refresh token for Dropbox/GDrive), or (b) acts as a signing proxy.

The broker model is materially more secure: plaintext long-lived secrets never leave the vault, blast radius of a worker compromise is bounded to in-flight scoped tokens, and the story for classified/air-gapped customers is much stronger. The cost is per-provider broker logic (token-minting, refresh handling, retry semantics) and an extra hop on the read path that pressures the 200ms P99 budget.

The brief, KPI, and whiteboard all presume the secret-store shape (`GetCredentials` returning a secret payload, P99 200ms fetch). The work-trial time-box might not accommodate building correct provider-specific broker logic across S3, Dropbox, Google Drive, and Box.

## Decision

Commit to the **secret-store model** for the work-trial deliverable.

For OAuth-based providers (Dropbox, Google Drive, Box), the vault will refresh access tokens server-side and return the **current access token** (not the refresh token) to workers. This is functionally a broker pattern for OAuth providers — the long-lived refresh token never leaves the vault — without paying the cost of full per-provider broker abstractions on the static-key path.

For static-key providers (S3 access keys), the vault returns the stored plaintext key.

## Consequences

**Accepted trade-offs:**
- Workers hold plaintext long-lived secrets in memory for the duration of a transfer for static-key providers. Mitigated by mTLS on the gRPC link, short-lived worker process memory, and worker-side discipline (never log, never persist).
- The PRD must articulate the production evolution: full broker model with STS-based scoped tokens for S3, eliminating long-lived plaintext on workers entirely.

**Implications for downstream design:**
- The gRPC `GetCredentials` response includes plaintext.
- Per-provider validators and refresh logic need a clean provider-adapter port (see future ADR on provider abstraction).
- Caching design (see future ADR) must reason about plaintext residency.
- Audit log must record every plaintext read with caller identity (even though "auditability" is officially out of scope, the read-path log is cheap and high-value).

## Production evolution path

1. Add an STS-based broker adapter for S3 — workers receive temporary credentials, never the root key.
2. Generalize provider adapters to expose a `MintCredential` method that can return either plaintext (current behavior) or a scoped token.
3. Deprecate plaintext return paths provider-by-provider behind a feature flag.
