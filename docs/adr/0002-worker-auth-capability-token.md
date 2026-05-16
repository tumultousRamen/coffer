# ADR 0002 — Worker Authentication: Per-Job Capability Token

The `GetCredentials` gRPC endpoint returns plaintext (per [ADR 0001](0001-secret-store-vs-broker.md)). Any caller who reaches it with believable identity gets a secret back. Authentication of the worker is therefore a critical security-load-bearing surface in the system.

Options considered:

- **mTLS only** — proves "you're a worker"; one compromised worker can iterate `user_id`s and exfiltrate the entire vault.
- **mTLS + service JWT** — short-lived JWT proves "you're a worker who is currently allowed to read"; still un-scoped per job.
- **mTLS + per-job capability token** — a signed token bound to a specific job and naming the exact credentials it may fetch, minted by the control plane when scheduling a transfer. Vault verifies signature and matches claims against the request.

## Decision

**mTLS + per-job capability token.**

- Control plane signs job grants (asymmetric key — control plane holds private, vault holds public).
- Token claims: `{job_id, user_id, credential_ids: [src_cred_id, dst_cred_id], exp}`, with `exp ≤ 15 min`.
- The token names **specific `credential_ids`**, not provider names. A user may legitimately hold multiple credentials per provider (e.g. `prod_parley_bucket` and `dev_test_bucket` for S3), so any coarser scope than per-credential would let a compromised worker pivot across the user's other credentials of the same provider.
- Vault verifies signature, checks every requested `credential_id` is in the claim, checks `user_id` matches the credential rows, checks `exp`. Only then decrypts and returns.
- mTLS underneath gates the network surface to Byteport-issued workers.

The control-plane minting service is **out of scope** for this trial — the minimal API gateway will mint a permissive grant for demo purposes. The vault verifies grants regardless of who issued them; production swap-in is just a public-key rotation.

## Consequences

- **Blast radius of a compromised worker:** bounded to the credentials for the one in-flight job, not the whole vault and not even all of one user's credentials.
- **Audit:** every plaintext read is keyed by `job_id`, which is the natural unit for customer-facing observability and billing later.
- **Pairs cleanly with the broker evolution in ADR 0001** — when S3 moves to STS, the capability token is the right scope to bind STS sessions to.
- **Cost:** ~50 lines of JWT verification middleware on the vault. Token-minting complexity sits in the (out-of-scope) control plane.

## Threat being hardened against

Primary: **a compromised worker process** (process exploit, dependency compromise, container escape). The capability token ensures such an attacker can only exfiltrate the credentials of the job currently in its hands — not pivot to other tenants, and not pivot to the same tenant's other credentials.

Not hardened against (acknowledged): a compromise of the control-plane signing key (would let an attacker mint arbitrary grants), or a worker that leaks creds in logs (orthogonal — solved by worker discipline + short cred TTLs).
