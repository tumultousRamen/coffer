# ADR 0003 — Envelope Encryption Shape

Credentials must be encrypted at rest such that a Postgres compromise alone cannot recover plaintext. We use **envelope encryption** with AWS KMS: a KEK (Key Encryption Key) lives in KMS and never leaves; DEKs (Data Encryption Keys) encrypt the actual secret bytes; the DB stores ciphertext + the KMS-encrypted DEK.

The load-bearing choice is **DEK granularity**: one DEK per credential, one per tenant, or one per epoch.

| Option | KMS calls / read (steady state) | Blast radius of leaked DEK | Cache efficiency |
|---|---|---|---|
| A. Per-credential DEK | 1 `Decrypt` every read | 1 credential | Poor (5M keys) |
| B. Per-tenant DEK | 0 (cache hit), 1 on cold miss | ≤5 credentials, one user | Strong (1M keys, smaller hot set) |

KMS `Decrypt` is ~10–30ms within-region. The P99 200ms budget cannot tolerate a KMS round-trip on every read.

## Decision

**Per-tenant DEK with in-memory cache.** Specifically:

- **KEK:** symmetric AWS KMS CMK, alias e.g. `alias/coffer-tenant-kek`. Never leaves KMS.
- **DEK:** AES-256, generated lazily on the first credential write for a `user_id` via `kms:GenerateDataKey(KeySpec=AES_256)`. KMS returns `{plaintext, ciphertext}`; we encrypt with `plaintext`, persist `ciphertext` on the tenant row, and zero the `plaintext` after caching it.
- **Cipher:** **AES-256-GCM**. Authenticated encryption — integrity is non-negotiable for a credentials store.
- **Nonce:** fresh 96-bit random nonce per encryption, stored alongside the ciphertext on the credential row. *Reusing a nonce under the same key in GCM is catastrophic — recovers the key stream — so this must be enforced at the call site, not left to convention.*
- **AAD (Additional Authenticated Data):** include `user_id || credential_id || provider` as AAD. Binds the ciphertext to its row so a swap-the-blob attack on the DB is detected on decrypt.
- **Cache:** decrypted DEKs cached in process memory keyed by `user_id`. Cache design is its own ADR (see [ADR 0004](0004-dek-cache.md), pending).
- **Rotation:** per-tenant DEK is rotated by generating a new DEK, re-encrypting that user's credentials in one transaction, and retiring the old DEK row. KEK rotation handled by KMS automatic key rotation; ciphertexts under the old KEK version remain decryptable.

## Consequences

**Accepted trade-offs:**
- One leaked DEK exposes up to 5 credentials for one user. Acceptable: it is a per-tenant incident, not a vault-wide one. Customers needing stricter isolation get single-tenant deployment, not finer-grained DEKs.
- Steady-state cache hit on reads means the freshness of revocation depends on cache invalidation, not on KMS-side key deletion. Crypto-shred only takes effect after cache eviction (see ADR 0004).

**Implications for downstream design:**
- The credential row schema needs columns for `ciphertext`, `nonce`, `dek_version` (so we can roll DEKs without ambiguity).
- The tenant table needs a column for `encrypted_dek` and `dek_version`.
- Cache TTL / eviction policy is now load-bearing for both performance and revocation semantics.

## Out of scope here

- Cache design (ADR 0004).
- KMS outage behavior (ADR 0008).
- Whether per-credential DEKs should reappear for specific high-sensitivity providers — possible future ADR if a customer demands it.

## A note on the whiteboard

The original whiteboard sketch labeled the DEK algorithm "SHA256". SHA-256 is a hash function, not a cipher, and has no role in this design. The intended algorithm — and the one accepted here — is **AES-256-GCM** for the data path, with the KEK as an AWS KMS-managed symmetric CMK. Logged here to avoid the confusion resurfacing.
