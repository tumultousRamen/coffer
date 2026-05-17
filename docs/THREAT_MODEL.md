# Threat Model — coffer

A consolidated view of what the vault defends against and what it explicitly does not. Each row links to the ADR(s) where the mitigation is designed.

## Assets being protected

| Asset | Sensitivity | Persistence |
|---|---|---|
| Long-lived storage-provider secrets (S3 access key, OAuth refresh token) | **Critical** — full account access | At rest in Postgres, encrypted under per-tenant DEK |
| Per-tenant DEKs | **Critical** — decrypts all of one user's credentials | At rest in Postgres, wrapped by KMS KEK; in process memory while cached |
| KMS KEK | **Critical** — decrypts all DEKs | AWS KMS, never leaves KMS |
| Capability tokens | High — short-lived authorization | In-flight only, 15-min expiry |
| Audit-log stream | Medium — operational forensics | stdout, captured by runtime |

## Trust boundaries

```
   [ User / SDK ]
        │ HTTPS + JWT
        ▼
   [ Gateway ]                                ← trust boundary: gateway-issued user identity
        │ internal HTTP, X-User-Id header
        ▼
   [ Vault Service ] ◄── gRPC + capability token ── [ Worker ]
        │
        ├─► [ Postgres ]                      ← trust boundary: dedicated role, encrypted-at-rest
        ├─► [ AWS KMS ]                       ← trust boundary: IAM, audit-logged
        └─► [ Redis ]                         ← trust boundary: VPC-internal, no plaintext key material
```

## Adversaries and mitigations

| Adversary | Capability | Mitigation | ADR |
|---|---|---|---|
| External attacker (network) | Intercept traffic | TLS (user→gateway), mTLS (worker↔vault), TLS (vault↔KMS, vault↔Postgres) | 0002, 0007 |
| External attacker (web exploit on gateway) | Reach REST surface as a user | JWT verification at gateway; rate-limit; type-level secret read-back guard prevents secrets in any response | 0007 |
| Compromised worker process | Holds mTLS cert + capability token; reaches gRPC | Per-job capability token bounds reads to the specific `credential_ids` in claims; mTLS bounds to Byteport-issued workers | 0002 |
| Compromised vault process | Holds plaintext DEKs in cache, can decrypt anything for hot tenants | KMS audit log; process isolation (no swap, no core dumps); read traffic is audit-logged with `job_id`; capability-token verification prevents arbitrary lookups | 0002, 0003, 0009 |
| Compromised Postgres / DB credentials | Reads ciphertext + KMS-encrypted DEKs + metadata | Envelope encryption — DB compromise alone yields no plaintext (KMS key not present); audit log captures unusual access patterns | 0003 |
| Compromised AWS KMS / IAM | Decrypts DEKs given ciphertext | Defense relies on KMS itself; mitigation = IAM least-privilege, separate AWS account for KMS (per brief), KMS audit log monitored | 0003, runbook |
| Compromised Redis | Reads rate-limit counters, OAuth access-token cache entries, idempotency keys | No plaintext long-lived secrets ever written to Redis (per ADR 0004). Short-lived OAuth access tokens in Redis have ≤access-token-TTL blast radius | 0004 |
| Compromised control-plane signing key | Mints arbitrary capability tokens, reads any credentials via workers | Out of scope for vault — assume the control plane's signing key is protected like a KMS KEK. Mitigation = key rotation policy at control-plane layer, audit-log review for unusual `job_id` patterns | 0002 |
| Malicious insider (vault operator) | Direct DB access; KMS access | Production deployment uses separate roles for app and ops; KMS audit log; no break-glass plaintext-export tooling exists by default | 0009 |
| User leaks own credential to a third party | (out of scope for vault) | — | — |
| Worker leaks credential via logs | Captures plaintext in log output | `SecretBlob.String()` returns `<redacted>`; CI lint rule flags logging-call sites that touch `SecretBlob`; unit tests assert no leak on error paths | 0009 |
| Replay of a captured capability token | Use after intended job | 15-min `exp` claim; vault enforces; `job_id` is the audit primitive | 0002 |
| Replay of a captured access token (OAuth) | Use against the provider | Bounded by access-token TTL (≤4h for Dropbox/GDrive/Box). Workers do not persist tokens; vault refreshes on schedule | 0001, 0006 |
| Tampered ciphertext in DB | Swap row's `secret_ciphertext` with another | AAD = `user_id ‖ credential_id ‖ provider` bound to GCM tag — swap is detected on decrypt | 0003 |
| Nonce reuse under same DEK | Catastrophic GCM key-stream recovery | Fresh 96-bit random nonce per encryption, generated at call site; per-tenant DEK has at most ~5 messages so collision probability negligible; lint check for non-random nonce generation | 0003 |
| KMS key accidentally deleted | All ciphertext bricked permanently | AWS KMS 7-30 day pending-delete window; runbook prescribes alarms + recovery; production should disable deletion entirely | runbook |

## STRIDE summary

| Category | Primary defenses |
|---|---|
| **Spoofing** (auth) | mTLS for workers, JWT for users, capability token for per-job authz |
| **Tampering** (integrity) | AES-256-GCM with AAD bound to row identity; TLS in transit |
| **Repudiation** | Structured audit log keyed to `job_id` and `user_id` for every read/write |
| **Information disclosure** | Envelope encryption at rest; type-level secret-read-back guard; redacted log formatters |
| **Denial of service** | Rate limiting at gateway; KMS circuit breaker; bounded batch size; graceful degradation on dep outage |
| **Elevation of privilege** | Per-job capability tokens (no broad-scope grants); no RLS bypass mode; hexagonal layout prevents transport from accessing adapters directly |

## Explicitly out of scope (acknowledged)

- **Compromised control-plane signing key** — the control plane is upstream of the vault; vault inherits its identity assertions.
- **Compromised AWS KMS itself** — defense relies on KMS being correct. Mitigations are at the IAM and account-isolation layer (per brief: separate AWS account for KMS).
- **Side-channel attacks on the vault process** (timing, cache) — addressed at the AES-GCM library level (constant-time implementations); not separately defended.
- **Physical attacks on the Postgres host** — Supabase responsibility.
- **Quantum-resistant cryptography** — AES-256 is considered safe against near-term quantum. Long-term migration is out of scope.

## Most-load-bearing assumptions

1. AWS KMS is correctly implemented and IAM is correctly configured.
2. The control plane's capability-token signing key is protected at least as well as the vault's secrets.
3. Workers do not log, persist, or leak the plaintext they receive — discipline plus short-lived tokens limit blast radius.
4. Postgres is not directly accessible by anything other than the vault service role.
