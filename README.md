# coffer

Credentials vault microservice — Byteport work trial.

A Go/gRPC service that stores customer credentials for external storage providers (S3, Dropbox, Google Drive, Box) and delivers them to transfer workers at transfer time. Encrypted at rest with envelope encryption (AWS KMS), designed for modular, replaceable deployment so Byteport can extract it into their production system.

- [PRD](docs/PRD.md)
- [ADRs](docs/adr/)

---

## System Context

```mermaid
flowchart LR
    User([User])
    Worker([Transfer Worker])
    CP([Control Plane<br/>capability-token minter<br/><i>out of scope</i>])

    subgraph coffer["coffer (this repo)"]
        Gateway["REST Gateway<br/>JWT • rate-limit • idempotency"]
        Vault["Vault Service<br/>Go • gRPC"]
        Refresh["Refresh Worker<br/>leader-elected"]
    end

    PG[("Postgres<br/>Supabase")]
    KMS[("AWS KMS")]
    Redis[("Redis")]
    OAuthP([OAuth Providers<br/>Dropbox / GDrive / Box])

    User -->|HTTPS + JWT| Gateway
    Gateway -->|internal gRPC| Vault
    CP -.->|signs job grants| Worker
    Worker -->|gRPC + capability token| Vault

    Vault --> PG
    Vault --> KMS
    Vault --> Redis
    Refresh --> PG
    Refresh -->|refresh tokens| OAuthP
```

Two clients of the vault: **users** (manage credentials via REST), **workers** (fetch credentials at transfer time via gRPC). The control plane mints per-job capability tokens that scope what a worker can fetch. See [ADR 0001](docs/adr/0001-secret-store-vs-broker.md), [ADR 0002](docs/adr/0002-worker-auth-capability-token.md).

---

## Hot Path — Worker `GetCredentials`

```mermaid
sequenceDiagram
    autonumber
    participant W as Worker
    participant V as Vault
    participant C as DEK Cache<br/>(in-process LRU)
    participant K as AWS KMS
    participant DB as Postgres

    W->>V: GetCredentials(grant_token, [src_id, dst_id])
    V->>V: Verify grant signature + claims + exp
    V->>DB: SELECT credentials WHERE id IN (...)
    DB-->>V: rows (ciphertext, nonce, dek_version, metadata)

    V->>C: Lookup DEK for user_id
    alt cache hit
        C-->>V: plaintext DEK
    else cache miss (single-flight)
        V->>K: Decrypt(encrypted_dek)
        K-->>V: plaintext DEK
        V->>C: Store (TTL 5 min)
    end

    V->>V: AES-256-GCM decrypt with AAD<br/>(user_id ‖ credential_id ‖ provider)
    V-->>W: [Credential{secret, metadata}, ...]
```

Steady-state hot path = 1 SELECT + 1 in-process AES-GCM. No KMS calls except on cold tenant. P99 budget 200 ms. See [ADR 0003](docs/adr/0003-envelope-encryption-shape.md), [ADR 0004](docs/adr/0004-dek-cache.md), [ADR 0007](docs/adr/0007-api-surface.md).

---

## OAuth Refresh — Self-Scheduling Per-Credential Jobs

```mermaid
sequenceDiagram
    autonumber
    participant U as User
    participant V as Vault
    participant DB as Postgres
    participant R as Refresh Worker<br/>(leader-elected)
    participant P as OAuth Provider

    U->>V: POST /v1/credentials (Dropbox)
    V->>V: encrypt secret with tenant DEK
    V->>DB: INSERT credentials
    V->>DB: INSERT refresh_jobs(run_at = expires_at - X)
    V-->>U: 201 Created

    loop refresh tick
        R->>DB: SELECT FOR UPDATE SKIP LOCKED<br/>WHERE run_at <= now()
        DB-->>R: claim job
        R->>P: POST /oauth/token (refresh_token)
        alt 200 OK
            P-->>R: new access_token (+ maybe new refresh_token)
            R->>DB: BEGIN<br/>UPDATE credentials (re-encrypt)<br/>UPDATE refresh_jobs (run_at = new_expires - X)<br/>COMMIT
        else 4xx invalid_grant
            R->>DB: UPDATE credentials status='failed'<br/>DELETE refresh_jobs row
        else 5xx / network
            R->>DB: UPDATE refresh_jobs attempts++<br/>backoff run_at
        end
    end
```

`run_at` is absolute (`new_expires_at - X`), not relative — prevents drift if a refresh runs late. Rotated refresh tokens are persisted in the same transaction as the new access token (load-bearing correctness invariant). `status='failed'` is the dead-letter state; no separate DLQ. See [ADR 0006](docs/adr/0006-provider-adapter-and-refresh.md).

---

## Architecture — Hexagonal / Ports & Adapters

```mermaid
flowchart TB
    subgraph cmd["cmd/"]
        Main["vault/main.go<br/>composition root"]
        Migrate["coffer-migrate/<br/>data migration CLI"]
    end

    subgraph transport["internal/transport/"]
        Grpc["grpc/<br/>worker-facing"]
        Rest["rest/<br/>user-facing"]
    end

    subgraph core["internal/vault/  (CORE — no infra deps)"]
        Service["service.go<br/>orchestration"]
        Types["credential.go<br/>types + redaction"]
        Ports["ports.go<br/>KeyManager • CredentialStore<br/>Provider • Telemetry"]
    end

    subgraph adapters["internal/adapters/"]
        AWS["awskms/"]
        PG["postgres/"]
        Providers["providers/<br/>s3 • dropbox<br/>gdrive • box"]
        Tel["telemetry/<br/>OTel + audit"]
    end

    Main --> Grpc
    Main --> Rest
    Main --> AWS
    Main --> PG
    Main --> Providers
    Main --> Tel

    Grpc --> Service
    Rest --> Service
    Service --> Ports

    AWS -.implements.-> Ports
    PG -.implements.-> Ports
    Providers -.implements.-> Ports
    Tel -.implements.-> Ports
```

**Dependency direction is one-way.** `internal/vault` (core) imports nothing in `internal/adapters` or `internal/transport`. Adapters implement the port interfaces defined by core. `cmd/vault/main.go` is the only place where adapters get wired into the core service.

Byteport can swap any adapter — KMS, DB, provider, telemetry — by replacing one folder and re-wiring `main.go`. The core lifts cleanly into their monorepo as a library. See [ADR 0010](docs/adr/0010-modular-boundaries.md).

---

## Tech Stack

| Layer | Choice |
|---|---|
| Language | Go |
| Service interface | gRPC (worker-facing) + REST gateway (user-facing) |
| Datastore | Postgres (Supabase-compatible) |
| Key management | AWS KMS (envelope encryption, per-tenant DEK, AES-256-GCM) |
| Cache / supporting | Redis (rate limiting, OAuth access-token cache, idempotency keys) |
| Observability | OpenTelemetry → Grafana |

## Build & Demo

See [ADR 0011](docs/adr/0011-scope-and-build-order.md) for the day-by-day build plan and the demo script (`demo/run.sh` — TBD).
