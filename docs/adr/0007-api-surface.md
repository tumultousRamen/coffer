# ADR 0007 — API Surface (gRPC + REST Gateway)

Two API surfaces:
1. **Worker-facing gRPC** — called by transfer workers at job time. Hot path. Bound by the 200ms P99 KPI.
2. **User-facing REST** — called by Byteport's product UI / SDK. Manages credential lifecycle. Routed through the minimal API gateway.

Both must encode the invariant from the brief: **users can register credentials but can never read the raw secret back.** That invariant should be enforced as deeply in the stack as possible — ideally at the type system, not at code review.

## Decisions

### 1. Worker-facing gRPC — batch fetch

```protobuf
service Vault {
  rpc GetCredentials(GetCredentialsRequest) returns (GetCredentialsResponse);
}

message GetCredentialsRequest {
  string grant_token = 1;                // signed by control plane, per ADR 0002
  repeated string credential_ids = 2;    // bounded; reject if len > 8
}

message GetCredentialsResponse {
  repeated Credential credentials = 1;
}

message Credential {
  string id = 1;
  string provider = 2;
  string label = 3;
  google.protobuf.Struct secret = 4;     // provider-shaped JSON (decrypted)
  google.protobuf.Struct metadata = 5;   // non-secret config
}
```

**Authorization:** the vault verifies that every `credential_id` in the request is in the grant token's `credential_ids` claim. **Reject the whole request if any ID is unauthorized** — partial fulfillment leaks the existence of credentials the caller wasn't supposed to know about.

**Why batch over single-credential fetch:**
- Transfer jobs always need source + destination — bounded to ~2 credentials.
- One round-trip halves the latency on the worker hot path (matters for the 200ms P99 KPI).
- One authz check, one audit-log event keyed to `job_id` — clean and atomic.
- A `(user_id, provider)` lookup model was rejected because users can have multiple credentials per provider (e.g. `prod_parley_bucket` and `dev_test_bucket` for S3). The grant must name specific IDs.

This decision triggered the refinement of [ADR 0002](0002-worker-auth-capability-token.md) — the capability token now carries `credential_ids`, not `allowed_providers`.

### 2. User-facing REST gateway

```
POST   /v1/credentials                  — create
GET    /v1/credentials                  — list (CredentialSummary[])
GET    /v1/credentials/{id}             — detail (CredentialSummary)
PUT    /v1/credentials/{id}             — replace secret (atomic; new ciphertext + nonce)
DELETE /v1/credentials/{id}             — hard delete (per ADR 0005)
```

**Authentication:** JWT in `Authorization: Bearer <token>` bearing `user_id`. Gateway verifies; vault service trusts the gateway's verified header. For the trial, the gateway issues stub JWTs — Byteport will swap in their real auth in production. Document this seam in the gateway README.

**No secret read-back, ever, on any GET endpoint.** Enforced by types (see #3).

### 3. Compile-time secret read-back prevention

Two Go types, one with secret material and one without. The compiler refuses any code path that returns a secret to a user-facing handler.

```go
// Internal-only. The gRPC worker handler returns this.
type Credential struct {
    ID       string
    Provider string
    Label    string
    Secret   SecretBlob
    Metadata Metadata
}

// User-facing. The REST handlers return this. No Secret field exists.
type CredentialSummary struct {
    ID        string
    Provider  string
    Label     string
    Status    string
    CreatedAt time.Time
}

func (s *VaultService) ListMyCredentials(ctx, userID) []CredentialSummary { ... }
func (s *VaultService) FetchForWorker(ctx, grantToken, ids) []Credential { ... }
```

Mistaken code (returning a `Credential` from a user-facing handler) fails to compile. The "users cannot read back" rule becomes a load-bearing **type-system invariant**, not a code-review property. Cost: ~10 lines of type plumbing. Benefit: a senior reviewer reads this and understands the safety property in seconds.

### 4. Idempotency on POST

`POST /v1/credentials` accepts an `Idempotency-Key: <opaque>` header.

- Server hashes the key, looks up `idem:{user_id}:{key_hash}` in Redis.
- Hit → return the previously stored `credential_id` with HTTP 200 and the original response body.
- Miss → create the credential, store `key_hash → {credential_id, response_body}` in Redis with 24h TTL, return 201.

Why: client retries on transient network errors are normal. Without idempotency, retries create duplicate credentials silently. With it, retries are safe.

Redis is already in the stack per [ADR 0004](0004-dek-cache.md) (rate limiting, OAuth access-token cache); idempotency keys join that list.

### 5. Update semantics — PUT replaces secret atomically

`PUT /v1/credentials/{id}` replaces the full secret payload. No PATCH on individual secret fields. Avoids "I partially updated the secret blob and now the credential is broken."

## Consequences

**Accepted trade-offs:**
- Batch fetch upper bound (8) is defensive only — actual jobs use exactly 2. Costs nothing.
- Idempotency adds Redis as a hard dependency for the write path (was previously soft — rate limiting can degrade open, idempotency cannot). Mitigated by treating Redis as required infrastructure rather than optional cache.
- Type-level safety only covers Go code; the JSON serializers and the protobuf message types must independently respect the boundary. Reviewed in code, not type-enforced (the cost of crossing language/protocol boundaries).

**Implications:**
- The gateway is responsible for JWT verification, rate limiting, and idempotency-key bookkeeping. Vault trusts its `X-User-Id` header.
- The worker SDK is dirt simple: one gRPC call per job; the response contains both credentials in their plaintext form. Easy to extract and replace.

## Out of scope

- Streaming RPCs / server-push for credential changes (not needed; workers fetch once per job).
- Versioned API surface (`/v2/`) — single version is fine for the trial; document the path.
- Granular permissions ("read-only credential", "shared-with-team credential") — future product features, not vault concerns.
