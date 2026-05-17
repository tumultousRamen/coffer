# ADR 0009 — Observability

The brief identifies observability as a nice-to-have signal that "the system needs replacement or scaling work" and specifies OpenTelemetry + Grafana as the stack. For a credentials vault, observability is also load-bearing for **security correctness** — secrets must never appear in any output, and reads should be auditable even though full auditability is officially de-scoped.

Four sub-decisions:
1. Metrics surface and naming.
2. Tracing on the hot path.
3. Audit logging — soft override of the "out of scope" line in the brief.
4. Secret scrubbing as a correctness invariant.

## Decisions

### 1. Unified telemetry facade

All instrumentation flows through a single internal package (`internal/telemetry`) that wraps OTel, the metric exporter, the structured logger, and the audit-log writer behind one interface. Application code never imports `otel/...` or a logger directly — it imports `telemetry`. This is the seam that makes the observability stack replaceable (per [ADR 0010](0010-modular-boundaries.md), pending) — a downstream consumer can swap the implementation without touching call sites.

```go
type Logger interface {
    Info(ctx context.Context, msg string, fields ...Field)
    Warn(ctx context.Context, msg string, fields ...Field)
    Error(ctx context.Context, err error, msg string, fields ...Field)
    Audit(ctx context.Context, event AuditEvent)            // routed to a separate sink
    StartSpan(ctx context.Context, name string) (context.Context, Span)
    Counter(name string, labels ...Label) Counter
    Histogram(name string, labels ...Label) Histogram
    Gauge(name string, labels ...Label) Gauge
}
```

`Field` and `AuditEvent` types are constrained — they cannot carry a `SecretBlob` (compile-time, per #4 below).

### 2. Metrics (Prometheus exposition via OTel)

```
# Request layer (RED)
coffer_grpc_requests_total{method,code}
coffer_grpc_request_duration_seconds{method}       # histogram
coffer_rest_requests_total{path,method,code}
coffer_rest_request_duration_seconds{path}

# KMS
coffer_kms_calls_total{op,outcome}                 # GenerateDataKey | Decrypt
coffer_kms_call_duration_seconds{op}
coffer_kms_breaker_state                           # 0=closed, 1=half, 2=open

# Cache
coffer_dek_cache_hit_total
coffer_dek_cache_miss_total
coffer_dek_cache_size                              # gauge

# Refresh worker (per ADR 0006)
coffer_refresh_lag_seconds                         # gauge
coffer_refresh_jobs_total{outcome}                 # success | transient | terminal
coffer_credentials_status{provider,status}         # gauge by (provider, active|failed)
```

Naming: `coffer_<subsystem>_<metric>`. Histograms use OTel default buckets unless tuned per-metric (e.g. `coffer_grpc_request_duration_seconds` gets sub-200ms buckets aligned with the P99 SLO).

### 3. Tracing — OTel spans on the hot path

Worker `GetCredentials` produces a trace with the following structure:

```
grpc.GetCredentials
├── authz.verify_grant_token       # JWT verify, claim match
├── cache.dek_lookup                # attr: user_id, hit=true|false
├── kms.decrypt                     # only on cache miss; attr: kms_key_id
├── db.select_credentials           # attr: credential_count
└── crypto.aes_gcm_decrypt          # per credential
```

OTLP exporter to whatever collector the deployment specifies (Grafana Tempo for the trial). Trace propagation across the REST gateway via standard W3C `traceparent` header.

### 4. Audit log — built despite "out of scope"

Soft override of the brief. The cost is ~30 lines and zero infrastructure; the benefit is a usable "who read this credential and when" trail for incident response.

Implementation: a dedicated `Logger.Audit(ctx, event)` method emits a structured JSON line per security-relevant action. Stream to stdout (captured by Fly.io or whichever runtime). Filter in Grafana Loki later. **No DB table, no replay machinery.**

Events emitted:

| Action | Fields |
|---|---|
| `credential.create` | `user_id`, `credential_id`, `provider`, `outcome` |
| `credential.update` | `user_id`, `credential_id`, `provider`, `outcome` |
| `credential.delete` | `user_id`, `credential_id`, `provider`, `outcome` |
| `credential.read`   | `job_id`, `user_id`, `credential_id`, `provider`, `outcome` |
| `credential.refresh`| `credential_id`, `provider`, `outcome`, `attempts` |

No secrets in audit fields, ever — enforced by the `AuditEvent` type (no `SecretBlob`-typed fields).

### 5. Secret scrubbing — correctness invariant

Three layers of defense:

1. **Type-level redaction.** `SecretBlob` and any type containing one implements both `String() string` and `MarshalJSON() ([]byte, error)` returning `"<redacted>"`. `fmt.Sprintf`, `log.Printf`, and `json.Marshal` all produce safe output by default.
2. **CI linter.** A pre-merge check (`go vet` analyzer or a simple `grep` rule) flags any call site that passes a value of type `SecretBlob` or containing `SecretBlob` to a logging or formatting function. Fails CI on match.
3. **Unit tests.** Every error path that touches a secret has a test that captures log output and asserts the secret material does not appear.

This is the one observability decision that is **not** a nice-to-have — a credentials vault that leaks secrets to logs has failed at its primary job.

## Consequences

**Accepted:**
- Application code is locked to the `telemetry` facade. Adds a layer of indirection. Worth it for the replaceability story.
- Audit log writes are synchronous to stdout. Marginal cost (~microseconds per write). No persistence concerns — stdout is captured by the runtime.
- The CI linter adds ~30s to merge time. Acceptable.

**Implications:**
- The `internal/telemetry` package is one of the first things to build — it's a dependency of every other handler. Cost amortizes across the project.
- Page conditions, codified:
  - `coffer_kms_breaker_state == 2` for >5 min.
  - `coffer_refresh_lag_seconds > 2 * refresh_margin` for >1 cycle.
  - `coffer_grpc_request_duration_seconds` P99 > 250ms for >5 min.
  - `coffer_credentials_status{status="failed"}` increasing >10/hr (unusual revocation rate).

## Out of scope here

- Log retention policy (ops doc, not architectural).
- Cost attribution / billing-grade metrics (not relevant to the trial deliverable).
- SIEM integration of audit logs (downstream of having them in stdout — trivial later).
