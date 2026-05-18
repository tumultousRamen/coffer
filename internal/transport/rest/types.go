// Package rest — JSON request/response shapes for the user-facing
// credential lifecycle (ADR 0007 §2; PRD 0007).
//
// The wire shapes are deliberately small. `Secret` rides as a Go
// []byte field, which encoding/json base64-encodes on the wire — this
// matches the bytes shape established for gRPC in PRD 0006 so both
// transports carry secrets identically.
//
// CredentialSummary on the wire (SummaryResponse) carries only
// non-secret fields. Per ADR 0007 §3, no REST endpoint surfaces
// secret material, and CredentialSummary has no Secret field for the
// type system to surrender.
package rest

import "time"

// CreateRequest is the body of POST /v1/credentials.
type CreateRequest struct {
	Provider string         `json:"provider"`
	Label    string         `json:"label"`
	Secret   []byte         `json:"secret"`
	Metadata map[string]any `json:"metadata,omitempty"`
}

// CreateResponse is the body of a successful POST /v1/credentials.
// The single field mirrors the gRPC Credential.id shape.
type CreateResponse struct {
	ID string `json:"id"`
}

// SummaryResponse is the user-facing projection of a credential.
// Mirror of vault.CredentialSummary; the type-system invariant from
// ADR 0007 §3 forbids a Secret field here.
type SummaryResponse struct {
	ID        string    `json:"id"`
	Provider  string    `json:"provider"`
	Label     string    `json:"label"`
	Status    string    `json:"status"`
	CreatedAt time.Time `json:"created_at"`
}

// ListResponse wraps SummaryResponse rows so future pagination
// fields (next_cursor, total) can be added without breaking
// clients. Per ADR 0005 the per-user ceiling is ~5 credentials and
// pagination is out of scope for the trial.
type ListResponse struct {
	Credentials []SummaryResponse `json:"credentials"`
}

// ReplaceRequest is the body of PUT /v1/credentials/{id}. Provider
// and label are not exposed because the AES-GCM AAD binds them
// (ADR 0003) — changing provider on replace would brick the row.
// ADR 0007 §5 also pins PUT to "replace secret payload, atomic".
type ReplaceRequest struct {
	Secret   []byte         `json:"secret"`
	Metadata map[string]any `json:"metadata,omitempty"`
}

// ErrorResponse is the standard error body returned for non-2xx
// responses. Error is the short human-readable category. Reason is
// the optional provider-side detail surfaced for 422 Unprocessable
// Entity (provider validation failure) — e.g. the AWS error string
// from a failed s3:ListBuckets probe. omitempty keeps the body
// minimal for status codes that do not carry a reason.
//
// Body intentionally avoids row IDs, SQL fragments, claim contents,
// or any other internal detail that would help an attacker map the
// system. Status code carries the semantic; reason carries the
// provider-side debugging hint when (and only when) the failure
// originates outside the vault.
type ErrorResponse struct {
	Error  string `json:"error"`
	Reason string `json:"reason,omitempty"`
}
