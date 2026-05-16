package vault

import "time"

// Status is the credential lifecycle state. Values are the strings that
// appear in the credentials.status column (see ADR 0005).
type Status string

const (
	StatusActive Status = "active"
	StatusFailed Status = "failed"
)

// Metadata is the non-secret per-credential configuration (region,
// scopes, account_email, etc.). Travels in plaintext alongside the
// encrypted secret blob per the two-blob model (ADR 0005).
type Metadata map[string]any

// Credential is the full credential record including plaintext secret
// material. Returned to workers from gRPC GetCredentials. Must never
// be returned from a user-facing REST handler — use CredentialSummary
// instead.
type Credential struct {
	ID       string
	Provider string
	Label    string
	Secret   SecretBlob
	Metadata Metadata
}

// CredentialSummary is the user-facing projection of a credential. It
// deliberately has no Secret field — REST handlers return this type so
// the compile-time guarantee from ADR 0007 §3 holds.
type CredentialSummary struct {
	ID        string
	Provider  string
	Label     string
	Status    Status
	CreatedAt time.Time
}
