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

// Credential is the full credential record. It leads a dual life:
//
//   - On the storage path (CredentialStore.Get/Create/Replace) Secret
//     holds the AES-GCM ciphertext and Nonce / DEKVersion carry the
//     row's per-secret nonce and the tenant DEK epoch under which the
//     ciphertext was sealed. All three fields round-trip through the
//     CredentialStore implementations.
//   - On the worker-facing decrypt path (returned by the service-layer
//     FetchForWorker method, a future PRD) Secret holds plaintext and
//     Nonce / DEKVersion are left zero — they have served their purpose
//     during decrypt and the worker has no use for them.
//
// Must never be returned from a user-facing REST handler — use
// CredentialSummary instead.
type Credential struct {
	ID         string
	Provider   string
	Label      string
	Secret     SecretBlob
	Metadata   Metadata
	Nonce      []byte // populated on storage path; zero on worker-facing decrypt path
	DEKVersion int    // populated on storage path; zero on worker-facing decrypt path
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
