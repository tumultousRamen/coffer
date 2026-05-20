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
//
// ValidationError carries the operator-side reason a credential was
// marked failed (PRD 0010 sync-on-stale path). Empty for active
// credentials.
type CredentialSummary struct {
	ID              string
	Provider        string
	Label           string
	Status          Status
	ValidationError string
	CreatedAt       time.Time
}

// MetadataKeyAccessTokenExpiresAt is the reserved metadata key that
// OAuth providers (Dropbox, Google Drive, Box) populate with the
// absolute expiry time of the cached access_token, formatted RFC3339.
// Sync-on-stale at FetchForWorker reads this key without decrypting the
// secret to decide whether a refresh is due.
const MetadataKeyAccessTokenExpiresAt = "access_token_expires_at"

// OAuthSkewMargin is the lead time before the persisted
// access_token_expires_at at which the sync-on-stale path treats a
// token as already stale and triggers a refresh. 30 seconds is chosen
// to absorb the round-trip a worker incurs handing the token to the
// vendor API after the vault returns. Per PRD 0010 §4.
const OAuthSkewMargin = 30 * time.Second
