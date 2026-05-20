package vault

import "context"

// KeyManager is the seam to a key-management service (AWS KMS in the
// reference deployment). Implementations live in internal/adapters/.
//
// GenerateDataKey returns a freshly-minted plaintext DEK and its
// ciphertext wrapper under the per-tenant KEK. Decrypt unwraps a
// previously-issued ciphertext DEK back to its plaintext form.
type KeyManager interface {
	GenerateDataKey(ctx context.Context, userID string) (plaintext, ciphertext []byte, err error)
	Decrypt(ctx context.Context, ciphertextDEK []byte) (plaintext []byte, err error)
}

// CredentialStore is the seam to the durable credential row store
// (Postgres in production; memstore in tests).
//
// Get returns credentials by ID, scoped to a single user. An ID that
// does not belong to userID — or that does not exist — yields
// ErrNotFound.
//
// Create returns ErrAlreadyExists if a credential with the same ID is
// already present. Replace returns ErrNotFound if the target ID does
// not exist; it replaces the secret payload atomically (ADR 0007 §5).
// Delete is a hard delete (ADR 0005).
//
// MarkFailed transitions an existing credential to status='failed' and
// stores a short, human-readable reason on the row. Used by the
// sync-on-stale OAuth refresh path (PRD 0010) when the provider returns
// a permanent error (e.g. invalid_grant); it lets subsequent
// FetchForWorker reads short-circuit without re-hitting the provider.
// Returns ErrNotFound if the target ID does not exist.
type CredentialStore interface {
	Get(ctx context.Context, userID string, ids []string) ([]Credential, error)
	List(ctx context.Context, userID string) ([]CredentialSummary, error)
	Create(ctx context.Context, userID string, c Credential) error
	Replace(ctx context.Context, userID string, c Credential) error
	Delete(ctx context.Context, userID, id string) error
	MarkFailed(ctx context.Context, userID, id, reason string) error
}

// TenantStore is the seam to the per-tenant DEK wrapper store
// (Postgres `tenants` table in production; memstore in tests).
//
// GetEncryptedDEK returns the tenant's wrapped DEK and its current
// dek_version. ErrNotFound is returned for a tenant that has never
// been provisioned.
//
// PutEncryptedDEK is load-or-store semantics for the provisioning
// flow: if no row exists for userID, ciphertextDEK is stored at
// version 1 and returned unchanged. If a row already exists, the
// existing (canonicalDEK, version) is returned and the caller's
// argument is discarded. This shape lets the loser of a concurrent
// first-Create race for the same tenant reuse the winner's DEK
// without an extra round-trip — credentials encrypted under the
// losing local DEK would otherwise be undecryptable, since the
// tenants row can only hold one wrapped DEK at a time.
//
// Rotation (a future PRD) gets its own explicit method; rotation
// and provisioning are semantically distinct and do not share this
// entry point.
type TenantStore interface {
	GetEncryptedDEK(ctx context.Context, userID string) (ciphertextDEK []byte, version int, err error)
	PutEncryptedDEK(ctx context.Context, userID string, ciphertextDEK []byte) (canonicalDEK []byte, version int, err error)
}

// Provider is the seam to an external storage-provider integration
// (S3, Dropbox, Google Drive, Box, …). Implementations live in
// internal/adapters/providers/.
//
// Refresh re-mints an expiring credential — for OAuth providers this
// is the refresh-token flow that yields a new access token. Validate
// performs a lightweight authentication probe at create / update time.
//
// NeedsScheduledRefresh discriminates the secret-store providers (S3,
// static keys) from the broker providers (OAuth) per ADR 0001 and
// ADR 0006. The forthcoming refresh worker enqueues a refresh_jobs row
// on credential write iff this returns true. S3 returns false; OAuth
// providers return true. Added now so OAuth-provider PRDs do not have
// to retrofit the interface across N implementations.
type Provider interface {
	NeedsScheduledRefresh() bool
	Refresh(ctx context.Context, c Credential) (Credential, error)
	Validate(ctx context.Context, secret SecretBlob, metadata Metadata) error
}
