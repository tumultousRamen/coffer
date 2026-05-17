// Package vault — Service is the REST-side orchestration layer. It
// composes a CredentialStore, a TenantStore, and a *Cryptor into the
// five lifecycle operations that the user-facing REST gateway will
// wrap (ADR 0007 §2): create, list, get-summary, replace, delete.
//
// The worker-facing FetchForWorker method (gRPC + capability tokens,
// ADR 0007 §1) ships in a follow-on PRD; it will live on this same
// struct.
package vault

import (
	"bytes"
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
)

// Service holds the wiring needed to drive credential lifecycle. The
// zero value is not usable; construct with NewService.
type Service struct {
	store   CredentialStore
	tenants TenantStore
	cryptor *Cryptor
}

// NewService composes the three collaborators into a Service. All
// three are required; nil checks are not performed (a misconfigured
// service is a startup-time programmer error, not a runtime failure
// mode).
func NewService(store CredentialStore, tenants TenantStore, cryptor *Cryptor) *Service {
	return &Service{store: store, tenants: tenants, cryptor: cryptor}
}

// CreateCredential orchestrates the full create flow: provision the
// tenant DEK on first use (with race protection), encrypt the secret
// under the canonical DEK, persist the row, return the new ID.
//
// UUIDv7 (time-ordered) is generated here per ADR 0005 — a single
// grep finds every credential-ID birth site.
//
// First-credential race protection: if two goroutines both see
// "tenant not provisioned" and both call Cryptor.Provision, they
// produce different plaintext DEKs. The TenantStore's load-or-store
// PutEncryptedDEK guarantees only one ciphertext DEK survives in the
// row; whichever caller's argument matches the returned canonicalDEK
// is the winner. The loser discards its local DEK and falls through
// to Encrypt under the canonical one — Cryptor.unwrap performs the
// extra KMS Decrypt to make the loser's DEK cache consistent with
// reality. Cost: at most one extra KMS Decrypt per losing goroutine
// per tenant lifetime.
func (s *Service) CreateCredential(
	ctx context.Context,
	userID, provider, label string,
	plaintextSecret []byte,
	metadata Metadata,
) (string, error) {
	id := uuid.Must(uuid.NewV7()).String()

	ciphertextDEK, version, err := s.resolveTenantDEK(ctx, userID)
	if err != nil {
		return "", err
	}

	ciphertext, nonce, err := s.cryptor.Encrypt(ctx, userID, id, provider, plaintextSecret, ciphertextDEK)
	if err != nil {
		return "", err
	}

	cred := Credential{
		ID:         id,
		Provider:   provider,
		Label:      label,
		Secret:     NewSecretBlob(ciphertext),
		Metadata:   metadata,
		Nonce:      nonce,
		DEKVersion: version,
	}
	if err := s.store.Create(ctx, userID, cred); err != nil {
		return "", err
	}
	return id, nil
}

// ListCredentials is a thin wrapper over the storage layer. Returns
// CredentialSummary values only — never plaintext, never ciphertext.
// ADR 0007 §3 read-back guard holds at the type level.
func (s *Service) ListCredentials(ctx context.Context, userID string) ([]CredentialSummary, error) {
	return s.store.List(ctx, userID)
}

// GetCredentialSummary returns the user-facing projection of a single
// credential. ErrNotFound if the credential is missing or owned by a
// different user (storage scopes by user_id; cross-tenant queries
// silently return empty, which we surface as ErrNotFound here so the
// REST 404 mapping is unambiguous).
//
// No decryption happens on this path — REST GET endpoints never
// surface secret bytes.
func (s *Service) GetCredentialSummary(ctx context.Context, userID, id string) (CredentialSummary, error) {
	summaries, err := s.store.List(ctx, userID)
	if err != nil {
		return CredentialSummary{}, err
	}
	for _, sum := range summaries {
		if sum.ID == id {
			return sum, nil
		}
	}
	return CredentialSummary{}, ErrNotFound
}

// ReplaceCredential re-encrypts the secret payload for an existing
// credential under the tenant's current DEK and persists the new
// ciphertext + nonce atomically.
//
// The AAD binding for AES-GCM is (userID || credentialID || provider)
// per ADR 0003. ReplaceCredential takes the new plaintext + metadata
// but NOT a new provider/label — those are read from the existing
// row. If the caller could change provider, the AAD would change and
// every subsequent Decrypt would fail with an auth tag mismatch.
// ADR 0007 §5 also specifies PUT replaces only the secret payload.
//
// DEKVersion is read live from the tenants row. Rotation is the only
// event that changes which DEK encrypts a tenant's credentials;
// Replace inherits whatever DEK is current at the moment of call.
// (If rotation interleaves with Replace, the Replace lands at the
// rotation's current dek_version — correct behavior, since the new
// ciphertext is sealed under the rotated DEK.)
func (s *Service) ReplaceCredential(
	ctx context.Context,
	userID, id string,
	plaintextSecret []byte,
	metadata Metadata,
) error {
	existing, err := s.store.Get(ctx, userID, []string{id})
	if err != nil {
		return err
	}
	if len(existing) == 0 {
		return ErrNotFound
	}

	ciphertextDEK, version, err := s.tenants.GetEncryptedDEK(ctx, userID)
	if err != nil {
		// A credential exists for this user but no tenant row does — an
		// inconsistent state that the DB FK should prevent. Surface as-is
		// rather than silently re-provisioning; that would lose the
		// historical DEK that sealed all the user's existing credentials.
		return fmt.Errorf("vault: replace: tenant lookup: %w", err)
	}

	ciphertext, nonce, err := s.cryptor.Encrypt(
		ctx, userID, id, existing[0].Provider, plaintextSecret, ciphertextDEK,
	)
	if err != nil {
		return err
	}
	cred := Credential{
		ID:         id,
		Provider:   existing[0].Provider,
		Label:      existing[0].Label,
		Secret:     NewSecretBlob(ciphertext),
		Metadata:   metadata,
		Nonce:      nonce,
		DEKVersion: version,
	}
	return s.store.Replace(ctx, userID, cred)
}

// DeleteCredential is a thin wrapper over the storage layer. Hard
// delete per ADR 0005. The tenants row's DEK is not touched —
// per-tenant DEK retirement is a rotation concern, not a per-credential
// one.
func (s *Service) DeleteCredential(ctx context.Context, userID, id string) error {
	return s.store.Delete(ctx, userID, id)
}

// resolveTenantDEK returns the (ciphertextDEK, version) under which a
// new credential for userID should be encrypted. On a first-credential
// path it provisions a new DEK and stores it via load-or-store; the
// returned canonical DEK is whichever bytes actually landed in the
// tenants row, which may not be the one we just provisioned if a
// concurrent goroutine won the race.
func (s *Service) resolveTenantDEK(ctx context.Context, userID string) ([]byte, int, error) {
	ciphertextDEK, version, err := s.tenants.GetEncryptedDEK(ctx, userID)
	if err == nil {
		return ciphertextDEK, version, nil
	}
	if !errors.Is(err, ErrNotFound) {
		return nil, 0, fmt.Errorf("vault: tenant lookup: %w", err)
	}

	// First-credential path: mint a new DEK and try to claim the
	// tenants row. PutEncryptedDEK's load-or-store contract returns the
	// canonical DEK whether we won or lost.
	provisioned, err := s.cryptor.Provision(ctx, userID)
	if err != nil {
		return nil, 0, fmt.Errorf("vault: provision: %w", err)
	}
	canonical, version, err := s.tenants.PutEncryptedDEK(ctx, userID, provisioned)
	if err != nil {
		return nil, 0, fmt.Errorf("vault: put tenant: %w", err)
	}
	// If our provisioned bytes are what landed, we're done — the
	// Cryptor already cached the plaintext DEK in Provision. If a
	// concurrent goroutine won, the loser's locally-cached plaintext
	// DEK is for an orphaned wrapped DEK that nothing in storage
	// references; Cryptor.Encrypt below will call unwrap(canonical),
	// which misses the cache (different ciphertextDEK key) and
	// triggers one KMS Decrypt to populate it. Correct, just slower
	// by one round-trip on the loser path.
	_ = canonical
	if !bytes.Equal(canonical, provisioned) {
		// Loser path: log nothing here (no Telemetry yet); the unwrap
		// on Encrypt handles correctness. Future Telemetry PRD will
		// emit a counter at this branch.
	}
	return canonical, version, nil
}
