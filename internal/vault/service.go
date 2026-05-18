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
//
// The verifier field is only consumed by FetchForWorker; REST-side
// methods (Create/List/GetSummary/Replace/Delete) do not use it and
// callers that only exercise the REST path may pass nil.
type Service struct {
	store    CredentialStore
	tenants  TenantStore
	cryptor  *Cryptor
	verifier *GrantVerifier
}

// NewService composes the four collaborators into a Service.
//
// store, tenants, and cryptor are always required. verifier is
// required only if the caller intends to invoke FetchForWorker; the
// REST-side methods do not consult it. A nil verifier passed to a
// service that later receives a FetchForWorker call surfaces as a
// runtime panic — a misconfigured service is a startup-time
// programmer error, not a request-time failure mode.
func NewService(store CredentialStore, tenants TenantStore, cryptor *Cryptor, verifier *GrantVerifier) *Service {
	return &Service{store: store, tenants: tenants, cryptor: cryptor, verifier: verifier}
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

// FetchForWorker is the worker-facing read path: verify the grant
// token, confirm every requested credential ID is in the token's
// allowed set, load the rows, decrypt each, return plaintexts with
// the storage-shape fields (Nonce, DEKVersion) zeroed.
//
// Defense in depth: the transport layer also verifies the token and
// performs per-ID scope checks. The service repeats both because
// future surfaces (REST gateway, internal admin tooling) may also
// call FetchForWorker, and the service should not assume the
// transport is the only authority on authorization. The cost is one
// signature verify + len(ids) map lookups per call.
//
// Reject-whole semantics (ADR 0007 §38):
//   - If any requested ID is not in the grant's credential_ids
//     claim, the whole request fails with ErrUnauthorized.
//   - If any requested ID does not exist in storage, the whole
//     request fails with ErrNotFound. Partial responses would leak
//     existence of credentials the caller wasn't supposed to know
//     about.
//   - If decryption of any row fails (auth-tag mismatch, KMS
//     failure), the whole request fails. A worker that receives a
//     partial result cannot start its job; failing whole is
//     strictly cleaner than returning a subset.
//
// TODO(provider PRD): sync-on-stale OAuth refresh fires here. After
// decrypt, if the plaintext is an OAuth payload and the access
// token is near expiry, call Provider.Refresh and persist the
// rotated credential before returning to the worker. ADR 0006 §4
// (updated 2026-05-16) reverses the original no-sync-fallback
// stance. Providers don't exist yet; slot is identified.
func (s *Service) FetchForWorker(
	ctx context.Context,
	grantToken string,
	ids []string,
) ([]Credential, error) {
	userID, allowedIDs, err := s.verifier.Verify(grantToken)
	if err != nil {
		return nil, err
	}

	allowed := make(map[string]struct{}, len(allowedIDs))
	for _, id := range allowedIDs {
		allowed[id] = struct{}{}
	}
	for _, id := range ids {
		if _, ok := allowed[id]; !ok {
			return nil, ErrUnauthorized
		}
	}

	ciphertextDEK, _, err := s.tenants.GetEncryptedDEK(ctx, userID)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return nil, ErrTenantNotProvisioned
		}
		return nil, fmt.Errorf("vault: fetch tenant: %w", err)
	}

	stored, err := s.store.Get(ctx, userID, ids)
	if err != nil {
		return nil, err
	}
	if len(stored) != len(ids) {
		// Reject-whole on any missing ID. ADR 0007 §38.
		return nil, ErrNotFound
	}

	out := make([]Credential, len(stored))
	for i, c := range stored {
		plaintext, err := s.cryptor.Decrypt(
			ctx, userID, c.ID, c.Provider,
			c.Secret.Reveal(), c.Nonce, ciphertextDEK,
		)
		if err != nil {
			// Fail-whole on decrypt failure. Returning the rows that
			// happened to decrypt would let an attacker who can tamper
			// with a single row probe which rows are tampered.
			return nil, fmt.Errorf("vault: fetch decrypt id=%s: %w", c.ID, err)
		}
		out[i] = Credential{
			ID:       c.ID,
			Provider: c.Provider,
			Label:    c.Label,
			Secret:   NewSecretBlob(plaintext),
			Metadata: c.Metadata,
			// Nonce + DEKVersion deliberately zero — they were storage-
			// path fields and the worker has no use for them.
		}
	}
	return out, nil
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
