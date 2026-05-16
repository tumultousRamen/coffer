// Package memstore is an in-process implementation of
// vault.CredentialStore backed by a sync.RWMutex-guarded map. It is the
// reference adapter — every later CredentialStore implementation (the
// Postgres adapter in PRD 0003 first) must produce behavior identical
// to this one against the contract tests.
package memstore

import (
	"context"
	"sort"
	"sync"
	"time"

	"github.com/tumultousRamen/coffer/internal/vault"
)

// record bundles a stored Credential with the timestamps the
// CredentialSummary projection needs but Credential does not carry.
type record struct {
	cred      vault.Credential
	status    vault.Status
	createdAt time.Time
}

// Store is an in-memory CredentialStore. The zero value is not usable;
// construct with New.
type Store struct {
	mu  sync.RWMutex
	now func() time.Time
	// data is keyed by userID, then credentialID.
	data map[string]map[string]record
}

// New returns an empty Store using time.Now for timestamps.
func New() *Store {
	return &Store{
		now:  time.Now,
		data: make(map[string]map[string]record),
	}
}

// Get returns the credentials whose IDs are listed in ids, scoped to
// userID. Any missing ID yields ErrNotFound — partial reads would leak
// existence information across users (per ADR 0007 §1 authorization
// reasoning). Order of the returned slice matches the order of ids.
func (s *Store) Get(_ context.Context, userID string, ids []string) ([]vault.Credential, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	bucket, ok := s.data[userID]
	if !ok {
		return nil, vault.ErrNotFound
	}

	out := make([]vault.Credential, 0, len(ids))
	for _, id := range ids {
		rec, ok := bucket[id]
		if !ok {
			return nil, vault.ErrNotFound
		}
		out = append(out, rec.cred)
	}
	return out, nil
}

// List returns CredentialSummary records for every credential owned by
// userID. Results are sorted by ID for deterministic test output. An
// unknown userID returns an empty slice (not an error) — listing is a
// "show me what I have" operation and emptiness is a valid answer.
func (s *Store) List(_ context.Context, userID string) ([]vault.CredentialSummary, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	bucket := s.data[userID]
	out := make([]vault.CredentialSummary, 0, len(bucket))
	for _, rec := range bucket {
		out = append(out, vault.CredentialSummary{
			ID:        rec.cred.ID,
			Provider:  rec.cred.Provider,
			Label:     rec.cred.Label,
			Status:    rec.status,
			CreatedAt: rec.createdAt,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

// Create inserts c under userID. Returns ErrAlreadyExists if a record
// with the same ID is already present for that user.
func (s *Store) Create(_ context.Context, userID string, c vault.Credential) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	bucket, ok := s.data[userID]
	if !ok {
		bucket = make(map[string]record)
		s.data[userID] = bucket
	}
	if _, exists := bucket[c.ID]; exists {
		return vault.ErrAlreadyExists
	}
	bucket[c.ID] = record{
		cred:      c,
		status:    vault.StatusActive,
		createdAt: s.now(),
	}
	return nil
}

// Replace overwrites the credential at c.ID for userID. Returns
// ErrNotFound if the target does not exist; createdAt is preserved
// across replacements (matches the row-level semantics of ADR 0005:
// id and created_at are stable, secret_ciphertext + metadata change).
func (s *Store) Replace(_ context.Context, userID string, c vault.Credential) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	bucket, ok := s.data[userID]
	if !ok {
		return vault.ErrNotFound
	}
	existing, ok := bucket[c.ID]
	if !ok {
		return vault.ErrNotFound
	}
	bucket[c.ID] = record{
		cred:      c,
		status:    existing.status,
		createdAt: existing.createdAt,
	}
	return nil
}

// Delete is a hard delete per ADR 0005. Returns ErrNotFound if the
// target does not exist.
func (s *Store) Delete(_ context.Context, userID, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	bucket, ok := s.data[userID]
	if !ok {
		return vault.ErrNotFound
	}
	if _, ok := bucket[id]; !ok {
		return vault.ErrNotFound
	}
	delete(bucket, id)
	return nil
}
