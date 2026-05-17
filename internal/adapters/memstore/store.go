// Package memstore is an in-process implementation of
// vault.CredentialStore and vault.TenantStore backed by sync.RWMutex-
// guarded maps. It is the reference adapter — every later
// implementation (the Postgres adapter from PRD 0004 onward) must
// produce behavior identical to this one against the shared contract
// tests in internal/vault/portcontract.
package memstore

import (
	"context"
	"sort"
	"sync"
	"time"

	"github.com/tumultousRamen/coffer/internal/vault"
)

type record struct {
	cred      vault.Credential
	status    vault.Status
	createdAt time.Time
}

// Store is an in-memory CredentialStore. The zero value is not usable;
// construct with New or NewWithTenants.
type Store struct {
	mu      sync.RWMutex
	now     func() time.Time
	tenants *TenantStore
	data    map[string]map[string]record
}

// New returns an empty Store without tenant-FK enforcement. Suitable
// for tests that exercise the CredentialStore in isolation.
func New() *Store {
	return &Store{
		now:  time.Now,
		data: make(map[string]map[string]record),
	}
}

// NewWithTenants returns a Store that enforces tenant existence on
// Create — matching the Postgres adapter's FK behavior. Pass the same
// *TenantStore that the surrounding system uses to provision tenants.
func NewWithTenants(ts *TenantStore) *Store {
	s := New()
	s.tenants = ts
	return s
}

// Get returns the credentials whose IDs are listed in ids, scoped to
// userID. Missing IDs are silently dropped — the caller (service
// layer) decides whether a partial result is acceptable. Matches the
// `SELECT ... WHERE id = ANY($2)` semantics of the Postgres adapter.
func (s *Store) Get(_ context.Context, userID string, ids []string) ([]vault.Credential, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	bucket := s.data[userID]
	out := make([]vault.Credential, 0, len(ids))
	for _, id := range ids {
		if rec, ok := bucket[id]; ok {
			out = append(out, rec.cred)
		}
	}
	return out, nil
}

// List returns CredentialSummary records for every credential owned by
// userID. Results are sorted by ID for deterministic test output. An
// unknown userID returns an empty slice (not an error).
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

// Create inserts c under userID. When the Store was built with
// NewWithTenants and the tenant has no DEK, returns
// ErrTenantNotProvisioned (matches the FK constraint in the Postgres
// adapter). Returns ErrAlreadyExists on duplicate (userID, provider,
// label) — same unique constraint as the Postgres adapter — and on
// duplicate ID.
func (s *Store) Create(ctx context.Context, userID string, c vault.Credential) error {
	if s.tenants != nil {
		if _, err := s.tenants.GetEncryptedDEK(ctx, userID); err != nil {
			if err == vault.ErrNotFound {
				return vault.ErrTenantNotProvisioned
			}
			return err
		}
	}

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
	for _, rec := range bucket {
		if rec.cred.Provider == c.Provider && rec.cred.Label == c.Label {
			return vault.ErrAlreadyExists
		}
	}
	bucket[c.ID] = record{
		cred:      c,
		status:    vault.StatusActive,
		createdAt: s.now(),
	}
	return nil
}

// Replace overwrites the credential at c.ID for userID. Returns
// ErrNotFound if the target does not exist; createdAt and status are
// preserved across replacements (row-level semantics of ADR 0005).
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
