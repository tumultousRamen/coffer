package memstore

import (
	"bytes"
	"context"
	"sync"

	"github.com/tumultousRamen/coffer/internal/vault"
)

// TenantStore is an in-memory vault.TenantStore. The zero value is not
// usable; construct with NewTenantStore.
type TenantStore struct {
	mu   sync.Mutex
	data map[string]tenantRow
}

type tenantRow struct {
	dek     []byte
	version int
}

func NewTenantStore() *TenantStore {
	return &TenantStore{data: make(map[string]tenantRow)}
}

// GetEncryptedDEK returns a defensive copy of the stored ciphertext
// DEK and the current dek_version. Returns vault.ErrNotFound if the
// tenant has never been provisioned.
func (t *TenantStore) GetEncryptedDEK(_ context.Context, userID string) ([]byte, int, error) {
	t.mu.Lock()
	defer t.mu.Unlock()

	row, ok := t.data[userID]
	if !ok {
		return nil, 0, vault.ErrNotFound
	}
	return copyBytes(row.dek), row.version, nil
}

// PutEncryptedDEK is load-or-store: if no row exists for userID, stores
// a defensive copy of ciphertextDEK at version 1 and returns it. If a
// row already exists, returns the existing (canonicalDEK, version) and
// discards the caller's argument. See vault.TenantStore for why this
// shape matters for the concurrent first-Create flow.
func (t *TenantStore) PutEncryptedDEK(_ context.Context, userID string, ciphertextDEK []byte) ([]byte, int, error) {
	t.mu.Lock()
	defer t.mu.Unlock()

	if row, ok := t.data[userID]; ok {
		return copyBytes(row.dek), row.version, nil
	}
	stored := copyBytes(ciphertextDEK)
	t.data[userID] = tenantRow{dek: stored, version: 1}
	return copyBytes(stored), 1, nil
}

func copyBytes(b []byte) []byte {
	out := make([]byte, len(b))
	copy(out, b)
	return out
}

// equalDEK is exposed only for tests that need to assert a particular
// userID's stored DEK matches a candidate. Kept in this file so it's
// trivially greppable.
func (t *TenantStore) equalDEK(userID string, candidate []byte) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	row, ok := t.data[userID]
	if !ok {
		return false
	}
	return bytes.Equal(row.dek, candidate)
}
