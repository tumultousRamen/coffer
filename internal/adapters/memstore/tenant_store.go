package memstore

import (
	"context"
	"sync"

	"github.com/tumultousRamen/coffer/internal/vault"
)

// TenantStore is an in-memory vault.TenantStore. The zero value is not
// usable; construct with NewTenantStore.
type TenantStore struct {
	mu   sync.RWMutex
	data map[string][]byte
}

func NewTenantStore() *TenantStore {
	return &TenantStore{data: make(map[string][]byte)}
}

// GetEncryptedDEK returns a defensive copy of the stored ciphertext
// DEK. Returns vault.ErrNotFound if the tenant has never been
// provisioned.
func (t *TenantStore) GetEncryptedDEK(_ context.Context, userID string) ([]byte, error) {
	t.mu.RLock()
	defer t.mu.RUnlock()

	b, ok := t.data[userID]
	if !ok {
		return nil, vault.ErrNotFound
	}
	out := make([]byte, len(b))
	copy(out, b)
	return out, nil
}

// PutEncryptedDEK upserts the ciphertext DEK for userID. The input
// slice is copied so the caller may reuse or mutate it freely.
func (t *TenantStore) PutEncryptedDEK(_ context.Context, userID string, ciphertextDEK []byte) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	cp := make([]byte, len(ciphertextDEK))
	copy(cp, ciphertextDEK)
	t.data[userID] = cp
	return nil
}
