package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/tumultousRamen/coffer/internal/vault"
)

// TenantStore implements vault.TenantStore against the `tenants` table
// from ADR 0005.
type TenantStore struct {
	db *sql.DB
}

func NewTenantStore(db *sql.DB) *TenantStore {
	return &TenantStore{db: db}
}

// GetEncryptedDEK fetches the wrapped DEK for userID. Returns
// vault.ErrNotFound if no row exists.
func (s *TenantStore) GetEncryptedDEK(ctx context.Context, userID string) ([]byte, error) {
	var dek []byte
	err := s.db.QueryRowContext(ctx,
		`SELECT encrypted_dek FROM tenants WHERE user_id = $1`,
		userID,
	).Scan(&dek)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, vault.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("postgres: select tenant: %w", err)
	}
	return dek, nil
}

// PutEncryptedDEK upserts the wrapped DEK for userID. First call
// inserts with dek_version = 1. Subsequent calls overwrite
// encrypted_dek and monotonically bump dek_version (the future
// rotation path; the port intentionally hides the counter).
func (s *TenantStore) PutEncryptedDEK(ctx context.Context, userID string, ciphertextDEK []byte) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO tenants (user_id, encrypted_dek, dek_version)
		VALUES ($1, $2, 1)
		ON CONFLICT (user_id) DO UPDATE
		SET encrypted_dek = EXCLUDED.encrypted_dek,
		    dek_version   = tenants.dek_version + 1,
		    updated_at    = now()
	`, userID, ciphertextDEK)
	if err != nil {
		return fmt.Errorf("postgres: upsert tenant: %w", mapInsertErr(err))
	}
	return nil
}
