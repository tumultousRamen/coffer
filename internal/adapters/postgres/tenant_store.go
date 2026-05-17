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

// GetEncryptedDEK fetches the wrapped DEK and dek_version for userID.
// Returns vault.ErrNotFound if no row exists.
func (s *TenantStore) GetEncryptedDEK(ctx context.Context, userID string) ([]byte, int, error) {
	var (
		dek     []byte
		version int
	)
	err := s.db.QueryRowContext(ctx,
		`SELECT encrypted_dek, dek_version FROM tenants WHERE user_id = $1`,
		userID,
	).Scan(&dek, &version)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, 0, vault.ErrNotFound
	}
	if err != nil {
		return nil, 0, fmt.Errorf("postgres: select tenant: %w", err)
	}
	return dek, version, nil
}

// PutEncryptedDEK is load-or-store. INSERT ... ON CONFLICT DO NOTHING
// gives us "first writer wins" atomicity at the database. On the
// winning insert RETURNING surfaces the row we just wrote; on the
// no-op path a follow-up SELECT fetches the canonical row that's
// already there. Either way the caller learns whichever DEK actually
// landed in the tenants row.
//
// Both branches return defensive copies; pgx allocates fresh slices on
// every Scan, so the bytes we return are independent of any internal
// driver state.
func (s *TenantStore) PutEncryptedDEK(ctx context.Context, userID string, ciphertextDEK []byte) ([]byte, int, error) {
	var (
		canonical []byte
		version   int
	)
	err := s.db.QueryRowContext(ctx, `
		INSERT INTO tenants (user_id, encrypted_dek, dek_version)
		VALUES ($1, $2, 1)
		ON CONFLICT (user_id) DO NOTHING
		RETURNING encrypted_dek, dek_version
	`, userID, ciphertextDEK).Scan(&canonical, &version)

	if err == nil {
		return canonical, version, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return nil, 0, fmt.Errorf("postgres: upsert tenant: %w", mapInsertErr(err))
	}

	// No row from the INSERT path → conflict was a no-op. Read the
	// canonical row that's already there.
	err = s.db.QueryRowContext(ctx,
		`SELECT encrypted_dek, dek_version FROM tenants WHERE user_id = $1`,
		userID,
	).Scan(&canonical, &version)
	if err != nil {
		// A row that conflicted moments ago should still be there. If
		// it isn't, surface the raw error rather than ErrNotFound — the
		// caller's load-or-store contract has been violated by an
		// out-of-band actor.
		return nil, 0, fmt.Errorf("postgres: select after upsert conflict: %w", err)
	}
	return canonical, version, nil
}
