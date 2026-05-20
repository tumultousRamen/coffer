package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/tumultousRamen/coffer/internal/vault"
)

// CredentialStore implements vault.CredentialStore against the
// `credentials` table from ADR 0005. Nonce and DEKVersion on the
// vault.Credential round-trip through the storage path: the service
// layer stamps them at write time, the adapter persists them, and
// Get reads them back so the service can drive Cryptor.Decrypt with
// the same nonce / under the same DEK epoch that sealed the row.
type CredentialStore struct {
	db *sql.DB
}

func NewCredentialStore(db *sql.DB) *CredentialStore {
	return &CredentialStore{db: db}
}

// Get returns whichever of the requested credential IDs exist for
// userID. Missing IDs are silently dropped — the service-layer caller
// decides whether a partial result is acceptable. Order of the
// returned slice is unspecified (callers must not rely on it).
func (s *CredentialStore) Get(ctx context.Context, userID string, ids []string) ([]vault.Credential, error) {
	if len(ids) == 0 {
		return nil, nil
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, provider, label, secret_ciphertext, nonce, dek_version, metadata
		FROM credentials
		WHERE user_id = $1 AND id = ANY($2::uuid[])
	`, userID, ids)
	if err != nil {
		return nil, fmt.Errorf("postgres: select credentials: %w", err)
	}
	defer rows.Close()

	out := make([]vault.Credential, 0, len(ids))
	for rows.Next() {
		var (
			id, provider, label string
			secret, nonce       []byte
			dekVersion          int
			metadataJSON        []byte
		)
		if err := rows.Scan(&id, &provider, &label, &secret, &nonce, &dekVersion, &metadataJSON); err != nil {
			return nil, fmt.Errorf("postgres: scan credential: %w", err)
		}
		md := vault.Metadata{}
		if len(metadataJSON) > 0 {
			if err := json.Unmarshal(metadataJSON, &md); err != nil {
				return nil, fmt.Errorf("postgres: unmarshal metadata for %s: %w", id, err)
			}
		}
		out = append(out, vault.Credential{
			ID:         id,
			Provider:   provider,
			Label:      label,
			Secret:     vault.NewSecretBlob(secret),
			Metadata:   md,
			Nonce:      nonce,
			DEKVersion: dekVersion,
		})
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("postgres: iterate credentials: %w", err)
	}
	return out, nil
}

// List returns CredentialSummary rows for userID, ordered by id.
func (s *CredentialStore) List(ctx context.Context, userID string) ([]vault.CredentialSummary, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, provider, label, status, validation_error, created_at
		FROM credentials
		WHERE user_id = $1
		ORDER BY id
	`, userID)
	if err != nil {
		return nil, fmt.Errorf("postgres: list credentials: %w", err)
	}
	defer rows.Close()

	out := []vault.CredentialSummary{}
	for rows.Next() {
		var sum vault.CredentialSummary
		var status string
		if err := rows.Scan(&sum.ID, &sum.Provider, &sum.Label, &status, &sum.ValidationError, &sum.CreatedAt); err != nil {
			return nil, fmt.Errorf("postgres: scan summary: %w", err)
		}
		sum.Status = vault.Status(status)
		out = append(out, sum)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("postgres: iterate summaries: %w", err)
	}
	return out, nil
}

// Create inserts c. Maps Postgres unique-violation (PK collision on
// id, or the unique index on (user_id, provider, label)) to
// ErrAlreadyExists; FK violation on user_id to ErrTenantNotProvisioned.
func (s *CredentialStore) Create(ctx context.Context, userID string, c vault.Credential) error {
	metadataJSON, err := json.Marshal(c.Metadata)
	if err != nil {
		return fmt.Errorf("postgres: marshal metadata: %w", err)
	}
	// metadata is passed as text so pgx's simple-protocol encoder
	// emits a string literal that Postgres implicitly casts to jsonb.
	// Passing []byte would be hex-encoded as a bytea literal, which
	// is not valid JSON (SQLSTATE 22P02).
	_, err = s.db.ExecContext(ctx, `
		INSERT INTO credentials
			(id, user_id, provider, label, secret_ciphertext, nonce, dek_version, metadata, status)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8::jsonb, $9)
	`,
		c.ID, userID, c.Provider, c.Label,
		c.Secret.Reveal(), c.Nonce, c.DEKVersion,
		string(metadataJSON), string(vault.StatusActive),
	)
	if err != nil {
		mapped := mapInsertErr(err)
		if errors.Is(mapped, vault.ErrAlreadyExists) || errors.Is(mapped, vault.ErrTenantNotProvisioned) {
			return mapped
		}
		return fmt.Errorf("postgres: insert credential: %w", err)
	}
	return nil
}

// Replace atomically updates the secret payload + metadata for the
// row identified by (id, user_id). Zero rows updated → ErrNotFound.
func (s *CredentialStore) Replace(ctx context.Context, userID string, c vault.Credential) error {
	metadataJSON, err := json.Marshal(c.Metadata)
	if err != nil {
		return fmt.Errorf("postgres: marshal metadata: %w", err)
	}
	res, err := s.db.ExecContext(ctx, `
		UPDATE credentials
		SET secret_ciphertext = $1,
		    nonce             = $2,
		    dek_version       = $3,
		    metadata          = $4::jsonb,
		    updated_at        = now()
		WHERE id = $5 AND user_id = $6
	`,
		c.Secret.Reveal(), c.Nonce, c.DEKVersion, string(metadataJSON),
		c.ID, userID,
	)
	if err != nil {
		return fmt.Errorf("postgres: update credential: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("postgres: rows affected: %w", err)
	}
	if n == 0 {
		return vault.ErrNotFound
	}
	return nil
}

// MarkFailed transitions the row's status to 'failed' and stamps a
// short reason in validation_error. Zero rows updated → ErrNotFound.
// Used by the sync-on-stale OAuth refresh path (PRD 0010).
func (s *CredentialStore) MarkFailed(ctx context.Context, userID, id, reason string) error {
	res, err := s.db.ExecContext(ctx, `
		UPDATE credentials
		SET status           = $1,
		    validation_error = $2,
		    updated_at       = now()
		WHERE id = $3 AND user_id = $4
	`, string(vault.StatusFailed), reason, id, userID)
	if err != nil {
		return fmt.Errorf("postgres: mark failed: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("postgres: rows affected: %w", err)
	}
	if n == 0 {
		return vault.ErrNotFound
	}
	return nil
}

// Delete hard-deletes the row identified by (id, user_id) per ADR
// 0005. Zero rows deleted → ErrNotFound (do not leak existence of
// rows owned by other users).
func (s *CredentialStore) Delete(ctx context.Context, userID, id string) error {
	res, err := s.db.ExecContext(ctx,
		`DELETE FROM credentials WHERE id = $1 AND user_id = $2`,
		id, userID,
	)
	if err != nil {
		return fmt.Errorf("postgres: delete credential: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("postgres: rows affected: %w", err)
	}
	if n == 0 {
		return vault.ErrNotFound
	}
	return nil
}

// Static interface checks: drift in either port shape breaks the build.
var (
	_ vault.CredentialStore = (*CredentialStore)(nil)
	_ vault.TenantStore     = (*TenantStore)(nil)
)
