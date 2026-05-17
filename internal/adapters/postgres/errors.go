package postgres

import (
	"database/sql"
	"errors"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/tumultousRamen/coffer/internal/vault"
)

// Postgres SQLSTATE codes we map to vault sentinels.
const (
	sqlstateUniqueViolation     = "23505"
	sqlstateForeignKeyViolation = "23503"
)

// mapInsertErr translates a Postgres error from an INSERT (or upsert)
// into the appropriate vault sentinel. Returns the original error if
// nothing matches.
func mapInsertErr(err error) error {
	if err == nil {
		return nil
	}
	var pg *pgconn.PgError
	if errors.As(err, &pg) {
		switch pg.Code {
		case sqlstateUniqueViolation:
			return vault.ErrAlreadyExists
		case sqlstateForeignKeyViolation:
			return vault.ErrTenantNotProvisioned
		}
	}
	if errors.Is(err, sql.ErrNoRows) {
		return vault.ErrNotFound
	}
	return err
}
