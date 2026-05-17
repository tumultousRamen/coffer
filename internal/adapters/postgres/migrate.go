package postgres

import (
	"context"
	"database/sql"
	"embed"
	"errors"
	"fmt"

	"github.com/golang-migrate/migrate/v4"
	pgxdriver "github.com/golang-migrate/migrate/v4/database/pgx/v5"
	"github.com/golang-migrate/migrate/v4/source/iofs"
)

//go:embed migrations/*.sql
var migrationsFS embed.FS

// Up applies every pending migration in lexical order. ADR 0010 §3
// makes this callable from the service binary on boot; the
// cmd/migrate CLI is a thin wrapper around the same function.
//
// The *sql.DB is borrowed, not owned: we deliberately do NOT call
// migrate.Migrate.Close() because that closes the underlying *sql.DB
// via the pgx driver's Close hook, which would surprise callers that
// expect to keep using the connection after migrations run.
func Up(_ context.Context, db *sql.DB) error {
	m, err := newMigrator(db)
	if err != nil {
		return err
	}
	if err := m.Up(); err != nil && !errors.Is(err, migrate.ErrNoChange) {
		return fmt.Errorf("postgres: migrate up: %w", err)
	}
	return nil
}

// Down rolls back the most recently applied migration. Same borrow
// semantics as Up — the *sql.DB stays open.
func Down(_ context.Context, db *sql.DB) error {
	m, err := newMigrator(db)
	if err != nil {
		return err
	}
	if err := m.Steps(-1); err != nil && !errors.Is(err, migrate.ErrNoChange) {
		return fmt.Errorf("postgres: migrate down: %w", err)
	}
	return nil
}

func newMigrator(db *sql.DB) (*migrate.Migrate, error) {
	src, err := iofs.New(migrationsFS, "migrations")
	if err != nil {
		return nil, fmt.Errorf("postgres: open embedded migrations: %w", err)
	}
	drv, err := pgxdriver.WithInstance(db, &pgxdriver.Config{})
	if err != nil {
		return nil, fmt.Errorf("postgres: build migrate driver: %w", err)
	}
	m, err := migrate.NewWithInstance("iofs", src, "pgx5", drv)
	if err != nil {
		return nil, fmt.Errorf("postgres: build migrator: %w", err)
	}
	return m, nil
}
