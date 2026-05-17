// Package postgres implements vault.CredentialStore and
// vault.TenantStore against a Postgres database. The reference
// deployment is Supabase Pro through its transaction-mode pooler
// (port 6543) — that pooler's behavior is the reason this package
// pins pgx into QueryExecModeExec (see Open).
package postgres

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
)

// Open builds a *sql.DB backed by pgx/v5, configured for Supabase's
// transaction-mode pooler.
//
// QueryExecModeExec is non-optional here: pgx's default
// QueryExecModeCacheStatement registers prepared-statement names
// against the client session, but Supavisor in transaction mode
// reassigns each query to a potentially different backend session,
// producing `SQLSTATE 42P05: prepared statement "stmtcache_..."
// already exists` on re-runs. See foundation runbook gotcha #8.
func Open(ctx context.Context, dsn string) (*sql.DB, error) {
	cfg, err := pgx.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("postgres: parse DSN: %w", err)
	}
	cfg.DefaultQueryExecMode = pgx.QueryExecModeExec

	db := stdlib.OpenDB(*cfg)
	if err := db.PingContext(ctx); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("postgres: ping: %w", err)
	}
	return db, nil
}
