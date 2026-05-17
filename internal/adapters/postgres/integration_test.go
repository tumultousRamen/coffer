//go:build integration

package postgres_test

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"reflect"
	"sync"
	"testing"

	"github.com/google/uuid"
	"github.com/tumultousRamen/coffer/internal/adapters/postgres"
	"github.com/tumultousRamen/coffer/internal/vault"
	"github.com/tumultousRamen/coffer/internal/vault/portcontract"
)

// openTestDB opens the Supabase Pro database under DATABASE_URL,
// failing the test loudly when the env var is unset so a missing
// configuration cannot be confused with a passing test.
func openTestDB(t *testing.T) *sql.DB {
	t.Helper()
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		t.Fatal("DATABASE_URL not set (source .env.local first or run via `make integration`)")
	}
	db, err := postgres.Open(context.Background(), dsn)
	if err != nil {
		t.Fatalf("postgres.Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

// resetTables wipes both PRD 0004 tables. Tests that need a clean
// slate call this at start; we do not register it as a global
// cleanup because integration_test.go is single-threaded.
func resetTables(t *testing.T, db *sql.DB) {
	t.Helper()
	if _, err := db.ExecContext(context.Background(), `TRUNCATE credentials, tenants CASCADE`); err != nil {
		t.Fatalf("TRUNCATE: %v", err)
	}
}

func TestMain(m *testing.M) {
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		fmt.Fprintln(os.Stderr, "integration: DATABASE_URL not set; skipping")
		os.Exit(0)
	}
	ctx := context.Background()
	db, err := postgres.Open(ctx, dsn)
	if err != nil {
		fmt.Fprintf(os.Stderr, "integration: open: %v\n", err)
		os.Exit(1)
	}
	if err := postgres.Up(ctx, db); err != nil {
		fmt.Fprintf(os.Stderr, "integration: migrate up: %v\n", err)
		_ = db.Close()
		os.Exit(1)
	}
	_ = db.Close()
	os.Exit(m.Run())
}

func bundle(t *testing.T) portcontract.StoreBundle {
	t.Helper()
	db := openTestDB(t)
	resetTables(t, db)
	return portcontract.StoreBundle{
		Credentials: postgres.NewCredentialStore(db),
		Tenants:     postgres.NewTenantStore(db),
	}
}

func TestPostgres_CredentialStoreContract(t *testing.T) {
	portcontract.RunCredentialStoreContract(t, bundle)
}

func TestPostgres_TenantStoreContract(t *testing.T) {
	portcontract.RunTenantStoreContract(t, bundle)
}

// TestPostgres_MigrationRoundTrip drives Up -> Down -> Up to confirm
// the down migration is structurally correct and the schema can be
// rebuilt from scratch. Runs against the live DB; leaves the tables
// in place for the rest of the suite.
func TestPostgres_MigrationRoundTrip(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t)

	if err := postgres.Down(ctx, db); err != nil {
		t.Fatalf("Down: %v", err)
	}
	// Tables should be gone — querying tenants must error with an
	// undefined-table SQLSTATE.
	if _, err := db.ExecContext(ctx, `SELECT 1 FROM tenants LIMIT 1`); err == nil {
		t.Fatal("tenants table still queryable after Down")
	}
	if err := postgres.Up(ctx, db); err != nil {
		t.Fatalf("Up after Down: %v", err)
	}
	if _, err := db.ExecContext(ctx, `SELECT 1 FROM tenants LIMIT 1`); err != nil {
		t.Fatalf("tenants table missing after Up: %v", err)
	}
}

// TestPostgres_QueryExecModeExecRegression guards against forgetting
// foundation runbook gotcha #8. Without DefaultQueryExecMode=Exec,
// the second SELECT through Supavisor's transaction-mode pooler
// returns SQLSTATE 42P05.
func TestPostgres_QueryExecModeExecRegression(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t)
	resetTables(t, db)

	// Run the same parameterized statement many times. Pre-fix, the
	// second run after a pooled-connection rotation would fail.
	for i := 0; i < 16; i++ {
		var n int
		if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM tenants WHERE user_id = $1`, uuid.NewString()).Scan(&n); err != nil {
			t.Fatalf("iter %d: %v", i, err)
		}
	}
}

// TestPostgres_BYTEAByteEqualRoundTrip stores a sizable random
// ciphertext and verifies the bytes survive the BYTEA encoder/decoder
// without re-shaping.
func TestPostgres_BYTEAByteEqualRoundTrip(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t)
	resetTables(t, db)
	ts := postgres.NewTenantStore(db)

	userID := uuid.NewString()
	want := make([]byte, 4096)
	for i := range want {
		want[i] = byte(i * 31)
	}
	if err := ts.PutEncryptedDEK(ctx, userID, want); err != nil {
		t.Fatalf("Put: %v", err)
	}
	got, err := ts.GetEncryptedDEK(ctx, userID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("byte mismatch: got %d bytes, want %d; first diff at %d",
			len(got), len(want), firstDiffIndex(got, want))
	}
}

// TestPostgres_JSONBRoundTripUnmarshalEqual stores a non-trivial
// Metadata value, retrieves it, and asserts that the unmarshalled
// value matches the original. Byte-stability is not asserted — Go's
// encoding/json does not sort keys.
func TestPostgres_JSONBRoundTripUnmarshalEqual(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t)
	resetTables(t, db)

	ts := postgres.NewTenantStore(db)
	cs := postgres.NewCredentialStore(db)

	userID := uuid.NewString()
	if err := ts.PutEncryptedDEK(ctx, userID, []byte("dek")); err != nil {
		t.Fatalf("Put tenant: %v", err)
	}

	credID := uuid.NewString()
	original := vault.Metadata{
		"region":  "us-west-1",
		"scopes":  []any{"read", "write"},
		"nested":  map[string]any{"k": "v", "deep": map[string]any{"x": float64(7)}},
		"absence": nil,
	}
	c := vault.Credential{
		ID:       credID,
		Provider: "s3",
		Label:    "prod",
		Secret:   vault.NewSecretBlob([]byte("ciphertext")),
		Metadata: original,
	}
	if err := cs.Create(ctx, userID, c); err != nil {
		t.Fatalf("Create: %v", err)
	}
	got, err := cs.Get(ctx, userID, []string{credID})
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	// json.Unmarshal into `any` produces float64 / map[string]any /
	// []any consistently with our setup — direct DeepEqual works.
	wantRoundTripped := vault.Metadata{}
	b, _ := json.Marshal(original)
	_ = json.Unmarshal(b, &wantRoundTripped)
	if !reflect.DeepEqual(got[0].Metadata, wantRoundTripped) {
		t.Errorf("metadata round-trip mismatch\n got: %#v\nwant: %#v", got[0].Metadata, wantRoundTripped)
	}
}

// TestPostgres_FKViolationMapping confirms attempting Create against
// a non-provisioned tenant surfaces ErrTenantNotProvisioned. The
// contract suite asserts this behaviorally; this test pins it to the
// real Postgres FK error path.
func TestPostgres_FKViolationMapping(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t)
	resetTables(t, db)

	cs := postgres.NewCredentialStore(db)
	err := cs.Create(ctx, uuid.NewString(), vault.Credential{
		ID:       uuid.NewString(),
		Provider: "s3",
		Label:    "p",
		Secret:   vault.NewSecretBlob([]byte("x")),
		Metadata: vault.Metadata{},
	})
	if !errors.Is(err, vault.ErrTenantNotProvisioned) {
		t.Errorf("FK violation err = %v, want ErrTenantNotProvisioned", err)
	}
}

// TestPostgres_UniqueViolationMapping confirms the unique index on
// (user_id, provider, label) maps cleanly to ErrAlreadyExists.
func TestPostgres_UniqueViolationMapping(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t)
	resetTables(t, db)
	ts := postgres.NewTenantStore(db)
	cs := postgres.NewCredentialStore(db)

	userID := uuid.NewString()
	if err := ts.PutEncryptedDEK(ctx, userID, []byte("dek")); err != nil {
		t.Fatalf("Put tenant: %v", err)
	}
	first := vault.Credential{
		ID:       uuid.NewString(),
		Provider: "s3",
		Label:    "prod",
		Secret:   vault.NewSecretBlob([]byte("x")),
		Metadata: vault.Metadata{},
	}
	if err := cs.Create(ctx, userID, first); err != nil {
		t.Fatalf("first Create: %v", err)
	}
	second := first
	second.ID = uuid.NewString()
	err := cs.Create(ctx, userID, second)
	if !errors.Is(err, vault.ErrAlreadyExists) {
		t.Errorf("unique violation err = %v, want ErrAlreadyExists", err)
	}
}

// TestPostgres_ConcurrentCreateRace runs many goroutines racing to
// claim the same (user_id, provider, label) tuple. The DB constraint
// must guarantee exactly one winner.
func TestPostgres_ConcurrentCreateRace(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t)
	resetTables(t, db)
	ts := postgres.NewTenantStore(db)
	cs := postgres.NewCredentialStore(db)

	userID := uuid.NewString()
	if err := ts.PutEncryptedDEK(ctx, userID, []byte("dek")); err != nil {
		t.Fatalf("Put tenant: %v", err)
	}

	const goroutines = 16
	var wg sync.WaitGroup
	results := make(chan error, goroutines)
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			results <- cs.Create(ctx, userID, vault.Credential{
				ID:       uuid.NewString(),
				Provider: "s3",
				Label:    "contended",
				Secret:   vault.NewSecretBlob([]byte("x")),
				Metadata: vault.Metadata{},
			})
		}()
	}
	wg.Wait()
	close(results)

	successes, duplicates, other := 0, 0, 0
	for err := range results {
		switch {
		case err == nil:
			successes++
		case errors.Is(err, vault.ErrAlreadyExists):
			duplicates++
		default:
			other++
			t.Errorf("unexpected error: %v", err)
		}
	}
	if successes != 1 {
		t.Errorf("successes = %d, want 1", successes)
	}
	if duplicates != goroutines-1 {
		t.Errorf("duplicates = %d, want %d", duplicates, goroutines-1)
	}
	if other != 0 {
		t.Errorf("unexpected errors = %d", other)
	}
}

func firstDiffIndex(a, b []byte) int {
	n := len(a)
	if len(b) < n {
		n = len(b)
	}
	for i := 0; i < n; i++ {
		if a[i] != b[i] {
			return i
		}
	}
	return n
}
