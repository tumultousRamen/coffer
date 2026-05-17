package portcontract

import (
	"bytes"
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/google/uuid"
	"github.com/tumultousRamen/coffer/internal/vault"
)

// RunTenantStoreContract drives the full TenantStore behavior contract
// against the bundle returned by factory.
func RunTenantStoreContract(t *testing.T, factory Factory) {
	t.Helper()

	tests := []struct {
		name string
		fn   func(t *testing.T, b StoreBundle)
	}{
		{"GetFreshReturnsNotFound", testGetFreshReturnsNotFound},
		{"PutFirstStoresAtVersion1", testPutFirstStoresAtVersion1},
		{"PutSecondLoadsExisting", testPutSecondLoadsExisting},
		{"GetReturnsLiveVersion", testGetReturnsLiveVersion},
		{"PutDoesNotAliasCallerSlice", testPutDoesNotAliasCallerSlice},
		{"GetReturnsDefensiveCopy", testGetReturnsDefensiveCopy},
		{"ConcurrentPutExactlyOneCanonicalDEK", testConcurrentPutExactlyOneCanonicalDEK},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tc.fn(t, factory(t))
		})
	}
}

func testGetFreshReturnsNotFound(t *testing.T, b StoreBundle) {
	_, _, err := b.Tenants.GetEncryptedDEK(context.Background(), uuid.NewString())
	if !errors.Is(err, vault.ErrNotFound) {
		t.Errorf("Get fresh err = %v, want ErrNotFound", err)
	}
}

func testPutFirstStoresAtVersion1(t *testing.T, b StoreBundle) {
	ctx := context.Background()
	userID := uuid.NewString()
	dek := []byte{0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0xFF, 0x01, 0x02, 0x03, 0x04}

	canonical, version, err := b.Tenants.PutEncryptedDEK(ctx, userID, dek)
	if err != nil {
		t.Fatalf("Put: %v", err)
	}
	if !bytes.Equal(canonical, dek) {
		t.Errorf("first Put canonical = %x, want %x", canonical, dek)
	}
	if version != 1 {
		t.Errorf("first Put version = %d, want 1", version)
	}

	got, gotVersion, err := b.Tenants.GetEncryptedDEK(ctx, userID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !bytes.Equal(got, dek) {
		t.Errorf("Get bytes = %x, want %x", got, dek)
	}
	if gotVersion != 1 {
		t.Errorf("Get version = %d, want 1", gotVersion)
	}
}

// testPutSecondLoadsExisting locks in the load-or-store contract: a
// second Put for an existing tenant must NOT overwrite the row and
// MUST return the original DEK + version, regardless of what the
// caller passed. This is the property the service-layer race fix
// depends on.
func testPutSecondLoadsExisting(t *testing.T, b StoreBundle) {
	ctx := context.Background()
	userID := uuid.NewString()
	first := []byte("first-dek")
	second := []byte("second-dek-should-be-ignored")

	if _, _, err := b.Tenants.PutEncryptedDEK(ctx, userID, first); err != nil {
		t.Fatalf("Put 1: %v", err)
	}
	canonical, version, err := b.Tenants.PutEncryptedDEK(ctx, userID, second)
	if err != nil {
		t.Fatalf("Put 2: %v", err)
	}
	if !bytes.Equal(canonical, first) {
		t.Errorf("Put 2 canonical = %q, want %q (load-or-store discarded caller's bytes)", canonical, first)
	}
	if version != 1 {
		t.Errorf("Put 2 version = %d, want 1 (provisioning Put must not bump version)", version)
	}

	// And on a fresh Get, the row is still the first DEK.
	got, gotVersion, err := b.Tenants.GetEncryptedDEK(ctx, userID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !bytes.Equal(got, first) {
		t.Errorf("Get after second Put = %q, want %q", got, first)
	}
	if gotVersion != 1 {
		t.Errorf("Get version after second Put = %d, want 1", gotVersion)
	}
}

func testGetReturnsLiveVersion(t *testing.T, b StoreBundle) {
	ctx := context.Background()
	userID := uuid.NewString()
	if _, _, err := b.Tenants.PutEncryptedDEK(ctx, userID, []byte("dek")); err != nil {
		t.Fatalf("Put: %v", err)
	}
	_, version, err := b.Tenants.GetEncryptedDEK(ctx, userID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if version <= 0 {
		t.Errorf("Get version = %d, want positive", version)
	}
}

func testPutDoesNotAliasCallerSlice(t *testing.T, b StoreBundle) {
	ctx := context.Background()
	userID := uuid.NewString()
	dek := []byte{1, 2, 3, 4}
	if _, _, err := b.Tenants.PutEncryptedDEK(ctx, userID, dek); err != nil {
		t.Fatalf("Put: %v", err)
	}
	for i := range dek {
		dek[i] = 0xFF
	}
	got, _, err := b.Tenants.GetEncryptedDEK(ctx, userID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !bytes.Equal(got, []byte{1, 2, 3, 4}) {
		t.Errorf("Put aliased caller slice: got %x, want 01020304", got)
	}
}

func testGetReturnsDefensiveCopy(t *testing.T, b StoreBundle) {
	ctx := context.Background()
	userID := uuid.NewString()
	if _, _, err := b.Tenants.PutEncryptedDEK(ctx, userID, []byte{1, 2, 3, 4}); err != nil {
		t.Fatalf("Put: %v", err)
	}
	got, _, err := b.Tenants.GetEncryptedDEK(ctx, userID)
	if err != nil {
		t.Fatalf("Get 1: %v", err)
	}
	for i := range got {
		got[i] = 0xFF
	}
	got2, _, err := b.Tenants.GetEncryptedDEK(ctx, userID)
	if err != nil {
		t.Fatalf("Get 2: %v", err)
	}
	if !bytes.Equal(got2, []byte{1, 2, 3, 4}) {
		t.Errorf("Get returned aliased slice: second Get = %x, want 01020304", got2)
	}
}

// testConcurrentPutExactlyOneCanonicalDEK races N goroutines, each
// calling PutEncryptedDEK with a distinct candidate DEK. Exactly one
// candidate must end up as the canonical row, and every goroutine
// must observe that same canonical DEK in its own return value. This
// is the storage-level half of the concurrent first-Create race fix
// — the service layer relies on this property to encrypt under the
// winner's DEK regardless of which goroutine got there first.
func testConcurrentPutExactlyOneCanonicalDEK(t *testing.T, b StoreBundle) {
	ctx := context.Background()
	userID := uuid.NewString()

	const goroutines = 16
	type result struct {
		canonical []byte
		version   int
		err       error
	}
	results := make(chan result, goroutines)
	var wg sync.WaitGroup
	for i := 0; i < goroutines; i++ {
		i := i
		wg.Add(1)
		go func() {
			defer wg.Done()
			// Each goroutine offers a uniquely-identifiable candidate.
			candidate := []byte{byte(i + 1), 0xAA, 0xBB}
			c, v, err := b.Tenants.PutEncryptedDEK(ctx, userID, candidate)
			results <- result{canonical: c, version: v, err: err}
		}()
	}
	wg.Wait()
	close(results)

	var canonical []byte
	versions := map[int]int{}
	for r := range results {
		if r.err != nil {
			t.Errorf("concurrent Put err: %v", r.err)
			continue
		}
		if canonical == nil {
			canonical = r.canonical
		} else if !bytes.Equal(canonical, r.canonical) {
			t.Errorf("concurrent Put returned divergent canonical DEKs: %x vs %x", canonical, r.canonical)
		}
		versions[r.version]++
	}

	// All callers should report version 1 — provisioning Put never bumps.
	if len(versions) != 1 {
		t.Errorf("concurrent Put returned %d distinct versions, want 1: %v", len(versions), versions)
	}
	for v := range versions {
		if v != 1 {
			t.Errorf("concurrent Put version = %d, want 1", v)
		}
	}

	// And a follow-up Get agrees.
	got, gotVersion, err := b.Tenants.GetEncryptedDEK(ctx, userID)
	if err != nil {
		t.Fatalf("Get after race: %v", err)
	}
	if !bytes.Equal(got, canonical) {
		t.Errorf("Get after race = %x, want %x", got, canonical)
	}
	if gotVersion != 1 {
		t.Errorf("Get version after race = %d, want 1", gotVersion)
	}
}
