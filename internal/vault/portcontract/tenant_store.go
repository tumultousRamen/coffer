package portcontract

import (
	"bytes"
	"context"
	"errors"
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
		{"PutThenGetByteEqual", testPutThenGetByteEqual},
		{"PutTwiceOverwrites", testPutTwiceOverwrites},
		{"PutDoesNotAliasCallerSlice", testPutDoesNotAliasCallerSlice},
		{"GetReturnsDefensiveCopy", testGetReturnsDefensiveCopy},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tc.fn(t, factory(t))
		})
	}
}

func testGetFreshReturnsNotFound(t *testing.T, b StoreBundle) {
	_, err := b.Tenants.GetEncryptedDEK(context.Background(), uuid.NewString())
	if !errors.Is(err, vault.ErrNotFound) {
		t.Errorf("Get fresh err = %v, want ErrNotFound", err)
	}
}

func testPutThenGetByteEqual(t *testing.T, b StoreBundle) {
	ctx := context.Background()
	userID := uuid.NewString()
	dek := []byte{0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0xFF, 0x01, 0x02, 0x03, 0x04}
	if err := b.Tenants.PutEncryptedDEK(ctx, userID, dek); err != nil {
		t.Fatalf("Put: %v", err)
	}
	got, err := b.Tenants.GetEncryptedDEK(ctx, userID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !bytes.Equal(got, dek) {
		t.Errorf("Get bytes = %x, want %x", got, dek)
	}
}

func testPutTwiceOverwrites(t *testing.T, b StoreBundle) {
	ctx := context.Background()
	userID := uuid.NewString()
	if err := b.Tenants.PutEncryptedDEK(ctx, userID, []byte("first")); err != nil {
		t.Fatalf("Put 1: %v", err)
	}
	if err := b.Tenants.PutEncryptedDEK(ctx, userID, []byte("second")); err != nil {
		t.Fatalf("Put 2: %v", err)
	}
	got, err := b.Tenants.GetEncryptedDEK(ctx, userID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !bytes.Equal(got, []byte("second")) {
		t.Errorf("Get bytes = %q, want %q", got, "second")
	}
}

func testPutDoesNotAliasCallerSlice(t *testing.T, b StoreBundle) {
	ctx := context.Background()
	userID := uuid.NewString()
	dek := []byte{1, 2, 3, 4}
	if err := b.Tenants.PutEncryptedDEK(ctx, userID, dek); err != nil {
		t.Fatalf("Put: %v", err)
	}
	for i := range dek {
		dek[i] = 0xFF
	}
	got, err := b.Tenants.GetEncryptedDEK(ctx, userID)
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
	if err := b.Tenants.PutEncryptedDEK(ctx, userID, []byte{1, 2, 3, 4}); err != nil {
		t.Fatalf("Put: %v", err)
	}
	got, err := b.Tenants.GetEncryptedDEK(ctx, userID)
	if err != nil {
		t.Fatalf("Get 1: %v", err)
	}
	for i := range got {
		got[i] = 0xFF
	}
	got2, err := b.Tenants.GetEncryptedDEK(ctx, userID)
	if err != nil {
		t.Fatalf("Get 2: %v", err)
	}
	if !bytes.Equal(got2, []byte{1, 2, 3, 4}) {
		t.Errorf("Get returned aliased slice: second Get = %x, want 01020304", got2)
	}
}
