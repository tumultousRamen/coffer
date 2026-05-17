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

// RunCredentialStoreContract drives the full CredentialStore behavior
// contract against the bundle returned by factory. The same scenarios
// must pass against memstore and the Postgres adapter — divergence is
// a bug in whichever side just changed.
func RunCredentialStoreContract(t *testing.T, factory Factory) {
	t.Helper()

	tests := []struct {
		name string
		fn   func(t *testing.T, b StoreBundle)
	}{
		{"CreateThenGet", testCreateThenGet},
		{"CreateThenList", testCreateThenList},
		{"ReplacePreservesCreatedAt", testReplacePreservesCreatedAt},
		{"DeleteThenGetReturnsEmpty", testDeleteThenGetReturnsEmpty},
		{"DuplicateIDReturnsAlreadyExists", testDuplicateIDReturnsAlreadyExists},
		{"DuplicateProviderLabelReturnsAlreadyExists", testDuplicateProviderLabelReturnsAlreadyExists},
		{"GetMixedValidInvalidReturnsOnlyValid", testGetMixedValidInvalidReturnsOnlyValid},
		{"CreateWithoutTenantReturnsNotProvisioned", testCreateWithoutTenantReturnsNotProvisioned},
		{"DeleteMissingReturnsNotFound", testDeleteMissingReturnsNotFound},
		{"ReplaceMissingReturnsNotFound", testReplaceMissingReturnsNotFound},
		{"ListUnknownUserReturnsEmpty", testListUnknownUserReturnsEmpty},
		{"TenantIsolation", testTenantIsolation},
		{"ConcurrentCreateExactlyOneWinner", testConcurrentCreateExactlyOneWinner},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tc.fn(t, factory(t))
		})
	}
}

func provision(t *testing.T, b StoreBundle, userID string) {
	t.Helper()
	if err := b.Tenants.PutEncryptedDEK(context.Background(), userID, []byte("ciphertext-dek-stub")); err != nil {
		t.Fatalf("provision tenant %s: %v", userID, err)
	}
}

func newCred(id, provider, label, secret string) vault.Credential {
	return vault.Credential{
		ID:       id,
		Provider: provider,
		Label:    label,
		Secret:   vault.NewSecretBlob([]byte(secret)),
		Metadata: vault.Metadata{"region": "us-west-1"},
	}
}

func testCreateThenGet(t *testing.T, b StoreBundle) {
	ctx := context.Background()
	userID := uuid.NewString()
	provision(t, b, userID)

	credID := uuid.NewString()
	c := newCred(credID, "s3", "prod_bucket", "secret-v1")
	if err := b.Credentials.Create(ctx, userID, c); err != nil {
		t.Fatalf("Create: %v", err)
	}

	got, err := b.Credentials.Get(ctx, userID, []string{credID})
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("Get returned %d credentials, want 1", len(got))
	}
	if got[0].ID != credID {
		t.Errorf("Get ID = %q, want %q", got[0].ID, credID)
	}
	if got[0].Provider != "s3" || got[0].Label != "prod_bucket" {
		t.Errorf("Get (provider,label) = (%q,%q), want (s3,prod_bucket)", got[0].Provider, got[0].Label)
	}
	if !bytes.Equal(got[0].Secret.Reveal(), []byte("secret-v1")) {
		t.Errorf("Get secret = %q, want %q", got[0].Secret.Reveal(), "secret-v1")
	}
	if got[0].Metadata["region"] != "us-west-1" {
		t.Errorf("Get metadata.region = %v, want us-west-1", got[0].Metadata["region"])
	}
}

func testCreateThenList(t *testing.T, b StoreBundle) {
	ctx := context.Background()
	userID := uuid.NewString()
	provision(t, b, userID)

	credID := uuid.NewString()
	if err := b.Credentials.Create(ctx, userID, newCred(credID, "s3", "prod_bucket", "x")); err != nil {
		t.Fatalf("Create: %v", err)
	}
	summaries, err := b.Credentials.List(ctx, userID)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(summaries) != 1 {
		t.Fatalf("List returned %d, want 1", len(summaries))
	}
	if summaries[0].ID != credID {
		t.Errorf("List ID = %q, want %q", summaries[0].ID, credID)
	}
	if summaries[0].Status != vault.StatusActive {
		t.Errorf("List status = %q, want %q", summaries[0].Status, vault.StatusActive)
	}
	if summaries[0].CreatedAt.IsZero() {
		t.Errorf("List CreatedAt is zero")
	}
}

func testReplacePreservesCreatedAt(t *testing.T, b StoreBundle) {
	ctx := context.Background()
	userID := uuid.NewString()
	provision(t, b, userID)

	credID := uuid.NewString()
	if err := b.Credentials.Create(ctx, userID, newCred(credID, "s3", "p", "v1")); err != nil {
		t.Fatalf("Create: %v", err)
	}
	beforeList, err := b.Credentials.List(ctx, userID)
	if err != nil {
		t.Fatalf("List before: %v", err)
	}
	createdAt := beforeList[0].CreatedAt

	if err := b.Credentials.Replace(ctx, userID, newCred(credID, "s3", "p", "v2")); err != nil {
		t.Fatalf("Replace: %v", err)
	}
	got, err := b.Credentials.Get(ctx, userID, []string{credID})
	if err != nil {
		t.Fatalf("Get after Replace: %v", err)
	}
	if !bytes.Equal(got[0].Secret.Reveal(), []byte("v2")) {
		t.Errorf("Get secret = %q, want v2", got[0].Secret.Reveal())
	}
	afterList, err := b.Credentials.List(ctx, userID)
	if err != nil {
		t.Fatalf("List after: %v", err)
	}
	if !afterList[0].CreatedAt.Equal(createdAt) {
		t.Errorf("CreatedAt changed across Replace: %v -> %v", createdAt, afterList[0].CreatedAt)
	}
}

func testDeleteThenGetReturnsEmpty(t *testing.T, b StoreBundle) {
	ctx := context.Background()
	userID := uuid.NewString()
	provision(t, b, userID)

	credID := uuid.NewString()
	if err := b.Credentials.Create(ctx, userID, newCred(credID, "s3", "p", "x")); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := b.Credentials.Delete(ctx, userID, credID); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	got, err := b.Credentials.Get(ctx, userID, []string{credID})
	if err != nil {
		t.Fatalf("Get after Delete: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("Get after Delete returned %d rows, want 0", len(got))
	}
}

func testDuplicateIDReturnsAlreadyExists(t *testing.T, b StoreBundle) {
	ctx := context.Background()
	userID := uuid.NewString()
	provision(t, b, userID)

	credID := uuid.NewString()
	if err := b.Credentials.Create(ctx, userID, newCred(credID, "s3", "p1", "x")); err != nil {
		t.Fatalf("first Create: %v", err)
	}
	err := b.Credentials.Create(ctx, userID, newCred(credID, "s3", "p2", "y"))
	if !errors.Is(err, vault.ErrAlreadyExists) {
		t.Errorf("duplicate ID err = %v, want ErrAlreadyExists", err)
	}
}

func testDuplicateProviderLabelReturnsAlreadyExists(t *testing.T, b StoreBundle) {
	ctx := context.Background()
	userID := uuid.NewString()
	provision(t, b, userID)

	if err := b.Credentials.Create(ctx, userID, newCred(uuid.NewString(), "s3", "prod", "x")); err != nil {
		t.Fatalf("first Create: %v", err)
	}
	err := b.Credentials.Create(ctx, userID, newCred(uuid.NewString(), "s3", "prod", "y"))
	if !errors.Is(err, vault.ErrAlreadyExists) {
		t.Errorf("duplicate (provider,label) err = %v, want ErrAlreadyExists", err)
	}
}

func testGetMixedValidInvalidReturnsOnlyValid(t *testing.T, b StoreBundle) {
	ctx := context.Background()
	userID := uuid.NewString()
	provision(t, b, userID)

	existing := uuid.NewString()
	missing := uuid.NewString()
	if err := b.Credentials.Create(ctx, userID, newCred(existing, "s3", "p", "x")); err != nil {
		t.Fatalf("Create: %v", err)
	}
	got, err := b.Credentials.Get(ctx, userID, []string{existing, missing})
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if len(got) != 1 || got[0].ID != existing {
		t.Errorf("Get returned %v, want exactly the existing credential", got)
	}
}

func testCreateWithoutTenantReturnsNotProvisioned(t *testing.T, b StoreBundle) {
	ctx := context.Background()
	// Deliberately do NOT call provision().
	userID := uuid.NewString()
	err := b.Credentials.Create(ctx, userID, newCred(uuid.NewString(), "s3", "p", "x"))
	if !errors.Is(err, vault.ErrTenantNotProvisioned) {
		t.Errorf("Create without tenant err = %v, want ErrTenantNotProvisioned", err)
	}
}

func testDeleteMissingReturnsNotFound(t *testing.T, b StoreBundle) {
	ctx := context.Background()
	userID := uuid.NewString()
	provision(t, b, userID)
	err := b.Credentials.Delete(ctx, userID, uuid.NewString())
	if !errors.Is(err, vault.ErrNotFound) {
		t.Errorf("Delete missing err = %v, want ErrNotFound", err)
	}
}

func testReplaceMissingReturnsNotFound(t *testing.T, b StoreBundle) {
	ctx := context.Background()
	userID := uuid.NewString()
	provision(t, b, userID)
	err := b.Credentials.Replace(ctx, userID, newCred(uuid.NewString(), "s3", "p", "x"))
	if !errors.Is(err, vault.ErrNotFound) {
		t.Errorf("Replace missing err = %v, want ErrNotFound", err)
	}
}

func testListUnknownUserReturnsEmpty(t *testing.T, b StoreBundle) {
	got, err := b.Credentials.List(context.Background(), uuid.NewString())
	if err != nil {
		t.Errorf("List unknown user err = %v, want nil", err)
	}
	if len(got) != 0 {
		t.Errorf("List unknown user returned %d rows, want 0", len(got))
	}
}

func testTenantIsolation(t *testing.T, b StoreBundle) {
	ctx := context.Background()
	u1, u2 := uuid.NewString(), uuid.NewString()
	provision(t, b, u1)
	provision(t, b, u2)

	// Same provider + label is allowed across users (unique constraint
	// is per-user).
	if err := b.Credentials.Create(ctx, u1, newCred(uuid.NewString(), "s3", "p", "u1-secret")); err != nil {
		t.Fatalf("Create u1: %v", err)
	}
	c2ID := uuid.NewString()
	if err := b.Credentials.Create(ctx, u2, newCred(c2ID, "s3", "p", "u2-secret")); err != nil {
		t.Fatalf("Create u2: %v", err)
	}
	got, err := b.Credentials.Get(ctx, u2, []string{c2ID})
	if err != nil {
		t.Fatalf("Get u2: %v", err)
	}
	if len(got) != 1 || !bytes.Equal(got[0].Secret.Reveal(), []byte("u2-secret")) {
		t.Errorf("tenant isolation broken: u2 read %v", got)
	}
	// u1 querying u2's credential ID must return empty (no leak).
	leak, err := b.Credentials.Get(ctx, u1, []string{c2ID})
	if err != nil {
		t.Fatalf("Get u1 with u2 id: %v", err)
	}
	if len(leak) != 0 {
		t.Errorf("u1 saw %d rows for u2's credential id, want 0", len(leak))
	}
}

func testConcurrentCreateExactlyOneWinner(t *testing.T, b StoreBundle) {
	ctx := context.Background()
	userID := uuid.NewString()
	provision(t, b, userID)

	const goroutines = 8
	var wg sync.WaitGroup
	results := make(chan error, goroutines)

	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			results <- b.Credentials.Create(ctx, userID, newCred(uuid.NewString(), "s3", "contended_label", "x"))
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
			t.Errorf("unexpected error from concurrent Create: %v", err)
		}
	}
	if successes != 1 {
		t.Errorf("got %d successful creates, want exactly 1", successes)
	}
	if duplicates != goroutines-1 {
		t.Errorf("got %d ErrAlreadyExists, want %d", duplicates, goroutines-1)
	}
	if other != 0 {
		t.Errorf("got %d unexpected errors", other)
	}
}
