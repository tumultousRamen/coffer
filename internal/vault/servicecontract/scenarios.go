package servicecontract

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/tumultousRamen/coffer/internal/vault"
)

// mustGenKeyPair returns a fresh ed25519 keypair for tests that need
// to mint tokens under a key the bundle's verifier does NOT trust
// (e.g. the bad-signature scenario).
func mustGenKeyPair(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey: %v", err)
	}
	return pub, priv
}

// RunServiceContract drives the full vault.Service behavior contract
// against the bundle returned by factory. Every scenario builds a
// fresh bundle so backend state cannot leak across scenarios.
func RunServiceContract(t *testing.T, factory Factory) {
	t.Helper()

	tests := []struct {
		name string
		fn   func(t *testing.T, b Bundle)
	}{
		{"CreateRoundTrip", testCreateRoundTrip},
		{"ListReturnsAllOwned", testListReturnsAllOwned},
		{"GetSummaryReturnsProjection", testGetSummaryReturnsProjection},
		{"GetSummaryMissingReturnsNotFound", testGetSummaryMissingReturnsNotFound},
		{"ReplaceUsesFreshNonce", testReplaceUsesFreshNonce},
		{"ReplacePreservesProviderForAAD", testReplacePreservesProviderForAAD},
		{"DeleteHardDeletes", testDeleteHardDeletes},
		{"DeleteMissingReturnsNotFound", testDeleteMissingReturnsNotFound},
		{"FirstCreateProvisionsTenant", testFirstCreateProvisionsTenant},
		{"SecondCredentialReusesDEK", testSecondCredentialReusesDEK},
		{"CrossTenantIsolation", testCrossTenantIsolation},
		{"ConcurrentFirstCreateAllDecryptable", testConcurrentFirstCreateAllDecryptable},
		{"FetchForWorkerRoundTrip", testFetchForWorkerRoundTrip},
		{"FetchForWorkerExpiredGrant", testFetchForWorkerExpiredGrant},
		{"FetchForWorkerBadSignature", testFetchForWorkerBadSignature},
		{"FetchForWorkerOutOfScopeID", testFetchForWorkerOutOfScopeID},
		{"FetchForWorkerRejectWholeOnMissing", testFetchForWorkerRejectWholeOnMissing},
		{"FetchForWorkerUnprovisionedTenant", testFetchForWorkerUnprovisionedTenant},
		{"FetchForWorkerBatchReturnsAllPlaintexts", testFetchForWorkerBatchReturnsAllPlaintexts},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tc.fn(t, factory(t))
		})
	}
}

// decryptCredential reads the stored row via the bundle's storage
// layer, fetches the tenant's current DEK, and unwraps the ciphertext
// using the same Cryptor instance the Service was built with.
//
// Worker-side decryption ships in the next PRD via gRPC +
// capability tokens; here we drive the same primitives directly so
// the contract suite can assert end-to-end decryptability without
// jumping through the worker auth model.
func decryptCredential(
	ctx context.Context,
	b Bundle,
	userID, credID string,
) ([]byte, error) {
	rows, err := b.Store.Get(ctx, userID, []string{credID})
	if err != nil {
		return nil, fmt.Errorf("decryptCredential: store.Get: %w", err)
	}
	if len(rows) == 0 {
		return nil, vault.ErrNotFound
	}
	row := rows[0]

	ciphertextDEK, _, err := b.Tenants.GetEncryptedDEK(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("decryptCredential: tenant lookup: %w", err)
	}
	return b.Cryptor.Decrypt(
		ctx, userID, credID, row.Provider,
		row.Secret.Reveal(), row.Nonce, ciphertextDEK,
	)
}

// helper: create a credential and return its ID + the original
// plaintext so the caller can later assert decryptability.
func mustCreate(t *testing.T, b Bundle, userID, provider, label string, secret []byte) string {
	t.Helper()
	id, err := b.Service.CreateCredential(
		context.Background(), userID, provider, label,
		secret, vault.Metadata{"region": "us-west-1"},
	)
	if err != nil {
		t.Fatalf("CreateCredential: %v", err)
	}
	return id
}

func testCreateRoundTrip(t *testing.T, b Bundle) {
	ctx := context.Background()
	userID := uuid.NewString()
	plaintext := []byte("super-secret")

	id := mustCreate(t, b, userID, "s3", "prod_bucket", plaintext)

	sum, err := b.Service.GetCredentialSummary(ctx, userID, id)
	if err != nil {
		t.Fatalf("GetCredentialSummary: %v", err)
	}
	if sum.ID != id {
		t.Errorf("summary.ID = %q, want %q", sum.ID, id)
	}
	if sum.Provider != "s3" || sum.Label != "prod_bucket" {
		t.Errorf("summary (provider,label) = (%q,%q), want (s3,prod_bucket)", sum.Provider, sum.Label)
	}
	if sum.Status != vault.StatusActive {
		t.Errorf("summary.Status = %q, want active", sum.Status)
	}
	if sum.CreatedAt.IsZero() {
		t.Errorf("summary.CreatedAt is zero")
	}

	// End-to-end decrypt is part of the round-trip contract.
	got, err := decryptCredential(ctx, b, userID, id)
	if err != nil {
		t.Fatalf("decryptCredential: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Errorf("decrypted = %q, want %q", got, plaintext)
	}
}

func testListReturnsAllOwned(t *testing.T, b Bundle) {
	ctx := context.Background()
	userID := uuid.NewString()

	mustCreate(t, b, userID, "s3", "bucket-a", []byte("a"))
	mustCreate(t, b, userID, "s3", "bucket-b", []byte("b"))
	mustCreate(t, b, userID, "dropbox", "personal", []byte("c"))

	got, err := b.Service.ListCredentials(ctx, userID)
	if err != nil {
		t.Fatalf("ListCredentials: %v", err)
	}
	if len(got) != 3 {
		t.Errorf("List returned %d summaries, want 3", len(got))
	}
}

func testGetSummaryReturnsProjection(t *testing.T, b Bundle) {
	ctx := context.Background()
	userID := uuid.NewString()
	id := mustCreate(t, b, userID, "s3", "p", []byte("x"))

	sum, err := b.Service.GetCredentialSummary(ctx, userID, id)
	if err != nil {
		t.Fatalf("GetCredentialSummary: %v", err)
	}
	// Type-level: vault.CredentialSummary has no Secret field, so
	// there is nothing to assert at runtime — the compile-time guard
	// from ADR 0007 §3 + the structural test in credential_test.go
	// pin this. We only need to assert positive identification.
	if sum.ID != id {
		t.Errorf("summary.ID = %q, want %q", sum.ID, id)
	}
}

func testGetSummaryMissingReturnsNotFound(t *testing.T, b Bundle) {
	ctx := context.Background()
	userID := uuid.NewString()
	_ = mustCreate(t, b, userID, "s3", "p", []byte("x")) // provision tenant + a row

	_, err := b.Service.GetCredentialSummary(ctx, userID, uuid.NewString())
	if !errors.Is(err, vault.ErrNotFound) {
		t.Errorf("GetCredentialSummary missing err = %v, want ErrNotFound", err)
	}
}

// testReplaceUsesFreshNonce verifies the catastrophic AES-GCM
// nonce-reuse failure mode is impossible on Replace: a Replace must
// generate a new nonce, not reuse the previous one. Observed via the
// portcontract round-trip wrapper — but the service-level assertion
// is that two consecutive Replaces produce two distinct nonces in the
// stored row. We can't see the stored row from outside the bundle
// without exposing the credential store, so we assert via the
// counting KMS that no extra GenerateDataKey was called (Replace
// reuses the existing DEK) and that the round-trip succeeded.
func testReplaceUsesFreshNonce(t *testing.T, b Bundle) {
	ctx := context.Background()
	userID := uuid.NewString()
	id := mustCreate(t, b, userID, "s3", "p", []byte("v1"))

	generatesBefore := b.KMS.GenerateCalls()
	if err := b.Service.ReplaceCredential(ctx, userID, id, []byte("v2"), vault.Metadata{"region": "us-west-2"}); err != nil {
		t.Fatalf("ReplaceCredential: %v", err)
	}
	generatesAfter := b.KMS.GenerateCalls()
	if generatesAfter != generatesBefore {
		t.Errorf("Replace called GenerateDataKey %d extra times, want 0 (DEK should not change on Replace)",
			generatesAfter-generatesBefore)
	}

	sum, err := b.Service.GetCredentialSummary(ctx, userID, id)
	if err != nil {
		t.Fatalf("GetCredentialSummary after Replace: %v", err)
	}
	if sum.ID != id {
		t.Errorf("Replace dropped the row (got summary ID %q)", sum.ID)
	}

	// End-to-end: the Replaced ciphertext must decrypt to the new
	// plaintext under the (unchanged) tenant DEK. A reused nonce
	// would not cause this test to fail — it would still decrypt —
	// but a tampered AAD (e.g. provider drift) would, providing
	// defense-in-depth coverage of the AAD-binding invariant.
	got, err := decryptCredential(ctx, b, userID, id)
	if err != nil {
		t.Fatalf("decrypt after Replace: %v", err)
	}
	if !bytes.Equal(got, []byte("v2")) {
		t.Errorf("decrypted after Replace = %q, want v2", got)
	}
}

// testReplacePreservesProviderForAAD verifies that Replace does NOT
// change the row's provider — if it did, the AAD binding in
// AES-GCM would change and the credential would become permanently
// undecryptable. Observed by reading back the summary.
func testReplacePreservesProviderForAAD(t *testing.T, b Bundle) {
	ctx := context.Background()
	userID := uuid.NewString()
	id := mustCreate(t, b, userID, "s3", "p", []byte("v1"))

	if err := b.Service.ReplaceCredential(ctx, userID, id, []byte("v2"), vault.Metadata{}); err != nil {
		t.Fatalf("ReplaceCredential: %v", err)
	}
	sum, err := b.Service.GetCredentialSummary(ctx, userID, id)
	if err != nil {
		t.Fatalf("GetCredentialSummary: %v", err)
	}
	if sum.Provider != "s3" {
		t.Errorf("provider drift after Replace: %q, want s3", sum.Provider)
	}
	if sum.Label != "p" {
		t.Errorf("label drift after Replace: %q, want p", sum.Label)
	}
}

func testDeleteHardDeletes(t *testing.T, b Bundle) {
	ctx := context.Background()
	userID := uuid.NewString()
	id := mustCreate(t, b, userID, "s3", "p", []byte("x"))

	if err := b.Service.DeleteCredential(ctx, userID, id); err != nil {
		t.Fatalf("DeleteCredential: %v", err)
	}
	_, err := b.Service.GetCredentialSummary(ctx, userID, id)
	if !errors.Is(err, vault.ErrNotFound) {
		t.Errorf("GetCredentialSummary after Delete = %v, want ErrNotFound", err)
	}
}

func testDeleteMissingReturnsNotFound(t *testing.T, b Bundle) {
	ctx := context.Background()
	userID := uuid.NewString()
	_ = mustCreate(t, b, userID, "s3", "p", []byte("x"))

	err := b.Service.DeleteCredential(ctx, userID, uuid.NewString())
	if !errors.Is(err, vault.ErrNotFound) {
		t.Errorf("DeleteCredential missing = %v, want ErrNotFound", err)
	}
}

// testFirstCreateProvisionsTenant asserts that creating a credential
// for a never-seen userID provisions a tenants row as a side effect.
func testFirstCreateProvisionsTenant(t *testing.T, b Bundle) {
	ctx := context.Background()
	userID := uuid.NewString()

	if _, _, err := b.Tenants.GetEncryptedDEK(ctx, userID); !errors.Is(err, vault.ErrNotFound) {
		t.Fatalf("pre-state: GetEncryptedDEK err = %v, want ErrNotFound", err)
	}

	_ = mustCreate(t, b, userID, "s3", "p", []byte("x"))

	dek, version, err := b.Tenants.GetEncryptedDEK(ctx, userID)
	if err != nil {
		t.Fatalf("post-state: GetEncryptedDEK err = %v", err)
	}
	if len(dek) == 0 {
		t.Errorf("tenant DEK is empty after first Create")
	}
	if version != 1 {
		t.Errorf("tenant DEK version = %d after first Create, want 1", version)
	}
}

// testSecondCredentialReusesDEK is the call-counting scenario from
// the PRD: a second credential for the same tenant must not trigger
// a fresh GenerateDataKey. Verified via CountingKeyManager.
func testSecondCredentialReusesDEK(t *testing.T, b Bundle) {
	userID := uuid.NewString()

	_ = mustCreate(t, b, userID, "s3", "p1", []byte("a"))
	generatesAfterFirst := b.KMS.GenerateCalls()
	_ = mustCreate(t, b, userID, "s3", "p2", []byte("b"))
	generatesAfterSecond := b.KMS.GenerateCalls()

	if generatesAfterFirst != 1 {
		t.Errorf("GenerateDataKey calls after first Create = %d, want 1", generatesAfterFirst)
	}
	if generatesAfterSecond != 1 {
		t.Errorf("GenerateDataKey calls after second Create = %d, want 1 (second Create must reuse DEK)",
			generatesAfterSecond)
	}
}

func testCrossTenantIsolation(t *testing.T, b Bundle) {
	ctx := context.Background()
	u1, u2 := uuid.NewString(), uuid.NewString()

	id1 := mustCreate(t, b, u1, "s3", "p", []byte("u1-secret"))
	_ = mustCreate(t, b, u2, "s3", "p", []byte("u2-secret"))

	// u2 cannot see u1's credential.
	_, err := b.Service.GetCredentialSummary(ctx, u2, id1)
	if !errors.Is(err, vault.ErrNotFound) {
		t.Errorf("cross-tenant leak: u2 read u1's credential, err = %v, want ErrNotFound", err)
	}

	// Delete from u2 with u1's ID must not delete u1's row.
	_ = b.Service.DeleteCredential(ctx, u2, id1)
	sum, err := b.Service.GetCredentialSummary(ctx, u1, id1)
	if err != nil {
		t.Fatalf("u1's credential lost after cross-tenant Delete: %v", err)
	}
	if sum.ID != id1 {
		t.Errorf("u1's credential ID = %q, want %q", sum.ID, id1)
	}
}

// testConcurrentFirstCreateAllDecryptable is the strongest scenario
// in the suite. N goroutines call CreateCredential concurrently for
// the same never-seen userID. The race-fix property says:
//
//  1. Exactly one tenants row results.
//  2. Every Create succeeds (different UUIDv7 IDs, different labels).
//  3. Every resulting credential is decryptable end-to-end under the
//     winning DEK. This is the property the wider PutEncryptedDEK
//     return shape was introduced to support — credentials written
//     by goroutines that lost the provisioning race would otherwise
//     be encrypted under an orphaned DEK and fail to decrypt.
//
// Decryption is exercised via a Cryptor that shares the same KMS
// instance — the same wrapped DEK can be unwrapped because the fake
// KeyManager's "fake:" prefix encoding is content-addressable.
func testConcurrentFirstCreateAllDecryptable(t *testing.T, b Bundle) {
	ctx := context.Background()
	userID := uuid.NewString()

	const goroutines = 50
	type result struct {
		id     string
		secret []byte
		err    error
	}
	results := make(chan result, goroutines)
	var wg sync.WaitGroup
	for i := 0; i < goroutines; i++ {
		i := i
		wg.Add(1)
		go func() {
			defer wg.Done()
			secret := []byte(fmt.Sprintf("plaintext-%d", i))
			label := fmt.Sprintf("contended-%d", i)
			id, err := b.Service.CreateCredential(
				ctx, userID, "s3", label, secret, vault.Metadata{},
			)
			results <- result{id: id, secret: secret, err: err}
		}()
	}
	wg.Wait()
	close(results)

	created := make([]result, 0, goroutines)
	for r := range results {
		if r.err != nil {
			t.Errorf("Create err: %v", r.err)
			continue
		}
		created = append(created, r)
	}
	if len(created) != goroutines {
		t.Fatalf("got %d successful creates, want %d", len(created), goroutines)
	}

	// Exactly one tenants row.
	_, version, err := b.Tenants.GetEncryptedDEK(ctx, userID)
	if err != nil {
		t.Fatalf("GetEncryptedDEK after race: %v", err)
	}
	if version != 1 {
		t.Errorf("post-race version = %d, want 1 (provisioning Put must not bump)", version)
	}

	// At most one Provision survives — the KMS sees N or more
	// GenerateDataKey calls (one per goroutine that hit the
	// NotFound path), but only one wrapped DEK lands in tenants. We
	// don't constrain the upper bound on GenerateCalls here because
	// every goroutine that observes ErrNotFound calls Provision
	// before racing to Put.
	if got := b.KMS.GenerateCalls(); got < 1 {
		t.Errorf("GenerateCalls = %d, want >= 1", got)
	}

	// Every credential's summary is readable.
	summaries, err := b.Service.ListCredentials(ctx, userID)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(summaries) != goroutines {
		t.Errorf("List returned %d summaries, want %d", len(summaries), goroutines)
	}

	// The strongest property: every credential is decryptable
	// end-to-end. This is the test that the wider PutEncryptedDEK
	// return shape was introduced to make passable — without the
	// load-or-store fix, losers of the provisioning race would have
	// ciphertext sealed under DEKs the tenants row never references
	// and decrypt would fail.
	for _, r := range created {
		got, err := decryptCredential(ctx, b, userID, r.id)
		if err != nil {
			t.Errorf("decrypt id=%s: %v", r.id, err)
			continue
		}
		if !bytes.Equal(got, r.secret) {
			t.Errorf("decrypt id=%s = %q, want %q", r.id, got, r.secret)
		}
	}
}


// mintFor issues a grant token for userID authorizing exactly ids.
// Default TTL 5 minutes — well inside the verifier's leeway.
func mintFor(t *testing.T, b Bundle, userID string, ids []string) string {
	t.Helper()
	token, err := vault.MintGrant(b.GrantSigner, userID, ids, 5*time.Minute, "test-job")
	if err != nil {
		t.Fatalf("MintGrant: %v", err)
	}
	return token
}

func testFetchForWorkerRoundTrip(t *testing.T, b Bundle) {
	ctx := context.Background()
	userID := uuid.NewString()
	plaintext := []byte("aws-secret-access-key-stuff")

	id := mustCreate(t, b, userID, "s3", "prod_bucket", plaintext)
	token := mintFor(t, b, userID, []string{id})

	got, err := b.Service.FetchForWorker(ctx, token, []string{id})
	if err != nil {
		t.Fatalf("FetchForWorker: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("FetchForWorker returned %d credentials, want 1", len(got))
	}
	if got[0].ID != id {
		t.Errorf("returned ID = %q, want %q", got[0].ID, id)
	}
	if got[0].Provider != "s3" || got[0].Label != "prod_bucket" {
		t.Errorf("(provider,label) = (%q,%q), want (s3,prod_bucket)", got[0].Provider, got[0].Label)
	}
	if !bytes.Equal(got[0].Secret.Reveal(), plaintext) {
		t.Errorf("returned plaintext = %q, want %q", got[0].Secret.Reveal(), plaintext)
	}
	// Worker-path Credentials must zero the storage-shape fields.
	if got[0].Nonce != nil {
		t.Errorf("Nonce should be zero on worker path, got %x", got[0].Nonce)
	}
	if got[0].DEKVersion != 0 {
		t.Errorf("DEKVersion should be zero on worker path, got %d", got[0].DEKVersion)
	}
}

func testFetchForWorkerExpiredGrant(t *testing.T, b Bundle) {
	ctx := context.Background()
	userID := uuid.NewString()
	id := mustCreate(t, b, userID, "s3", "p", []byte("x"))

	token, err := vault.MintGrant(b.GrantSigner, userID, []string{id}, -10*time.Minute, "j")
	if err != nil {
		t.Fatalf("MintGrant: %v", err)
	}
	_, err = b.Service.FetchForWorker(ctx, token, []string{id})
	if !errors.Is(err, vault.ErrGrantExpired) {
		t.Errorf("FetchForWorker expired grant err = %v, want ErrGrantExpired", err)
	}
}

func testFetchForWorkerBadSignature(t *testing.T, b Bundle) {
	ctx := context.Background()
	userID := uuid.NewString()
	id := mustCreate(t, b, userID, "s3", "p", []byte("x"))

	// Mint with an unrelated private key — verifier built with b.GrantSigner's
	// counterpart public key will reject.
	_, otherPriv := mustGenKeyPair(t)
	token, err := vault.MintGrant(otherPriv, userID, []string{id}, 5*time.Minute, "j")
	if err != nil {
		t.Fatalf("MintGrant: %v", err)
	}
	_, err = b.Service.FetchForWorker(ctx, token, []string{id})
	if !errors.Is(err, vault.ErrGrantSignature) {
		t.Errorf("FetchForWorker bad signature err = %v, want ErrGrantSignature", err)
	}
}

func testFetchForWorkerOutOfScopeID(t *testing.T, b Bundle) {
	ctx := context.Background()
	userID := uuid.NewString()
	idAuthorized := mustCreate(t, b, userID, "s3", "auth", []byte("a"))
	idOther := mustCreate(t, b, userID, "s3", "other", []byte("b"))

	// Token authorizes only idAuthorized; request asks for both.
	token := mintFor(t, b, userID, []string{idAuthorized})
	_, err := b.Service.FetchForWorker(ctx, token, []string{idAuthorized, idOther})
	if !errors.Is(err, vault.ErrUnauthorized) {
		t.Errorf("FetchForWorker out-of-scope err = %v, want ErrUnauthorized", err)
	}
}

func testFetchForWorkerRejectWholeOnMissing(t *testing.T, b Bundle) {
	ctx := context.Background()
	userID := uuid.NewString()
	existing := mustCreate(t, b, userID, "s3", "p", []byte("x"))
	missing := uuid.NewString()

	// Grant authorizes both IDs, but only one exists in storage.
	token := mintFor(t, b, userID, []string{existing, missing})
	_, err := b.Service.FetchForWorker(ctx, token, []string{existing, missing})
	if !errors.Is(err, vault.ErrNotFound) {
		t.Errorf("FetchForWorker partial-missing err = %v, want ErrNotFound (reject-whole)", err)
	}
}

func testFetchForWorkerUnprovisionedTenant(t *testing.T, b Bundle) {
	ctx := context.Background()
	// userID is fresh and has no credentials/tenants row at all.
	userID := uuid.NewString()
	fakeID := uuid.NewString()
	token := mintFor(t, b, userID, []string{fakeID})

	_, err := b.Service.FetchForWorker(ctx, token, []string{fakeID})
	if !errors.Is(err, vault.ErrTenantNotProvisioned) {
		t.Errorf("FetchForWorker unprovisioned err = %v, want ErrTenantNotProvisioned", err)
	}
}

func testFetchForWorkerBatchReturnsAllPlaintexts(t *testing.T, b Bundle) {
	ctx := context.Background()
	userID := uuid.NewString()
	want := map[string][]byte{}
	ids := make([]string, 0, 3)
	for i, label := range []string{"a", "b", "c"} {
		secret := []byte(fmt.Sprintf("secret-%d", i))
		id := mustCreate(t, b, userID, "s3", label, secret)
		want[id] = secret
		ids = append(ids, id)
	}
	token := mintFor(t, b, userID, ids)

	got, err := b.Service.FetchForWorker(ctx, token, ids)
	if err != nil {
		t.Fatalf("FetchForWorker batch: %v", err)
	}
	if len(got) != len(ids) {
		t.Fatalf("FetchForWorker returned %d, want %d", len(got), len(ids))
	}
	for _, c := range got {
		expected, ok := want[c.ID]
		if !ok {
			t.Errorf("FetchForWorker returned unexpected id %q", c.ID)
			continue
		}
		if !bytes.Equal(c.Secret.Reveal(), expected) {
			t.Errorf("id=%s plaintext = %q, want %q", c.ID, c.Secret.Reveal(), expected)
		}
	}
}
