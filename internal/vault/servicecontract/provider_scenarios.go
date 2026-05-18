package servicecontract

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/tumultousRamen/coffer/internal/vault"
	"github.com/tumultousRamen/coffer/internal/vault/providertest"
)

// ProviderFactory builds a Bundle whose Service was constructed with
// the supplied ProviderLookup. Adapter packages (memstore, postgres)
// provide one of these so the provider-aware scenarios can stage a
// custom registry per case (always-validates, always-rejects, etc.)
// without re-implementing the bundle wiring.
//
// Implementations should mirror their existing Factory: same storage
// + cryptor + verifier setup, but use the supplied lookup as the
// fifth NewService arg. lookup is non-nil; pass it through directly.
type ProviderFactory func(t *testing.T, lookup vault.ProviderLookup) Bundle

// RunProviderScenarios drives the provider-aware Service scenarios
// against the bundle the factory produces. Each scenario builds its
// own ProviderLookup per case so the suite never relies on shared
// state between scenarios.
//
// Call this from the same adapter test file that already calls
// RunServiceContract — the provider scenarios are complementary, not
// duplicative.
func RunProviderScenarios(t *testing.T, factory ProviderFactory) {
	t.Helper()

	t.Run("CreateValidatesProvider", func(t *testing.T) {
		runCreateValidatesProvider(t, factory)
	})
	t.Run("CreateRejectsOnValidationFailure", func(t *testing.T) {
		runCreateRejectsOnValidationFailure(t, factory)
	})
	t.Run("CreateRejectsOnUnknownProvider", func(t *testing.T) {
		runCreateRejectsOnUnknownProvider(t, factory)
	})
	t.Run("ReplaceValidatesProvider", func(t *testing.T) {
		runReplaceValidatesProvider(t, factory)
	})
	t.Run("ReplaceRejectsOnValidationFailure", func(t *testing.T) {
		runReplaceRejectsOnValidationFailure(t, factory)
	})
	t.Run("ValidationFailureDoesNotPersist", func(t *testing.T) {
		runValidationFailureDoesNotPersist(t, factory)
	})
}

// strictRegistry returns a ProviderLookup whose only known provider
// is "s3", mapped to the supplied ConfigurableProvider.
func strictRegistry(p vault.Provider) vault.ProviderLookup {
	r := vault.NewProviderRegistry()
	r.Register("s3", p)
	return r
}

func runCreateValidatesProvider(t *testing.T, factory ProviderFactory) {
	prov := &providertest.ConfigurableProvider{}
	b := factory(t, strictRegistry(prov))

	plaintext := []byte(`{"access_key_id":"AKIA","secret_access_key":"x"}`)
	_, err := b.Service.CreateCredential(
		context.Background(), uuid.NewString(), "s3", "p",
		plaintext, vault.Metadata{"region": "us-west-1"},
	)
	if err != nil {
		t.Fatalf("CreateCredential err = %v, want nil", err)
	}
	if prov.ValidateCalls != 1 {
		t.Errorf("Validate calls = %d, want 1", prov.ValidateCalls)
	}
	// The Service must pass the user's submitted plaintext through
	// to Validate, not the post-encrypt ciphertext.
	if string(prov.ValidateLastSecret) != string(plaintext) {
		t.Errorf("Validate received %q, want submitted plaintext %q", prov.ValidateLastSecret, plaintext)
	}
}

func runCreateRejectsOnValidationFailure(t *testing.T, factory ProviderFactory) {
	prov := &providertest.ConfigurableProvider{
		ValidateErr: vault.ErrProviderValidation,
	}
	b := factory(t, strictRegistry(prov))

	_, err := b.Service.CreateCredential(
		context.Background(), uuid.NewString(), "s3", "p",
		[]byte("anything"), vault.Metadata{"region": "us-west-1"},
	)
	if !errors.Is(err, vault.ErrProviderValidation) {
		t.Errorf("CreateCredential err = %v, want ErrProviderValidation", err)
	}
}

func runCreateRejectsOnUnknownProvider(t *testing.T, factory ProviderFactory) {
	// Empty strict registry — Get("s3") returns ErrProviderUnknown.
	b := factory(t, vault.NewProviderRegistry())

	_, err := b.Service.CreateCredential(
		context.Background(), uuid.NewString(), "s3", "p",
		[]byte("x"), vault.Metadata{"region": "us-west-1"},
	)
	if !errors.Is(err, vault.ErrProviderUnknown) {
		t.Errorf("CreateCredential err = %v, want ErrProviderUnknown", err)
	}
}

func runReplaceValidatesProvider(t *testing.T, factory ProviderFactory) {
	prov := &providertest.ConfigurableProvider{}
	b := factory(t, strictRegistry(prov))

	userID := uuid.NewString()
	id, err := b.Service.CreateCredential(
		context.Background(), userID, "s3", "p",
		[]byte("v1"), vault.Metadata{"region": "us-west-1"},
	)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	callsAfterCreate := prov.ValidateCalls

	if err := b.Service.ReplaceCredential(
		context.Background(), userID, id, []byte("v2"), vault.Metadata{"region": "us-west-2"},
	); err != nil {
		t.Fatalf("Replace: %v", err)
	}
	if prov.ValidateCalls != callsAfterCreate+1 {
		t.Errorf("Replace Validate calls delta = %d, want 1", prov.ValidateCalls-callsAfterCreate)
	}
	if string(prov.ValidateLastSecret) != "v2" {
		t.Errorf("Validate received %q on Replace, want v2", prov.ValidateLastSecret)
	}
}

func runReplaceRejectsOnValidationFailure(t *testing.T, factory ProviderFactory) {
	prov := &providertest.ConfigurableProvider{}
	b := factory(t, strictRegistry(prov))

	userID := uuid.NewString()
	id, err := b.Service.CreateCredential(
		context.Background(), userID, "s3", "p",
		[]byte("v1"), vault.Metadata{"region": "us-west-1"},
	)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	// Flip the provider to rejecting before Replace.
	prov.ValidateErr = vault.ErrProviderValidation
	err = b.Service.ReplaceCredential(
		context.Background(), userID, id, []byte("v2"), vault.Metadata{"region": "us-west-1"},
	)
	if !errors.Is(err, vault.ErrProviderValidation) {
		t.Errorf("Replace err = %v, want ErrProviderValidation", err)
	}

	// The original row must be untouched. Decrypting via the bundle
	// must still yield v1, not v2.
	got, err := decryptCredential(context.Background(), b, userID, id)
	if err != nil {
		t.Fatalf("decrypt after rejected Replace: %v", err)
	}
	if string(got) != "v1" {
		t.Errorf("post-rejected-Replace plaintext = %q, want v1 (Replace must be a no-op on validation failure)", got)
	}
}

func runValidationFailureDoesNotPersist(t *testing.T, factory ProviderFactory) {
	prov := &providertest.ConfigurableProvider{
		ValidateErr: vault.ErrProviderValidation,
	}
	b := factory(t, strictRegistry(prov))

	userID := uuid.NewString()
	_, err := b.Service.CreateCredential(
		context.Background(), userID, "s3", "p",
		[]byte("x"), vault.Metadata{"region": "us-west-1"},
	)
	if !errors.Is(err, vault.ErrProviderValidation) {
		t.Fatalf("CreateCredential err = %v, want ErrProviderValidation", err)
	}

	// No credential rows for the user.
	summaries, err := b.Service.ListCredentials(context.Background(), userID)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(summaries) != 0 {
		t.Errorf("List returned %d summaries after rejected Create, want 0 (Validate failure must gate persistence)", len(summaries))
	}
}
