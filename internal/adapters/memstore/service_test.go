package memstore

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"

	"github.com/tumultousRamen/coffer/internal/vault"
	"github.com/tumultousRamen/coffer/internal/vault/providertest"
	"github.com/tumultousRamen/coffer/internal/vault/servicecontract"
)

func TestMemstore_ServiceContract(t *testing.T) {
	servicecontract.RunServiceContract(t, func(t *testing.T) servicecontract.Bundle {
		return newMemstoreBundle(t, providertest.PermissiveRegistry())
	})
}

// TestMemstore_ProviderScenarios exercises the provider-aware Service
// scenarios (Validate is called on Create / Replace; failures gate
// persistence; unknown providers are rejected). Same backend wiring
// as the service-contract suite; only the ProviderLookup varies.
func TestMemstore_ProviderScenarios(t *testing.T) {
	servicecontract.RunProviderScenarios(t, func(t *testing.T, lookup vault.ProviderLookup) servicecontract.Bundle {
		return newMemstoreBundle(t, lookup)
	})
}

func newMemstoreBundle(t *testing.T, lookup vault.ProviderLookup) servicecontract.Bundle {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey: %v", err)
	}
	verifier := vault.NewGrantVerifier(pub)

	km := servicecontract.NewCountingKeyManager()
	cache := vault.NewDEKCache(64, time.Minute)
	cryptor := vault.NewCryptor(km, cache)

	tenants := NewTenantStore()
	store := NewWithTenants(tenants)

	return servicecontract.Bundle{
		Service:     vault.NewService(store, tenants, cryptor, verifier, lookup),
		Tenants:     tenants,
		Store:       store,
		Cryptor:     cryptor,
		KMS:         km,
		GrantSigner: priv,
	}
}
