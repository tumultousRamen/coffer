package memstore

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"

	"github.com/tumultousRamen/coffer/internal/transport/rest/restcontract"
	"github.com/tumultousRamen/coffer/internal/vault"
	"github.com/tumultousRamen/coffer/internal/vault/providertest"
	"github.com/tumultousRamen/coffer/internal/vault/servicecontract"
)

// TestMemstore_RESTContract drives the REST behavior contract against
// the memstore-backed Service. Mirrors TestMemstore_ServiceContract;
// the two suites stack the verification chain at different layers
// (Service-direct vs through-the-HTTP-handler).
func TestMemstore_RESTContract(t *testing.T) {
	restcontract.RunRESTContract(t, func(t *testing.T) restcontract.Bundle {
		pub, _, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatalf("ed25519.GenerateKey: %v", err)
		}
		verifier := vault.NewGrantVerifier(pub)

		km := servicecontract.NewCountingKeyManager()
		cache := vault.NewDEKCache(64, time.Minute)
		cryptor := vault.NewCryptor(km, cache)

		tenants := NewTenantStore()
		store := NewWithTenants(tenants)
		svc := vault.NewService(store, tenants, cryptor, verifier, providertest.PermissiveRegistry())

		return restcontract.NewBundleFromService(t, svc)
	})
}
