//go:build integration

package postgres_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"

	"github.com/tumultousRamen/coffer/internal/adapters/postgres"
	"github.com/tumultousRamen/coffer/internal/vault"
	"github.com/tumultousRamen/coffer/internal/vault/providertest"
	"github.com/tumultousRamen/coffer/internal/vault/servicecontract"
)

func TestPostgres_ServiceContract(t *testing.T) {
	servicecontract.RunServiceContract(t, func(t *testing.T) servicecontract.Bundle {
		return newPostgresBundle(t, providertest.PermissiveRegistry())
	})
}

// TestPostgres_ProviderScenarios exercises the provider-aware Service
// scenarios against the Postgres adapter. The Postgres-backed
// "Validate failure does not persist" run is the strongest version of
// that scenario — failure on the wire path must leave the credentials
// table untouched.
func TestPostgres_ProviderScenarios(t *testing.T) {
	servicecontract.RunProviderScenarios(t, func(t *testing.T, lookup vault.ProviderLookup) servicecontract.Bundle {
		return newPostgresBundle(t, lookup)
	})
}

func newPostgresBundle(t *testing.T, lookup vault.ProviderLookup) servicecontract.Bundle {
	t.Helper()
	db := openTestDB(t)
	resetTables(t, db)

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey: %v", err)
	}
	verifier := vault.NewGrantVerifier(pub)

	km := servicecontract.NewCountingKeyManager()
	cache := vault.NewDEKCache(64, time.Minute)
	cryptor := vault.NewCryptor(km, cache)

	tenants := postgres.NewTenantStore(db)
	store := postgres.NewCredentialStore(db)

	return servicecontract.Bundle{
		Service:     vault.NewService(store, tenants, cryptor, verifier, lookup),
		Tenants:     tenants,
		Store:       store,
		Cryptor:     cryptor,
		KMS:         km,
		GrantSigner: priv,
	}
}
