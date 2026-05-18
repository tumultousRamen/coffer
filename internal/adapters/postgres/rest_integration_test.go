//go:build integration

package postgres_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"

	"github.com/tumultousRamen/coffer/internal/adapters/postgres"
	"github.com/tumultousRamen/coffer/internal/transport/rest/restcontract"
	"github.com/tumultousRamen/coffer/internal/vault"
	"github.com/tumultousRamen/coffer/internal/vault/providertest"
	"github.com/tumultousRamen/coffer/internal/vault/servicecontract"
)

// TestPostgres_RESTContract drives the REST behavior contract against
// the Postgres-backed Service through a real httptest.Server. Stacks
// on top of TestPostgres_ServiceContract to verify the
// REST-handler↔Service↔PG composition end-to-end.
func TestPostgres_RESTContract(t *testing.T) {
	restcontract.RunRESTContract(t, func(t *testing.T) restcontract.Bundle {
		db := openTestDB(t)
		resetTables(t, db)

		pub, _, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatalf("ed25519.GenerateKey: %v", err)
		}
		verifier := vault.NewGrantVerifier(pub)

		km := servicecontract.NewCountingKeyManager()
		cache := vault.NewDEKCache(64, time.Minute)
		cryptor := vault.NewCryptor(km, cache)

		tenants := postgres.NewTenantStore(db)
		store := postgres.NewCredentialStore(db)
		svc := vault.NewService(store, tenants, cryptor, verifier, providertest.PermissiveRegistry())

		return restcontract.NewBundleFromService(t, svc)
	})
}
