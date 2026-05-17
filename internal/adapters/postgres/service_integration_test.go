//go:build integration

package postgres_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"

	"github.com/tumultousRamen/coffer/internal/adapters/postgres"
	"github.com/tumultousRamen/coffer/internal/vault"
	"github.com/tumultousRamen/coffer/internal/vault/servicecontract"
)

func TestPostgres_ServiceContract(t *testing.T) {
	servicecontract.RunServiceContract(t, func(t *testing.T) servicecontract.Bundle {
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
			Service:     vault.NewService(store, tenants, cryptor, verifier),
			Tenants:     tenants,
			Store:       store,
			Cryptor:     cryptor,
			KMS:         km,
			GrantSigner: priv,
		}
	})
}
