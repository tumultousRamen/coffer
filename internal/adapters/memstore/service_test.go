package memstore

import (
	"testing"
	"time"

	"github.com/tumultousRamen/coffer/internal/vault"
	"github.com/tumultousRamen/coffer/internal/vault/servicecontract"
)

func TestMemstore_ServiceContract(t *testing.T) {
	servicecontract.RunServiceContract(t, func(t *testing.T) servicecontract.Bundle {
		km := servicecontract.NewCountingKeyManager()
		cache := vault.NewDEKCache(64, time.Minute)
		cryptor := vault.NewCryptor(km, cache)

		tenants := NewTenantStore()
		store := NewWithTenants(tenants)

		return servicecontract.Bundle{
			Service: vault.NewService(store, tenants, cryptor),
			Tenants: tenants,
			Store:   store,
			Cryptor: cryptor,
			KMS:     km,
		}
	})
}
