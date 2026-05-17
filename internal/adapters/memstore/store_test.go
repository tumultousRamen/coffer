package memstore

import (
	"testing"

	"github.com/tumultousRamen/coffer/internal/vault"
	"github.com/tumultousRamen/coffer/internal/vault/portcontract"
)

// Compile-time guards — fail to build if memstore drifts from either
// port surface.
var (
	_ vault.CredentialStore = (*Store)(nil)
	_ vault.TenantStore     = (*TenantStore)(nil)
)

func TestMemstore_CredentialStoreContract(t *testing.T) {
	portcontract.RunCredentialStoreContract(t, func(t *testing.T) portcontract.StoreBundle {
		ts := NewTenantStore()
		return portcontract.StoreBundle{
			Credentials: NewWithTenants(ts),
			Tenants:     ts,
		}
	})
}

func TestMemstore_TenantStoreContract(t *testing.T) {
	portcontract.RunTenantStoreContract(t, func(t *testing.T) portcontract.StoreBundle {
		ts := NewTenantStore()
		return portcontract.StoreBundle{
			Credentials: NewWithTenants(ts),
			Tenants:     ts,
		}
	})
}
