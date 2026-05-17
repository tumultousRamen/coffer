// Package portcontract holds the reference-contract test suites that
// every CredentialStore and TenantStore implementation must satisfy.
//
// Adapter equivalence is the load-bearing property of the hexagonal
// architecture (ADR 0010). These suites turn that promise into a CI
// property: any behavioral divergence between memstore and the
// Postgres adapter (or any future adapter) is a hard test failure.
//
// Usage from an adapter's test package:
//
//	func TestMyAdapter_CredentialStoreContract(t *testing.T) {
//	    portcontract.RunCredentialStoreContract(t, func(t *testing.T) portcontract.StoreBundle {
//	        // build and return a fresh, isolated bundle per call
//	    })
//	}
package portcontract

import (
	"testing"

	"github.com/tumultousRamen/coffer/internal/vault"
)

// StoreBundle pairs the two stores a contract scenario may need.
// Scenarios that exercise CredentialStore.Create against the FK
// require a working TenantStore to call PutEncryptedDEK first.
type StoreBundle struct {
	Credentials vault.CredentialStore
	Tenants     vault.TenantStore
}

// Factory returns a fresh, isolated StoreBundle on each call. The
// factory is responsible for any per-test setup (e.g., TRUNCATE for
// the Postgres adapter) and may register t.Cleanup hooks.
type Factory func(t *testing.T) StoreBundle
