// Package servicecontract holds the reference-contract test suite for
// vault.Service. The same scenarios must pass against every storage
// backend (memstore offline, Postgres under the `integration` build
// tag). Adapter-equivalence at the service-layer composition point is
// a CI property in the same shape as portcontract enforces it at the
// storage-port level.
//
// Usage from an adapter's test package:
//
//	func TestMyAdapter_ServiceContract(t *testing.T) {
//	    servicecontract.RunServiceContract(t, func(t *testing.T) servicecontract.Bundle {
//	        // build the storage adapters, wire them into a Service, return
//	    })
//	}
package servicecontract

import (
	"testing"

	"github.com/tumultousRamen/coffer/internal/vault"
)

// Bundle holds the moving parts a scenario may need. Factories build
// a fresh, isolated Bundle per scenario.
//
//   - Service is the unit under test.
//   - Tenants and Store give scenarios direct read access so they
//     can verify side effects without going through the Service's
//     user-facing projections (e.g. read full Credentials including
//     ciphertext + nonce, count tenants rows post-race).
//   - Cryptor is the same instance the Service was built with; the
//     race-decryptability scenario uses it to verify each credential
//     round-trips end-to-end under the winning DEK.
//   - KMS exposes the counting KeyManager so scenarios can assert
//     "Provision was called exactly once across N creates".
type Bundle struct {
	Service *vault.Service
	Tenants vault.TenantStore
	Store   vault.CredentialStore
	Cryptor *vault.Cryptor
	KMS     *CountingKeyManager
}

// Factory returns a fresh, isolated Bundle on each call. It is
// responsible for any per-test setup (e.g., TRUNCATE for the Postgres
// adapter) and may register t.Cleanup hooks.
type Factory func(t *testing.T) Bundle
