// Package vault — ProviderLookup is the composition seam between the
// Service and the set of registered Provider implementations
// (S3, Dropbox, Google Drive, …). ADR 0006 and ADR 0010 §1 anchor
// the provider port; this file is the discovery shape that wires
// concrete providers into Create / Replace.
//
// Two types live here, paired on purpose:
//
//   - ProviderLookup is the small interface the Service consumes. It
//     has one method (Get). Tests substitute a catch-all double; the
//     Service does not depend on the concrete registry type.
//   - ProviderRegistry is the production strict-map implementation.
//     Get on an unknown name returns ErrProviderUnknown, surfaced as
//     HTTP 400 by the REST transport.
//
// Composition is one-line per provider in cmd/vault/main.go:
//
//	providers := vault.NewProviderRegistry()
//	providers.Register("s3", s3.New())
package vault

import "sync"

// ProviderLookup is the read-side of the registry. The Service depends
// on this small interface, not on *ProviderRegistry, so tests can
// substitute a catch-all permissive lookup without depending on the
// strict-map semantics.
type ProviderLookup interface {
	Get(name string) (Provider, error)
}

// ProviderRegistry is the production strict-map ProviderLookup.
// Register / Get are O(1) under an RWMutex; Register takes the write
// lock, Get takes the read lock. The zero value is not usable;
// construct with NewProviderRegistry.
type ProviderRegistry struct {
	mu        sync.RWMutex
	providers map[string]Provider
}

// NewProviderRegistry constructs an empty registry. Callers (the
// composition root) Register providers at boot, before the Service
// is wired.
func NewProviderRegistry() *ProviderRegistry {
	return &ProviderRegistry{providers: make(map[string]Provider)}
}

// Register binds name → provider. A second Register for the same name
// silently overwrites — composition roots register each provider
// exactly once; programmer error at boot is preferable to a runtime
// panic that hides which call site is at fault.
func (r *ProviderRegistry) Register(name string, p Provider) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.providers[name] = p
}

// Get returns the provider bound to name, or ErrProviderUnknown if no
// provider was registered under that name. The REST transport maps
// ErrProviderUnknown to 400 with a clear "unknown provider" body so
// the caller learns at registration time.
func (r *ProviderRegistry) Get(name string) (Provider, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	p, ok := r.providers[name]
	if !ok {
		return nil, ErrProviderUnknown
	}
	return p, nil
}

// Compile-time guarantee that the strict-map registry satisfies the
// ProviderLookup contract.
var _ ProviderLookup = (*ProviderRegistry)(nil)
