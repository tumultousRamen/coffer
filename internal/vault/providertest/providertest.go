// Package providertest holds test doubles for the vault.Provider /
// vault.ProviderLookup ports. Two doubles live here:
//
//   - PermissiveProvider — Validate always returns nil, Refresh is a
//     no-op, NeedsScheduledRefresh returns false. Used by Service-tier
//     scenarios that aren't testing validation behavior (PRD 0005's
//     servicecontract suite, REST/gRPC handler tests).
//   - ConfigurableProvider — public fields let a scenario program
//     specific Validate / Refresh behavior per case.
//
// The package also exposes PermissiveRegistry: a catch-all
// ProviderLookup whose Get always returns a PermissiveProvider
// regardless of name. This lets tests reference arbitrary provider
// strings ("s3", "dropbox", "test-provider") without registering
// each one.
package providertest

import (
	"context"

	"github.com/tumultousRamen/coffer/internal/vault"
)

// PermissiveProvider is a no-op vault.Provider for tests that do not
// exercise validation. Every method succeeds; Refresh returns the
// credential unchanged.
type PermissiveProvider struct{}

// NeedsScheduledRefresh returns false — matches the secret-store mode
// per ADR 0001, which is what the existing service tests assume.
func (PermissiveProvider) NeedsScheduledRefresh() bool { return false }

// Validate accepts any input.
func (PermissiveProvider) Validate(_ context.Context, _ vault.SecretBlob, _ vault.Metadata) error {
	return nil
}

// Refresh returns the credential unchanged.
func (PermissiveProvider) Refresh(_ context.Context, c vault.Credential) (vault.Credential, error) {
	return c, nil
}

// ConfigurableProvider is a test double whose behavior is set by
// public fields. Scenarios assign per-case and pass it to whichever
// registry/lookup the test uses.
type ConfigurableProvider struct {
	NeedsScheduledRefreshValue bool
	ValidateErr                error
	RefreshFunc                func(ctx context.Context, c vault.Credential) (vault.Credential, error)

	// ValidateCalls and ValidateLastSecret let scenarios assert that
	// the Service did (or did not) call Validate, and on which
	// payload. Not thread-safe — scenarios run single-threaded.
	ValidateCalls      int
	ValidateLastSecret []byte
}

// NeedsScheduledRefresh returns the configured value (default false).
func (c *ConfigurableProvider) NeedsScheduledRefresh() bool {
	return c.NeedsScheduledRefreshValue
}

// Validate increments the call counter, records the secret bytes,
// and returns the configured error.
func (c *ConfigurableProvider) Validate(_ context.Context, secret vault.SecretBlob, _ vault.Metadata) error {
	c.ValidateCalls++
	rev := secret.Reveal()
	c.ValidateLastSecret = make([]byte, len(rev))
	copy(c.ValidateLastSecret, rev)
	return c.ValidateErr
}

// Refresh delegates to RefreshFunc if set; otherwise returns c unchanged.
func (c *ConfigurableProvider) Refresh(ctx context.Context, cred vault.Credential) (vault.Credential, error) {
	if c.RefreshFunc != nil {
		return c.RefreshFunc(ctx, cred)
	}
	return cred, nil
}

// catchAllLookup is the ProviderLookup whose Get always returns a
// PermissiveProvider regardless of name. Lets existing scenarios
// reference arbitrary provider strings without registering each one.
type catchAllLookup struct{}

func (catchAllLookup) Get(_ string) (vault.Provider, error) {
	return PermissiveProvider{}, nil
}

// PermissiveRegistry returns a catch-all ProviderLookup: every Get
// returns a PermissiveProvider, never ErrProviderUnknown. Use for
// tests that exercise the rest of the Service (storage, encryption,
// grant verification) but do not care about provider semantics.
//
// Tests that DO care about provider semantics should build a strict
// vault.NewProviderRegistry directly and register a
// ConfigurableProvider under the names they exercise.
func PermissiveRegistry() vault.ProviderLookup {
	return catchAllLookup{}
}

// FakeOAuthProvider is a test double that simulates an OAuth broker
// provider: NeedsScheduledRefresh returns true, Validate does a basic
// payload-shape check, and Refresh is driven by the caller-supplied
// RefreshFunc so each scenario can program the exact response shape
// (success with rotation, success without rotation, ErrInvalidGrant,
// ErrTransient). Used by the PRD 0010 OAuth service-contract scenarios.
//
// Refresh and RefreshCalls are not thread-safe by default — scenarios
// that exercise concurrency (single-flight) protect access with a
// sync.Mutex via the safe-counter pattern; see oauth_scenarios.go.
type FakeOAuthProvider struct {
	RefreshFunc  func(ctx context.Context, c vault.Credential) (vault.Credential, error)
	ValidateErr  error
	RefreshCalls int
}

func (f *FakeOAuthProvider) NeedsScheduledRefresh() bool { return true }

func (f *FakeOAuthProvider) Validate(_ context.Context, _ vault.SecretBlob, _ vault.Metadata) error {
	return f.ValidateErr
}

func (f *FakeOAuthProvider) Refresh(ctx context.Context, c vault.Credential) (vault.Credential, error) {
	f.RefreshCalls++
	if f.RefreshFunc != nil {
		return f.RefreshFunc(ctx, c)
	}
	return c, nil
}

// Compile-time guarantees.
var (
	_ vault.Provider       = PermissiveProvider{}
	_ vault.Provider       = (*ConfigurableProvider)(nil)
	_ vault.Provider       = (*FakeOAuthProvider)(nil)
	_ vault.ProviderLookup = catchAllLookup{}
)
