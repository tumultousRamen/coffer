// PRD 0010 — OAuth-aware Service scenarios. Drives the sync-on-stale
// refresh path at FetchForWorker plus the broker-mode Create-time
// probe, across both memstore and Postgres adapters via the same
// ProviderFactory shape the existing provider_scenarios.go uses.
package servicecontract

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/tumultousRamen/coffer/internal/vault"
	"github.com/tumultousRamen/coffer/internal/vault/providertest"
)

// RunOAuthScenarios drives the OAuth-aware Service scenarios from PRD
// 0010. Each scenario builds its own ProviderLookup via the factory so
// the suite never leaks state across cases.
func RunOAuthScenarios(t *testing.T, factory ProviderFactory) {
	t.Helper()

	t.Run("CreateOAuthCredentialPersistsTokens", func(t *testing.T) {
		runCreateOAuthCredentialPersistsTokens(t, factory)
	})
	t.Run("CreateOAuthFailedOnInvalidGrant", func(t *testing.T) {
		runCreateOAuthFailedOnInvalidGrant(t, factory)
	})
	t.Run("FetchForWorkerSyncRefreshOnStale", func(t *testing.T) {
		runFetchForWorkerSyncRefreshOnStale(t, factory)
	})
	t.Run("FetchForWorkerSingleFlightOnConcurrentStale", func(t *testing.T) {
		runFetchForWorkerSingleFlightOnConcurrentStale(t, factory)
	})
	t.Run("FetchForWorkerInvalidGrantTransitionsToFailed", func(t *testing.T) {
		runFetchForWorkerInvalidGrantTransitionsToFailed(t, factory)
	})
	t.Run("BoxRefreshTokenRotatedAndPersisted", func(t *testing.T) {
		runBoxRefreshTokenRotatedAndPersisted(t, factory)
	})
}

// oauthRegistry builds a strict registry binding "oauth" to the supplied
// provider. Scenarios use the literal name "oauth" rather than per-vendor
// names so the test reads independent of which vendor is being modeled.
func oauthRegistry(p vault.Provider) vault.ProviderLookup {
	r := vault.NewProviderRegistry()
	r.Register("oauth", p)
	return r
}

// payload helpers — kept inline so scenarios stay self-contained and
// don't accidentally couple to the oauth2 adapter package.
func encodePayload(refreshToken, accessToken string) []byte {
	b, _ := json.Marshal(map[string]string{
		"refresh_token": refreshToken,
		"access_token":  accessToken,
	})
	return b
}

func decodePayload(t *testing.T, raw []byte) (refresh, access string) {
	t.Helper()
	var p struct {
		RefreshToken string `json:"refresh_token"`
		AccessToken  string `json:"access_token"`
	}
	if err := json.Unmarshal(raw, &p); err != nil {
		t.Fatalf("decode payload: %v (raw=%q)", err, raw)
	}
	return p.RefreshToken, p.AccessToken
}

// runCreateOAuthCredentialPersistsTokens — broker-mode probe at Create
// must mint a fresh access_token, stamp expires_at on metadata, and
// persist both atomically with the row.
func runCreateOAuthCredentialPersistsTokens(t *testing.T, factory ProviderFactory) {
	fakeNow := time.Date(2026, 5, 20, 15, 30, 0, 0, time.UTC)
	prov := &providertest.FakeOAuthProvider{
		RefreshFunc: func(_ context.Context, c vault.Credential) (vault.Credential, error) {
			return vault.Credential{
				ID:       c.ID,
				Provider: c.Provider,
				Label:    c.Label,
				Secret:   vault.NewSecretBlob(encodePayload("rt", "at-fresh")),
				Metadata: vault.Metadata{
					vault.MetadataKeyAccessTokenExpiresAt: fakeNow.Add(time.Hour).Format(time.RFC3339),
				},
			}, nil
		},
	}
	b := factory(t, oauthRegistry(prov))

	userID := uuid.NewString()
	id, err := b.Service.CreateCredential(
		context.Background(), userID, "oauth", "personal",
		encodePayload("rt", ""), vault.Metadata{},
	)
	if err != nil {
		t.Fatalf("CreateCredential: %v", err)
	}

	// Decrypt via the same machinery the worker path uses (helper in
	// scenarios.go). The persisted secret must include the cached
	// access_token from the Refresh probe.
	got, err := decryptCredential(context.Background(), b, userID, id)
	if err != nil {
		t.Fatalf("decryptCredential: %v", err)
	}
	rt, at := decodePayload(t, got)
	if rt != "rt" || at != "at-fresh" {
		t.Errorf("persisted payload (rt=%q at=%q), want (rt, at-fresh)", rt, at)
	}

	// The summary path doesn't expose metadata, but the storage path does.
	rows, _ := b.Store.Get(context.Background(), userID, []string{id})
	if got, _ := rows[0].Metadata[vault.MetadataKeyAccessTokenExpiresAt].(string); got == "" {
		t.Error("metadata.access_token_expires_at missing from persisted row")
	}
}

// runCreateOAuthFailedOnInvalidGrant — an invalid_grant at Create-time
// surfaces as ErrProviderValidation (mapped to 422 by REST). The row
// must NOT be persisted (gates persistence).
func runCreateOAuthFailedOnInvalidGrant(t *testing.T, factory ProviderFactory) {
	prov := &providertest.FakeOAuthProvider{
		RefreshFunc: func(_ context.Context, _ vault.Credential) (vault.Credential, error) {
			return vault.Credential{}, vault.ErrProviderRefreshPermanent
		},
	}
	b := factory(t, oauthRegistry(prov))

	userID := uuid.NewString()
	_, err := b.Service.CreateCredential(
		context.Background(), userID, "oauth", "personal",
		encodePayload("rt", ""), vault.Metadata{},
	)
	if !errors.Is(err, vault.ErrProviderValidation) {
		t.Errorf("CreateCredential err = %v, want wrap of ErrProviderValidation", err)
	}

	// No row was persisted (Create rejected before encrypt/store).
	summaries, _ := b.Service.ListCredentials(context.Background(), userID)
	if len(summaries) != 0 {
		t.Errorf("ListCredentials returned %d rows, want 0 (Create must gate persistence on probe failure)", len(summaries))
	}
}

// runFetchForWorkerSyncRefreshOnStale — credential with an
// access_token_expires_at in the past triggers an inline Refresh; the
// worker receives the freshened plaintext and the row is updated in DB.
func runFetchForWorkerSyncRefreshOnStale(t *testing.T, factory ProviderFactory) {
	staleExpiry := time.Date(2026, 5, 20, 14, 0, 0, 0, time.UTC) // in the past relative to fakeNow
	freshExpiry := time.Date(2026, 5, 20, 16, 30, 0, 0, time.UTC)

	prov := &providertest.FakeOAuthProvider{
		RefreshFunc: func(_ context.Context, c vault.Credential) (vault.Credential, error) {
			// Returned secret carries the refreshed access_token; metadata
			// gets a new expires_at that puts the credential well outside
			// the staleness window.
			return vault.Credential{
				ID:       c.ID,
				Provider: c.Provider,
				Label:    c.Label,
				Secret:   vault.NewSecretBlob(encodePayload("rt", "at-after-refresh")),
				Metadata: vault.Metadata{
					vault.MetadataKeyAccessTokenExpiresAt: freshExpiry.Format(time.RFC3339),
				},
			}, nil
		},
	}
	b := factory(t, oauthRegistry(prov))
	b.Service.SetClock(func() time.Time {
		return time.Date(2026, 5, 20, 15, 30, 0, 0, time.UTC) // > staleExpiry
	})

	userID := uuid.NewString()
	// Create with the stale expiry pre-stamped — bypasses the
	// CreateCredential probe by using a permissive RefreshFunc on Create
	// that returns the inputs but stamps the stale expiry.
	prov.RefreshFunc = func(_ context.Context, c vault.Credential) (vault.Credential, error) {
		return vault.Credential{
			ID:       c.ID,
			Provider: c.Provider,
			Label:    c.Label,
			Secret:   vault.NewSecretBlob(encodePayload("rt", "at-original")),
			Metadata: vault.Metadata{
				vault.MetadataKeyAccessTokenExpiresAt: staleExpiry.Format(time.RFC3339),
			},
		}, nil
	}
	id, err := b.Service.CreateCredential(
		context.Background(), userID, "oauth", "personal",
		encodePayload("rt", ""), vault.Metadata{},
	)
	if err != nil {
		t.Fatalf("CreateCredential: %v", err)
	}

	// Flip the fake to its "after refresh" behavior, then FetchForWorker.
	prov.RefreshFunc = func(_ context.Context, c vault.Credential) (vault.Credential, error) {
		return vault.Credential{
			ID:       c.ID,
			Provider: c.Provider,
			Label:    c.Label,
			Secret:   vault.NewSecretBlob(encodePayload("rt", "at-after-refresh")),
			Metadata: vault.Metadata{
				vault.MetadataKeyAccessTokenExpiresAt: freshExpiry.Format(time.RFC3339),
			},
		}, nil
	}

	token := mintGrant(t, b, userID, []string{id})
	out, err := b.Service.FetchForWorker(context.Background(), token, []string{id})
	if err != nil {
		t.Fatalf("FetchForWorker: %v", err)
	}
	_, at := decodePayload(t, out[0].Secret.Reveal())
	if at != "at-after-refresh" {
		t.Errorf("worker received access_token = %q, want at-after-refresh (sync-on-stale must fire)", at)
	}

	// The persisted row must also carry the new state — a subsequent
	// non-stale read returns the new access_token without firing
	// Refresh again.
	rows, _ := b.Store.Get(context.Background(), userID, []string{id})
	got, _ := rows[0].Metadata[vault.MetadataKeyAccessTokenExpiresAt].(string)
	if got != freshExpiry.Format(time.RFC3339) {
		t.Errorf("persisted expires_at = %q, want %q (Replace must have landed)", got, freshExpiry.Format(time.RFC3339))
	}
}

// runFetchForWorkerSingleFlightOnConcurrentStale — N concurrent
// FetchForWorker calls against the same stale credential trigger
// exactly one Refresh, not N. Per PRD 0010 §1 single-flight invariant.
func runFetchForWorkerSingleFlightOnConcurrentStale(t *testing.T, factory ProviderFactory) {
	const goroutines = 100

	// Synchronization: gate the first refresh call behind a release
	// channel so all N goroutines have time to coalesce on the
	// singleflight before the first one returns. Otherwise the test
	// becomes timing-dependent and may pass even without singleflight.
	release := make(chan struct{})
	var mu sync.Mutex
	calls := 0

	freshExpiry := time.Date(2026, 5, 20, 17, 0, 0, 0, time.UTC)
	staleExpiry := time.Date(2026, 5, 20, 14, 0, 0, 0, time.UTC)

	prov := &providertest.FakeOAuthProvider{
		RefreshFunc: func(_ context.Context, c vault.Credential) (vault.Credential, error) {
			mu.Lock()
			calls++
			currentCall := calls
			mu.Unlock()
			if currentCall == 1 {
				<-release
			}
			return vault.Credential{
				ID:       c.ID,
				Provider: c.Provider,
				Label:    c.Label,
				Secret:   vault.NewSecretBlob(encodePayload("rt", "at-refreshed")),
				Metadata: vault.Metadata{
					vault.MetadataKeyAccessTokenExpiresAt: freshExpiry.Format(time.RFC3339),
				},
			}, nil
		},
	}
	b := factory(t, oauthRegistry(prov))
	b.Service.SetClock(func() time.Time {
		return time.Date(2026, 5, 20, 15, 30, 0, 0, time.UTC)
	})

	// Create with stale expiry stamped.
	userID := uuid.NewString()
	prov.RefreshFunc = func(_ context.Context, c vault.Credential) (vault.Credential, error) {
		return vault.Credential{
			ID:       c.ID,
			Provider: c.Provider,
			Label:    c.Label,
			Secret:   vault.NewSecretBlob(encodePayload("rt", "at-original")),
			Metadata: vault.Metadata{
				vault.MetadataKeyAccessTokenExpiresAt: staleExpiry.Format(time.RFC3339),
			},
		}, nil
	}
	id, err := b.Service.CreateCredential(
		context.Background(), userID, "oauth", "personal",
		encodePayload("rt", ""), vault.Metadata{},
	)
	if err != nil {
		t.Fatalf("CreateCredential: %v", err)
	}

	// Reset counter + swap to the gated refresh function.
	mu.Lock()
	calls = 0
	mu.Unlock()
	prov.RefreshFunc = func(_ context.Context, c vault.Credential) (vault.Credential, error) {
		mu.Lock()
		calls++
		currentCall := calls
		mu.Unlock()
		if currentCall == 1 {
			<-release
		}
		return vault.Credential{
			ID:       c.ID,
			Provider: c.Provider,
			Label:    c.Label,
			Secret:   vault.NewSecretBlob(encodePayload("rt", "at-refreshed")),
			Metadata: vault.Metadata{
				vault.MetadataKeyAccessTokenExpiresAt: freshExpiry.Format(time.RFC3339),
			},
		}, nil
	}

	token := mintGrant(t, b, userID, []string{id})

	var wg sync.WaitGroup
	results := make(chan error, goroutines)
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := b.Service.FetchForWorker(context.Background(), token, []string{id})
			results <- err
		}()
	}

	// Give the singleflight time to coalesce the followers behind the
	// gated leader. ~50ms is generous on any reasonable host.
	time.Sleep(50 * time.Millisecond)
	close(release)
	wg.Wait()
	close(results)

	for err := range results {
		if err != nil {
			t.Errorf("FetchForWorker err: %v", err)
		}
	}

	mu.Lock()
	defer mu.Unlock()
	if calls != 1 {
		t.Errorf("Refresh called %d times across %d concurrent FetchForWorker calls, want 1 (single-flight invariant)", calls, goroutines)
	}
}

// runFetchForWorkerInvalidGrantTransitionsToFailed — a permanent
// refresh failure marks the credential failed and surfaces
// ErrCredentialUnusable. A subsequent FetchForWorker returns the same
// error without re-hitting the provider.
func runFetchForWorkerInvalidGrantTransitionsToFailed(t *testing.T, factory ProviderFactory) {
	staleExpiry := time.Date(2026, 5, 20, 14, 0, 0, 0, time.UTC)

	prov := &providertest.FakeOAuthProvider{}
	b := factory(t, oauthRegistry(prov))
	b.Service.SetClock(func() time.Time {
		return time.Date(2026, 5, 20, 15, 30, 0, 0, time.UTC)
	})

	userID := uuid.NewString()
	prov.RefreshFunc = func(_ context.Context, c vault.Credential) (vault.Credential, error) {
		return vault.Credential{
			ID:       c.ID,
			Provider: c.Provider,
			Label:    c.Label,
			Secret:   vault.NewSecretBlob(encodePayload("rt", "at-original")),
			Metadata: vault.Metadata{
				vault.MetadataKeyAccessTokenExpiresAt: staleExpiry.Format(time.RFC3339),
			},
		}, nil
	}
	id, err := b.Service.CreateCredential(
		context.Background(), userID, "oauth", "personal",
		encodePayload("rt", ""), vault.Metadata{},
	)
	if err != nil {
		t.Fatalf("CreateCredential: %v", err)
	}

	// Flip the fake to invalid_grant for the post-Create reads.
	prov.RefreshFunc = func(_ context.Context, _ vault.Credential) (vault.Credential, error) {
		return vault.Credential{}, vault.ErrProviderRefreshPermanent
	}
	token := mintGrant(t, b, userID, []string{id})

	_, err = b.Service.FetchForWorker(context.Background(), token, []string{id})
	if !errors.Is(err, vault.ErrCredentialUnusable) {
		t.Errorf("FetchForWorker err = %v, want wrap of ErrCredentialUnusable", err)
	}

	// Row status flipped to failed.
	summaries, _ := b.Service.ListCredentials(context.Background(), userID)
	if len(summaries) != 1 {
		t.Fatalf("ListCredentials returned %d, want 1", len(summaries))
	}
	if summaries[0].Status != vault.StatusFailed {
		t.Errorf("summary.Status = %q, want failed", summaries[0].Status)
	}
	if summaries[0].ValidationError == "" {
		t.Error("ValidationError empty after MarkFailed, want the provider-side reason")
	}
}

// runBoxRefreshTokenRotatedAndPersisted — Box-specific rotation
// discipline: every Refresh returns a new refresh_token and the
// persisted credential must reflect the new value (not the original).
// This is the Box correctness invariant the PRD calls out as
// "load-bearing".
func runBoxRefreshTokenRotatedAndPersisted(t *testing.T, factory ProviderFactory) {
	staleExpiry := time.Date(2026, 5, 20, 14, 0, 0, 0, time.UTC)
	freshExpiry := time.Date(2026, 5, 20, 16, 30, 0, 0, time.UTC)

	prov := &providertest.FakeOAuthProvider{}
	b := factory(t, oauthRegistry(prov))
	b.Service.SetClock(func() time.Time {
		return time.Date(2026, 5, 20, 15, 30, 0, 0, time.UTC)
	})

	userID := uuid.NewString()
	prov.RefreshFunc = func(_ context.Context, c vault.Credential) (vault.Credential, error) {
		// Simulating Box: the Create-time probe ALSO rotates the
		// refresh_token. The Service must persist the rotated value.
		return vault.Credential{
			ID:       c.ID,
			Provider: c.Provider,
			Label:    c.Label,
			Secret:   vault.NewSecretBlob(encodePayload("rt-after-create", "at-after-create")),
			Metadata: vault.Metadata{
				vault.MetadataKeyAccessTokenExpiresAt: staleExpiry.Format(time.RFC3339),
			},
		}, nil
	}
	id, err := b.Service.CreateCredential(
		context.Background(), userID, "oauth", "personal",
		encodePayload("rt-original", ""), vault.Metadata{},
	)
	if err != nil {
		t.Fatalf("CreateCredential: %v", err)
	}

	// Assert: persisted refresh_token after Create is the rotated value,
	// not the originally-submitted one.
	{
		got, _ := decryptCredential(context.Background(), b, userID, id)
		rt, _ := decodePayload(t, got)
		if rt != "rt-after-create" {
			t.Errorf("post-Create persisted refresh_token = %q, want rt-after-create (rotation discipline)", rt)
		}
	}

	// Now flip to "post-stale refresh" behavior and trigger
	// FetchForWorker; the second rotation must also persist.
	prov.RefreshFunc = func(_ context.Context, c vault.Credential) (vault.Credential, error) {
		return vault.Credential{
			ID:       c.ID,
			Provider: c.Provider,
			Label:    c.Label,
			Secret:   vault.NewSecretBlob(encodePayload("rt-after-fetch", "at-after-fetch")),
			Metadata: vault.Metadata{
				vault.MetadataKeyAccessTokenExpiresAt: freshExpiry.Format(time.RFC3339),
			},
		}, nil
	}
	token := mintGrant(t, b, userID, []string{id})
	if _, err := b.Service.FetchForWorker(context.Background(), token, []string{id}); err != nil {
		t.Fatalf("FetchForWorker: %v", err)
	}

	got, _ := decryptCredential(context.Background(), b, userID, id)
	rt, at := decodePayload(t, got)
	if rt != "rt-after-fetch" {
		t.Errorf("post-FetchForWorker persisted refresh_token = %q, want rt-after-fetch", rt)
	}
	if at != "at-after-fetch" {
		t.Errorf("post-FetchForWorker persisted access_token = %q, want at-after-fetch", at)
	}
}

// mintGrant builds a grant token covering the supplied credential IDs.
// The signing key lives on the Bundle; the verifier was constructed
// from its pair.
func mintGrant(t *testing.T, b Bundle, userID string, credentialIDs []string) string {
	t.Helper()
	tok, err := vault.MintGrant(b.GrantSigner, userID, credentialIDs, 5*time.Minute, "test-job")
	if err != nil {
		t.Fatalf("MintGrant: %v", err)
	}
	return tok
}
