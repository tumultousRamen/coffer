// Package gdrive implements vault.Provider for Google Drive in broker
// mode per ADR 0001. The vault holds the user's refresh_token and
// mints fresh access_tokens on demand via Google's /token endpoint.
//
// Google specifics: the /token endpoint USUALLY returns the same
// refresh_token (no rotation) but MAY return a new one — undocumented
// conditions, plus the 100-token-per-client cap can silently invalidate
// the oldest refresh_token when a new authorization happens. Always
// honor IsRefreshTokenRotated() defensively. Default access_token TTL
// is 3599 seconds (~1h).
//
// Concurrent refreshes against Google explicitly fail with
// invalid_grant — see PRD 0010 §1 single-flight invariant.
package gdrive

import (
	"context"
	"time"

	"github.com/tumultousRamen/coffer/internal/adapters/providers/oauth2"
	"github.com/tumultousRamen/coffer/internal/vault"
)

// Endpoint is Google's OAuth2 token endpoint per Google Identity
// Platform docs (lookup 2026-05-20). Distinct from accounts.google.com
// which serves the authorization endpoint.
const Endpoint = "https://oauth2.googleapis.com/token"

// Provider implements vault.Provider for Google Drive.
type Provider struct {
	client *oauth2.Client
	now    func() time.Time
}

// New builds a Provider with the supplied app credentials. clientID and
// clientSecret come from the COFFER_GDRIVE_CLIENT_ID /
// COFFER_GDRIVE_CLIENT_SECRET env vars wired in cmd/vault/main.go.
func New(clientID, clientSecret string) *Provider {
	return &Provider{
		client: oauth2.NewClient(Endpoint, clientID, clientSecret),
		now:    time.Now,
	}
}

// NewWithClient is the test-friendly constructor; production uses New.
func NewWithClient(client *oauth2.Client, now func() time.Time) *Provider {
	return &Provider{client: client, now: now}
}

// NeedsScheduledRefresh returns true — Google access tokens expire on
// a fixed cadence (default ~1h).
func (p *Provider) NeedsScheduledRefresh() bool { return true }

// Refresh exchanges the persisted refresh_token for a fresh access_token.
// If Google returned a rotated refresh_token (uncommon but contractually
// allowed), the helper writes it back to the secret payload atomically.
func (p *Provider) Refresh(ctx context.Context, c vault.Credential) (vault.Credential, error) {
	return oauth2.RefreshCredential(ctx, p.client, c, p.now)
}

// Validate performs a payload-shape check only. The actual provider
// probe at Create/Replace time happens via Refresh.
func (p *Provider) Validate(_ context.Context, secret vault.SecretBlob, _ vault.Metadata) error {
	return oauth2.ValidatePayloadShape(secret)
}

var _ vault.Provider = (*Provider)(nil)
