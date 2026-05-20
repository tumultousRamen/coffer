// Package dropbox implements vault.Provider for Dropbox in broker mode
// per ADR 0001. The vault holds the user's refresh_token and mints
// fresh access_tokens on demand via Dropbox's /token endpoint.
//
// Dropbox specifics: refresh tokens are issued via the
// token_access_type=offline grant during the initial authorization
// code flow (out-of-band per PRD 0010 §Out of Scope). The /token
// endpoint NEVER rotates the refresh_token on refresh — the response
// only carries a new access_token + expiry. Default access_token TTL
// is 14400 seconds (4h).
//
// Hexagonal discipline: this package imports internal/vault and the
// shared oauth2 client. The Service is the only consumer; the REST
// transport never imports this package directly.
package dropbox

import (
	"context"
	"time"

	"github.com/tumultousRamen/coffer/internal/adapters/providers/oauth2"
	"github.com/tumultousRamen/coffer/internal/vault"
)

// Endpoint is Dropbox's OAuth2 token endpoint per the developer docs
// (lookup 2026-05-20). The host is api.dropbox.com — NOT www.dropbox.com
// (which serves the consumer site) and NOT api.dropboxapi.com (which
// serves the Files / Sharing APIs once you have an access_token).
const Endpoint = "https://api.dropbox.com/oauth2/token"

// Provider implements vault.Provider for Dropbox.
type Provider struct {
	client *oauth2.Client
	now    func() time.Time
}

// New builds a Provider with the supplied app credentials. clientID and
// clientSecret come from the COFFER_DROPBOX_CLIENT_ID /
// COFFER_DROPBOX_CLIENT_SECRET env vars wired in cmd/vault/main.go.
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

// NeedsScheduledRefresh returns true — Dropbox access tokens expire on
// a fixed cadence (default 4h) and the refresh worker (PRD 0011) plus
// the sync-on-stale path (PRD 0010 §4) keep them current.
func (p *Provider) NeedsScheduledRefresh() bool { return true }

// Refresh exchanges the persisted refresh_token for a fresh access_token
// and returns an updated Credential carrying the new secret JSON and a
// metadata stamp for access_token_expires_at. Errors are raw oauth2
// sentinels (ErrInvalidGrant / ErrTransient); the Service translates
// them based on call-site context (Create/Replace vs FetchForWorker).
func (p *Provider) Refresh(ctx context.Context, c vault.Credential) (vault.Credential, error) {
	return oauth2.RefreshCredential(ctx, p.client, c, p.now)
}

// Validate performs a payload-shape check only. The actual provider
// probe at Create/Replace time happens via Refresh, which the Service
// invokes for broker-mode providers (NeedsScheduledRefresh()==true).
func (p *Provider) Validate(_ context.Context, secret vault.SecretBlob, _ vault.Metadata) error {
	return oauth2.ValidatePayloadShape(secret)
}

var _ vault.Provider = (*Provider)(nil)
