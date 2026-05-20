// Package box implements vault.Provider for Box in broker mode per
// ADR 0001. The vault holds the user's refresh_token and mints fresh
// access_tokens on demand via Box's /token endpoint.
//
// Box specifics — LOAD-BEARING per PRD 0010 §4:
//
//   - Box ALWAYS rotates the refresh_token on every refresh call.
//     Single-use refresh tokens; the old one is invalid the moment Box
//     issues the new one. If the vault loses the new token (e.g. the
//     storage Replace fails), the credential is bricked — the user must
//     re-authorize from scratch.
//
//   - Concurrent refresh against Box invalidates the loser's token.
//     The Service's single-flight wrapper at FetchForWorker (PRD 0010
//     §4) is what prevents this; if you bypass it, expect bricked
//     credentials.
//
// Default access_token TTL is 3600 seconds (1h). The rotation discipline
// is documented inline at every Box-handling call site by intent.
package box

import (
	"context"
	"time"

	"github.com/tumultousRamen/coffer/internal/adapters/providers/oauth2"
	"github.com/tumultousRamen/coffer/internal/vault"
)

// Endpoint is Box's OAuth2 token endpoint per the Box developer
// reference (lookup 2026-05-20). The host is api.box.com.
const Endpoint = "https://api.box.com/oauth2/token"

// Provider implements vault.Provider for Box.
type Provider struct {
	client *oauth2.Client
	now    func() time.Time
}

// New builds a Provider with the supplied app credentials. clientID and
// clientSecret come from the COFFER_BOX_CLIENT_ID /
// COFFER_BOX_CLIENT_SECRET env vars wired in cmd/vault/main.go.
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

// NeedsScheduledRefresh returns true — Box access tokens expire after
// ~1h and the refresh worker plus sync-on-stale path keep them current.
func (p *Provider) NeedsScheduledRefresh() bool { return true }

// Refresh exchanges the persisted refresh_token for a fresh access_token
// AND a new refresh_token (Box's mandatory rotation). The shared helper
// writes the rotated value into the returned Credential's secret payload
// atomically; the Service then Replaces the row in one UPDATE statement.
// If anything between this call returning and the Replace landing
// fails, the credential is bricked — PRD 0010 §4 acknowledges this as
// the sole correctness boundary for Box rotation, mitigated via
// single-flight + observability.
func (p *Provider) Refresh(ctx context.Context, c vault.Credential) (vault.Credential, error) {
	return oauth2.RefreshCredential(ctx, p.client, c, p.now)
}

// Validate performs a payload-shape check only. The actual provider
// probe at Create/Replace time happens via Refresh, which the Service
// invokes for broker-mode providers — and for Box specifically the
// Refresh call rotates the refresh_token, so the Service MUST persist
// the result of the create-time probe rather than just discarding the
// returned access_token (per PRD 0010 §Implementation Decisions option c).
func (p *Provider) Validate(_ context.Context, secret vault.SecretBlob, _ vault.Metadata) error {
	return oauth2.ValidatePayloadShape(secret)
}

var _ vault.Provider = (*Provider)(nil)
