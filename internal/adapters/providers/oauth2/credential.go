package oauth2

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/tumultousRamen/coffer/internal/vault"
)

// SecretPayload is the wire shape of the plaintext secret blob for an
// OAuth credential. All three providers (Dropbox, Google Drive, Box)
// share this exact schema — provider-specific quirks live in error
// classification and endpoint URLs, not in the on-row payload.
//
// AccessToken is the most recently minted access token, cached so the
// first FetchForWorker after Create can serve without a refresh
// round-trip. access_token_expires_at lives in vault.Metadata under
// vault.MetadataKeyAccessTokenExpiresAt (not in this payload) so the
// sync-on-stale check at FetchForWorker can read expiry without
// decrypting the row.
type SecretPayload struct {
	RefreshToken string `json:"refresh_token"`
	AccessToken  string `json:"access_token,omitempty"`
}

// RefreshCredential is the shared per-provider refresh routine. Given
// a vault.Credential whose Secret is plaintext JSON in the SecretPayload
// shape, it calls client.Refresh, persists any rotated refresh_token
// (load-bearing for Box per PRD 0010 §4), caches the new access_token,
// and stamps the absolute expiry on Metadata. Returns an updated
// Credential ready for atomic persistence.
//
// Error mapping is intentionally NOT performed here — the caller (the
// per-provider package, or the Service when it invokes Provider.Refresh
// directly) is the right place to decide whether ErrInvalidGrant becomes
// vault.ErrProviderValidation (Create/Replace path) or status=failed
// (FetchForWorker sync-on-stale path).
//
// now is injected so tests can pin Metadata's expires_at value
// deterministically; production passes time.Now.
func RefreshCredential(
	ctx context.Context,
	client *Client,
	c vault.Credential,
	now func() time.Time,
) (vault.Credential, error) {
	var payload SecretPayload
	if err := json.Unmarshal(c.Secret.Reveal(), &payload); err != nil {
		return vault.Credential{}, fmt.Errorf("oauth2: parse secret payload: %w", err)
	}
	if payload.RefreshToken == "" {
		// Missing refresh_token is a user-side validation failure
		// rather than a provider rejection — there's nothing to send
		// to the /token endpoint. Wrap as permanent so the caller
		// treats it as terminal (matches the "credential cannot be
		// used" semantic). wrapPermanent threads both vault and
		// oauth2 sentinels through errors.Is.
		return vault.Credential{}, wrapPermanent(errors.New("secret missing refresh_token"))
	}

	tr, err := client.Refresh(ctx, payload.RefreshToken)
	if err != nil {
		return vault.Credential{}, err
	}

	newPayload := SecretPayload{
		RefreshToken: payload.RefreshToken,
		AccessToken:  tr.AccessToken,
	}
	if tr.IsRefreshTokenRotated() {
		// Atomic rotation: the new refresh_token MUST land in the
		// returned Credential, which the Service then persists
		// transactionally. Failure to overwrite here is the Box
		// rotation-bricking failure mode flagged in PRD 0010 §4.
		newPayload.RefreshToken = tr.RefreshToken
	}

	payloadBytes, err := json.Marshal(newPayload)
	if err != nil {
		return vault.Credential{}, fmt.Errorf("oauth2: marshal updated payload: %w", err)
	}

	// Copy metadata before mutation so we don't bash a caller-owned map.
	md := vault.Metadata{}
	for k, v := range c.Metadata {
		md[k] = v
	}
	md[vault.MetadataKeyAccessTokenExpiresAt] = tr.AccessTokenExpiresAt(now()).UTC().Format(time.RFC3339)

	return vault.Credential{
		ID:         c.ID,
		Provider:   c.Provider,
		Label:      c.Label,
		Secret:     vault.NewSecretBlob(payloadBytes),
		Metadata:   md,
		Nonce:      c.Nonce,      // preserved; service may re-encrypt with fresh nonce on persist
		DEKVersion: c.DEKVersion, // preserved
	}, nil
}

// ValidatePayloadShape is the create/replace-time payload sanity check
// used when the Service's Validate path is invoked on an OAuth provider.
// It confirms refresh_token is present without making a network call —
// the actual provider probe happens via Refresh, which the Service
// invokes separately for broker-mode providers.
func ValidatePayloadShape(secret vault.SecretBlob) error {
	var payload SecretPayload
	if err := json.Unmarshal(secret.Reveal(), &payload); err != nil {
		return fmt.Errorf("%w: secret is not valid JSON: %v", vault.ErrProviderValidation, err)
	}
	if payload.RefreshToken == "" {
		return fmt.Errorf("%w: refresh_token missing from secret", vault.ErrProviderValidation)
	}
	return nil
}

