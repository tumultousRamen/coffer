// Package oauth2 is the shared client three vault.Provider
// implementations (dropbox, gdrive, box) rely on for the
// grant_type=refresh_token leg of RFC 6749 §6.
//
// Centralizing the form-encoded POST + response parse + error
// classification means each per-provider package collapses to roughly
// "endpoint URL, app credentials, error-string quirks" — see ADR 0006
// and PRD 0010 §1 for the rationale.
//
// The Client does NOT know about vault.Credential, vault.SecretBlob,
// or any storage shape. It is a thin protocol adapter; per-provider
// packages wrap it and translate to/from the vault types.
package oauth2

import "time"

// TokenResponse is the parsed shape of a successful /token reply.
//
// RefreshToken is set iff the provider rotated the submitted refresh
// token — Box always rotates; Google sometimes; Dropbox never. Callers
// MUST persist the new value atomically with the access token, or the
// next refresh attempt will use a stale value the provider has already
// invalidated. See PRD 0010 §4 for the rotation-discipline invariant.
type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type,omitempty"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token,omitempty"`
	Scope        string `json:"scope,omitempty"`
}

// IsRefreshTokenRotated reports whether the provider returned a new
// refresh token that must replace the one the caller submitted. A
// non-empty RefreshToken field is the only signal the OAuth2 spec
// gives for rotation — providers that never rotate omit the field.
func (t *TokenResponse) IsRefreshTokenRotated() bool {
	return t.RefreshToken != ""
}

// AccessTokenExpiresAt computes the absolute expiry instant from the
// ExpiresIn duration the provider returned. Callers persist this on
// the credential row's metadata so sync-on-stale can decide whether a
// refresh is due without re-decrypting the secret payload.
func (t *TokenResponse) AccessTokenExpiresAt(now time.Time) time.Time {
	return now.Add(time.Duration(t.ExpiresIn) * time.Second)
}
