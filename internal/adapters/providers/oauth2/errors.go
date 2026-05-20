package oauth2

import "errors"

// Sentinel errors the Client returns from Refresh. Callers compare via
// errors.Is and translate to the appropriate vault-level outcome.
//
// Every error returned from the oauth2 package is double-wrapped: the
// inner sentinel here lets adapter-level tests assert specific
// classification ("invalid_grant should be permanent"), and the outer
// vault-level sentinel (vault.ErrProviderRefreshPermanent or
// vault.ErrProviderRefreshTransient) lets the Service classify
// without taking a build-time dependency on this package — preserving
// the internal/vault ↛ internal/adapters/* hexagonal invariant.
//
//   - ErrInvalidGrant — refresh_token revoked/rejected. Permanent.
//   - ErrTransient    — 5xx, network, unrecognized; retry safe.
var (
	ErrInvalidGrant = errors.New("oauth2: refresh_token revoked or rejected by provider")
	ErrTransient    = errors.New("oauth2: transient provider error")
)
