package vault

import "errors"

// Sentinel errors returned by port implementations. Callers compare with
// errors.Is rather than string-matching on Error().
var (
	ErrNotFound             = errors.New("vault: not found")
	ErrAlreadyExists        = errors.New("vault: already exists")
	ErrUnauthorized         = errors.New("vault: unauthorized")
	ErrInvalidArgument      = errors.New("vault: invalid argument")
	ErrTenantNotProvisioned = errors.New("vault: tenant not provisioned")

	// ErrProviderUnknown is returned by ProviderLookup.Get when no
	// provider has been registered under the requested name. The REST
	// transport maps this to 400 — the caller used a provider string
	// the vault does not know about.
	ErrProviderUnknown = errors.New("vault: provider not registered")

	// ErrProviderValidation is returned by Provider.Validate (and by
	// Service.CreateCredential / ReplaceCredential when Validate
	// rejects the input) when the provider has determined the
	// credential cannot be used. Typically wrapped with the
	// provider-side reason so the REST transport can surface a
	// diagnostic in the 422 body:
	//
	//	fmt.Errorf("%w: %v", vault.ErrProviderValidation, awsErr)
	ErrProviderValidation = errors.New("vault: provider rejected credential")

	// ErrProviderRefreshPermanent is wrapped by Provider.Refresh when
	// the provider has issued a terminal verdict on the credential
	// (e.g. OAuth invalid_grant — the refresh_token has been revoked
	// or rejected and cannot be recovered without re-authorization).
	// The Service's sync-on-stale path at FetchForWorker checks for
	// this via errors.Is and transitions the credential to
	// status='failed' so subsequent reads short-circuit. Per PRD 0010
	// §4.
	ErrProviderRefreshPermanent = errors.New("vault: provider refresh permanent failure")

	// ErrProviderRefreshTransient is wrapped by Provider.Refresh for
	// retryable failures (5xx, network errors, anything the adapter
	// could not confidently classify as permanent). The Service
	// propagates this so the worker can retry per ADR 0008 §3.
	ErrProviderRefreshTransient = errors.New("vault: provider refresh transient failure")
)
