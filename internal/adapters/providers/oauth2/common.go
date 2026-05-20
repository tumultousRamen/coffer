package oauth2

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/tumultousRamen/coffer/internal/vault"
)

// DefaultTimeout caps a single Refresh call. Vendor /token endpoints
// (Dropbox, Google, Box) usually answer in 100–500ms; 10s absorbs
// transient slowness without parking the caller indefinitely. See
// PRD 0010 §1 — the sync-on-stale path is allowed to live outside the
// 50ms read SLO per ADR-0006 §4.
const DefaultTimeout = 10 * time.Second

// Client is a thin wrapper over net/http for the OAuth2 refresh-token
// leg of RFC 6749. One Client per provider — endpoint and app
// credentials are immutable for the Client's lifetime.
//
// The zero value is not usable; construct with NewClient.
type Client struct {
	httpClient   *http.Client
	endpoint     string
	clientID     string
	clientSecret string
}

// NewClient builds a Client bound to endpoint with the supplied app
// credentials. The HTTP client uses DefaultTimeout; callers that need
// a different deadline should wrap context.WithTimeout themselves.
func NewClient(endpoint, clientID, clientSecret string) *Client {
	return &Client{
		httpClient:   &http.Client{Timeout: DefaultTimeout},
		endpoint:     endpoint,
		clientID:     clientID,
		clientSecret: clientSecret,
	}
}

// NewClientWithHTTP is the test-friendly constructor that lets callers
// inject a custom *http.Client — typically one whose Transport rewrites
// to an httptest.Server. Production code uses NewClient.
func NewClientWithHTTP(endpoint, clientID, clientSecret string, hc *http.Client) *Client {
	return &Client{
		httpClient:   hc,
		endpoint:     endpoint,
		clientID:     clientID,
		clientSecret: clientSecret,
	}
}

// Refresh POSTs grant_type=refresh_token to the configured endpoint and
// returns the parsed TokenResponse. Errors are classified into the two
// vault-level outcomes the caller cares about (ErrInvalidGrant vs
// ErrTransient) via errors.Is — the wrapped error retains the
// provider-side error_description for diagnostics.
//
// "Unknown" failure modes (parse errors on the response body,
// unrecognized error codes, non-2xx without a parseable OAuth2 error
// envelope) are deliberately classified as ErrTransient. Treating an
// unknown failure as permanent would risk bricking a credential the
// vault could not actually prove was rejected; treating it as transient
// at worst burns an extra refresh attempt. Per PRD 0010 §1.
func (c *Client) Refresh(ctx context.Context, refreshToken string) (*TokenResponse, error) {
	form := url.Values{}
	form.Set("grant_type", "refresh_token")
	form.Set("refresh_token", refreshToken)
	form.Set("client_id", c.clientID)
	form.Set("client_secret", c.clientSecret)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, wrapTransient(fmt.Errorf("build request: %v", err))
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		// Network errors, deadline exceeded, etc. All transient — let
		// the caller retry. context.Canceled propagates as-is so cleanup
		// paths can distinguish caller cancellation from provider trouble.
		if errors.Is(err, context.Canceled) {
			return nil, err
		}
		return nil, wrapTransient(fmt.Errorf("http: %v", err))
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, wrapTransient(fmt.Errorf("read body: %v", err))
	}

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		var tr TokenResponse
		if err := json.Unmarshal(body, &tr); err != nil {
			return nil, wrapTransient(fmt.Errorf("parse success body: %v", err))
		}
		if tr.AccessToken == "" {
			// A 2xx response without an access_token is malformed enough
			// that we treat it as transient and let the worker retry; the
			// alternative (mark the credential failed) would brick a
			// possibly-fine refresh_token on a provider hiccup.
			return nil, wrapTransient(errors.New("success response missing access_token"))
		}
		return &tr, nil
	}

	return nil, classifyErrorBody(resp.StatusCode, body)
}

// wrapTransient and wrapPermanent double-wrap: outer = vault sentinel
// (so the Service can errors.Is without importing this package), inner
// = oauth2 sentinel (for adapter-package tests). errors.Is walks the
// full chain, so a single error value satisfies both checks.
func wrapTransient(inner error) error {
	return chainedError{outer: vault.ErrProviderRefreshTransient, mid: ErrTransient, inner: inner}
}

func wrapPermanent(inner error) error {
	return chainedError{outer: vault.ErrProviderRefreshPermanent, mid: ErrInvalidGrant, inner: inner}
}

// chainedError carries three error values so errors.Is matches both
// the vault-level sentinel and the oauth2-level sentinel on the same
// error. The Error string composes the human-readable chain.
type chainedError struct {
	outer error // vault.ErrProviderRefresh{Permanent,Transient}
	mid   error // oauth2.Err{InvalidGrant,Transient}
	inner error // operator-readable detail
}

func (e chainedError) Error() string {
	return fmt.Sprintf("%s: %s: %s", e.outer.Error(), e.mid.Error(), e.inner.Error())
}

// Is satisfies errors.Is for both layered sentinels. The Service relies
// on errors.Is(err, vault.ErrProviderRefreshPermanent) without seeing
// the oauth2 package symbol; adapter tests rely on
// errors.Is(err, oauth2.ErrInvalidGrant).
func (e chainedError) Is(target error) bool {
	return target == e.outer || target == e.mid
}

func (e chainedError) Unwrap() error { return e.inner }

// errorEnvelope is the standard OAuth2 error shape (RFC 6749 §5.2)
// plus the human-readable description providers include.
type errorEnvelope struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description,omitempty"`
}

func classifyErrorBody(status int, body []byte) error {
	var env errorEnvelope
	_ = json.Unmarshal(body, &env) // best-effort; empty env if unparseable

	// Permanent failures — caller marks the credential failed.
	//   invalid_grant: refresh_token revoked / expired (most common).
	//   invalid_client: app credentials don't authenticate. Operator-side
	//   from the vault's perspective, but the credential will keep
	//   failing until reconfigured; classifying as permanent stops the
	//   per-credential retry hammer.
	if env.Error == "invalid_grant" || env.Error == "invalid_client" {
		return wrapPermanent(fmt.Errorf("%s: %s", env.Error, env.ErrorDescription))
	}

	// Transient failures — caller's worker retries.
	if status >= 500 || env.Error == "server_error" || env.Error == "temporarily_unavailable" {
		return wrapTransient(fmt.Errorf("status=%d %s: %s", status, env.Error, env.ErrorDescription))
	}

	// Unrecognized 4xx with no OAuth2 envelope, or unrecognized error
	// code. Default to transient — safer to retry than to brick.
	if env.Error != "" {
		return wrapTransient(fmt.Errorf("status=%d %s: %s", status, env.Error, env.ErrorDescription))
	}
	return wrapTransient(fmt.Errorf("status=%d (no error envelope)", status))
}
