package dropbox

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/tumultousRamen/coffer/internal/adapters/providers/oauth2"
	"github.com/tumultousRamen/coffer/internal/vault"
)

const fixedNow = "2026-05-20T15:30:00Z"

func newFakeProvider(t *testing.T, handler http.HandlerFunc) *Provider {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	client := oauth2.NewClientWithHTTP(srv.URL, "cid", "csecret", srv.Client())
	now := func() time.Time {
		ts, _ := time.Parse(time.RFC3339, fixedNow)
		return ts
	}
	return NewWithClient(client, now)
}

func TestRefresh_HappyPath(t *testing.T) {
	p := newFakeProvider(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" { // httptest server routes all paths to /; we just confirm form-encoded
			t.Errorf("path = %q", r.URL.Path)
		}
		_, _ = w.Write([]byte(`{"access_token":"at-fresh","token_type":"bearer","expires_in":14400}`))
	})

	in := vault.Credential{
		ID:       "cred-id",
		Provider: "dropbox",
		Label:    "personal",
		Secret:   vault.NewSecretBlob([]byte(`{"refresh_token":"rt"}`)),
		Metadata: vault.Metadata{"foo": "bar"},
	}
	out, err := p.Refresh(context.Background(), in)
	if err != nil {
		t.Fatalf("Refresh: %v", err)
	}

	var payload oauth2.SecretPayload
	if err := json.Unmarshal(out.Secret.Reveal(), &payload); err != nil {
		t.Fatalf("unmarshal payload: %v", err)
	}
	if payload.AccessToken != "at-fresh" {
		t.Errorf("access_token = %q", payload.AccessToken)
	}
	if payload.RefreshToken != "rt" {
		t.Errorf("refresh_token = %q, want rt (Dropbox never rotates)", payload.RefreshToken)
	}
	wantExpiry := "2026-05-20T19:30:00Z"
	if got, _ := out.Metadata[vault.MetadataKeyAccessTokenExpiresAt].(string); got != wantExpiry {
		t.Errorf("expires_at = %q, want %q", got, wantExpiry)
	}
	if out.Metadata["foo"] != "bar" {
		t.Errorf("caller-supplied metadata was clobbered: %v", out.Metadata)
	}
}

func TestRefresh_InvalidGrant(t *testing.T) {
	p := newFakeProvider(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"invalid_grant"}`))
	})
	in := vault.Credential{Secret: vault.NewSecretBlob([]byte(`{"refresh_token":"rt"}`))}
	_, err := p.Refresh(context.Background(), in)
	if !errors.Is(err, oauth2.ErrInvalidGrant) {
		t.Errorf("err = %v, want wrap of ErrInvalidGrant", err)
	}
}

func TestValidate_MissingRefreshToken(t *testing.T) {
	p := New("cid", "csecret")
	err := p.Validate(context.Background(), vault.NewSecretBlob([]byte(`{}`)), nil)
	if !errors.Is(err, vault.ErrProviderValidation) {
		t.Errorf("err = %v, want wrap of ErrProviderValidation", err)
	}
}

func TestNeedsScheduledRefresh(t *testing.T) {
	p := New("cid", "csecret")
	if !p.NeedsScheduledRefresh() {
		t.Error("NeedsScheduledRefresh = false, want true")
	}
}
