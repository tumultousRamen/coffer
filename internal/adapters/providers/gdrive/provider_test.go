package gdrive

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/tumultousRamen/coffer/internal/adapters/providers/oauth2"
	"github.com/tumultousRamen/coffer/internal/vault"
)

func newFakeProvider(t *testing.T, handler http.HandlerFunc) *Provider {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	client := oauth2.NewClientWithHTTP(srv.URL, "cid", "csecret", srv.Client())
	now := func() time.Time {
		ts, _ := time.Parse(time.RFC3339, "2026-05-20T15:30:00Z")
		return ts
	}
	return NewWithClient(client, now)
}

func TestRefresh_HappyPathNoRotation(t *testing.T) {
	p := newFakeProvider(t, func(w http.ResponseWriter, r *http.Request) {
		// Google sometimes returns the refresh_token, sometimes omits it.
		// Default-case test: omitted.
		_, _ = w.Write([]byte(`{"access_token":"at","token_type":"Bearer","expires_in":3599,"scope":"drive.readonly"}`))
	})
	in := vault.Credential{Secret: vault.NewSecretBlob([]byte(`{"refresh_token":"rt"}`))}
	out, err := p.Refresh(context.Background(), in)
	if err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	var payload oauth2.SecretPayload
	_ = json.Unmarshal(out.Secret.Reveal(), &payload)
	if payload.RefreshToken != "rt" {
		t.Errorf("refresh_token = %q, want rt (not rotated)", payload.RefreshToken)
	}
}

func TestRefresh_HandlesOptionalRotation(t *testing.T) {
	p := newFakeProvider(t, func(w http.ResponseWriter, r *http.Request) {
		// Google's silent-rotation case (100-token-cap conditions).
		_, _ = w.Write([]byte(`{"access_token":"at","expires_in":3599,"refresh_token":"rt-new"}`))
	})
	in := vault.Credential{Secret: vault.NewSecretBlob([]byte(`{"refresh_token":"rt-old"}`))}
	out, err := p.Refresh(context.Background(), in)
	if err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	var payload oauth2.SecretPayload
	_ = json.Unmarshal(out.Secret.Reveal(), &payload)
	if payload.RefreshToken != "rt-new" {
		t.Errorf("refresh_token = %q, want rt-new", payload.RefreshToken)
	}
}
