package box

import (
	"bytes"
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

// Critical Box invariant per PRD 0010 §4: the refresh_token MUST change
// across every Refresh and the new value must appear in the returned
// Credential's secret payload (which the Service then persists
// atomically). This test is the unit-level enforcement of that
// invariant.
func TestRefresh_AlwaysRotatesRefreshToken(t *testing.T) {
	p := newFakeProvider(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{
			"access_token":  "at-new",
			"expires_in":    3600,
			"refresh_token": "rt-rotated"
		}`))
	})

	originalRT := []byte("rt-original")
	in := vault.Credential{
		ID:       "cred-id",
		Provider: "box",
		Secret:   vault.NewSecretBlob([]byte(`{"refresh_token":"rt-original"}`)),
	}
	out, err := p.Refresh(context.Background(), in)
	if err != nil {
		t.Fatalf("Refresh: %v", err)
	}

	var payload oauth2.SecretPayload
	if err := json.Unmarshal(out.Secret.Reveal(), &payload); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if payload.RefreshToken != "rt-rotated" {
		t.Errorf("refresh_token = %q, want rt-rotated (Box ALWAYS rotates)", payload.RefreshToken)
	}
	if bytes.Equal([]byte(payload.RefreshToken), originalRT) {
		t.Error("refresh_token byte-equal to original — rotation discipline violated")
	}
	if payload.AccessToken != "at-new" {
		t.Errorf("access_token = %q, want at-new", payload.AccessToken)
	}
}

// Even if Box (hypothetically, via a quirk) returns the same value as
// the submitted refresh_token, IsRefreshTokenRotated() must still see
// the field and the helper must persist it (the empty-field semantic
// is the only signal for "no rotation").
func TestRefresh_OmittedRotationFieldKeepsOriginal(t *testing.T) {
	p := newFakeProvider(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"access_token":"at","expires_in":3600}`))
	})
	in := vault.Credential{Secret: vault.NewSecretBlob([]byte(`{"refresh_token":"rt"}`))}
	out, err := p.Refresh(context.Background(), in)
	if err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	var payload oauth2.SecretPayload
	_ = json.Unmarshal(out.Secret.Reveal(), &payload)
	if payload.RefreshToken != "rt" {
		t.Errorf("refresh_token = %q, want rt", payload.RefreshToken)
	}
}
