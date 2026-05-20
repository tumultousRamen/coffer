//go:build integration

package box

import (
	"context"
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/tumultousRamen/coffer/internal/adapters/providers/oauth2"
	"github.com/tumultousRamen/coffer/internal/vault"
)

// Box integration test is destructive against the refresh_token in the
// env: Box always rotates, so after this test runs the env var's value
// is no longer valid. Operators re-mint via the Box dev console between
// runs.
func TestIntegration_BoxRefreshAlwaysRotates(t *testing.T) {
	clientID := os.Getenv("COFFER_BOX_CLIENT_ID")
	clientSecret := os.Getenv("COFFER_BOX_CLIENT_SECRET")
	refreshToken := os.Getenv("COFFER_TEST_BOX_REFRESH_TOKEN")
	if clientID == "" || clientSecret == "" || refreshToken == "" {
		t.Skip("Box integration test requires COFFER_BOX_CLIENT_ID + COFFER_BOX_CLIENT_SECRET + COFFER_TEST_BOX_REFRESH_TOKEN (Box rotates the token on every refresh)")
	}

	p := New(clientID, clientSecret)

	secret, _ := json.Marshal(map[string]string{"refresh_token": refreshToken})
	in := vault.Credential{
		ID:       "box-integration",
		Provider: "box",
		Label:    "integration",
		Secret:   vault.NewSecretBlob(secret),
		Metadata: vault.Metadata{},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	out, err := p.Refresh(ctx, in)
	if err != nil {
		t.Fatalf("Refresh against real Box: %v", err)
	}

	var payload oauth2.SecretPayload
	if err := json.Unmarshal(out.Secret.Reveal(), &payload); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if payload.AccessToken == "" {
		t.Error("real Box /token returned without an access_token")
	}
	if payload.RefreshToken == refreshToken {
		t.Error("Box did NOT rotate the refresh_token — contract violation (PRD 0010 §4 invariant)")
	}
	if payload.RefreshToken == "" {
		t.Error("Box returned an empty refresh_token — rotation expected to always produce a new value")
	}
}
