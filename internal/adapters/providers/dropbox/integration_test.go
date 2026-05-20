//go:build integration

package dropbox

import (
	"context"
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/tumultousRamen/coffer/internal/adapters/providers/oauth2"
	"github.com/tumultousRamen/coffer/internal/vault"
)

// Gated on the env-var triple being present so a developer who only
// has (say) Box app credentials can still run `make integration`
// without hitting Dropbox.
func TestIntegration_DropboxRefreshAgainstRealEndpoint(t *testing.T) {
	clientID := os.Getenv("COFFER_DROPBOX_CLIENT_ID")
	clientSecret := os.Getenv("COFFER_DROPBOX_CLIENT_SECRET")
	refreshToken := os.Getenv("COFFER_TEST_DROPBOX_REFRESH_TOKEN")
	if clientID == "" || clientSecret == "" || refreshToken == "" {
		t.Skip("Dropbox integration test requires COFFER_DROPBOX_CLIENT_ID + COFFER_DROPBOX_CLIENT_SECRET + COFFER_TEST_DROPBOX_REFRESH_TOKEN")
	}

	p := New(clientID, clientSecret)

	secret, _ := json.Marshal(map[string]string{"refresh_token": refreshToken})
	in := vault.Credential{
		ID:       "dropbox-integration",
		Provider: "dropbox",
		Label:    "integration",
		Secret:   vault.NewSecretBlob(secret),
		Metadata: vault.Metadata{},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	out, err := p.Refresh(ctx, in)
	if err != nil {
		t.Fatalf("Refresh against real Dropbox: %v", err)
	}

	var payload oauth2.SecretPayload
	if err := json.Unmarshal(out.Secret.Reveal(), &payload); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if payload.AccessToken == "" {
		t.Error("real Dropbox /token returned without an access_token")
	}
	if _, ok := out.Metadata[vault.MetadataKeyAccessTokenExpiresAt]; !ok {
		t.Error("metadata.access_token_expires_at not populated")
	}
	// Dropbox never rotates; refresh_token should be unchanged.
	if payload.RefreshToken != refreshToken {
		t.Errorf("refresh_token changed across Dropbox refresh (unexpected): got %q, want %q", payload.RefreshToken, refreshToken)
	}
}
