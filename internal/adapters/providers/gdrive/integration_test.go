//go:build integration

package gdrive

import (
	"context"
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/tumultousRamen/coffer/internal/adapters/providers/oauth2"
	"github.com/tumultousRamen/coffer/internal/vault"
)

func TestIntegration_GDriveRefreshAgainstRealEndpoint(t *testing.T) {
	clientID := os.Getenv("COFFER_GDRIVE_CLIENT_ID")
	clientSecret := os.Getenv("COFFER_GDRIVE_CLIENT_SECRET")
	refreshToken := os.Getenv("COFFER_TEST_GDRIVE_REFRESH_TOKEN")
	if clientID == "" || clientSecret == "" || refreshToken == "" {
		t.Skip("GDrive integration test requires COFFER_GDRIVE_CLIENT_ID + COFFER_GDRIVE_CLIENT_SECRET + COFFER_TEST_GDRIVE_REFRESH_TOKEN")
	}

	p := New(clientID, clientSecret)

	secret, _ := json.Marshal(map[string]string{"refresh_token": refreshToken})
	in := vault.Credential{
		ID:       "gdrive-integration",
		Provider: "gdrive",
		Label:    "integration",
		Secret:   vault.NewSecretBlob(secret),
		Metadata: vault.Metadata{},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	out, err := p.Refresh(ctx, in)
	if err != nil {
		t.Fatalf("Refresh against real Google: %v", err)
	}

	var payload oauth2.SecretPayload
	if err := json.Unmarshal(out.Secret.Reveal(), &payload); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if payload.AccessToken == "" {
		t.Error("real Google /token returned without an access_token")
	}
	if _, ok := out.Metadata[vault.MetadataKeyAccessTokenExpiresAt]; !ok {
		t.Error("metadata.access_token_expires_at not populated")
	}
	// Google rarely rotates; assertion deliberately omitted — both
	// outcomes are spec-compliant.
}
