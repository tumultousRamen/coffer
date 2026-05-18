//go:build integration

// Integration tests for the S3 provider. Runs against real AWS using
// SSO credentials picked up from AWS_PROFILE. Invoke via
// `make integration`. Skipped (with a loud message) when AWS_PROFILE
// is unset so it can't silently no-op in CI.
//
// Two scenarios:
//
//   - Known-good creds: load SSO-derived static keys via STS
//     GetSessionToken; pass them to Validate; expect success.
//   - Known-bad creds: hardcoded garbage; expect Validate to return
//     ErrProviderValidation with a non-empty reason.
//
// The good-creds path mirrors the AWS KMS integration test's
// AWS_PROFILE pickup. The bad-creds path is a static literal so we
// never accidentally test against real working keys we don't own.
package s3

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"testing"

	"github.com/aws/aws-sdk-go-v2/config"

	"github.com/tumultousRamen/coffer/internal/vault"
)

const integrationRegion = "us-west-1"

// loadStaticCredsFromProfile extracts the active AWS_PROFILE's
// resolved AccessKeyId / SecretAccessKey / (optional) SessionToken
// by asking the SDK's credential chain to Retrieve once, then
// serializes them as the JSON shape the S3 provider expects.
//
// For SSO-derived profiles the resolved credentials are themselves
// short-lived STS credentials carrying a SessionToken; the provider
// currently ignores session_token (extra fields are forward-compat
// with STS broker mode), so a separate "no session token" run is
// not strictly required to prove the success path. The bad-creds
// test below uses hardcoded garbage with no session token.
func loadStaticCredsFromProfile(t *testing.T) []byte {
	t.Helper()
	if os.Getenv("AWS_PROFILE") == "" {
		t.Skip("SKIP: AWS_PROFILE unset (run via `make integration`)")
	}
	ctx := context.Background()
	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(integrationRegion))
	if err != nil {
		t.Fatalf("load AWS config (is `aws sso login --profile $AWS_PROFILE` fresh?): %v", err)
	}
	creds, err := cfg.Credentials.Retrieve(ctx)
	if err != nil {
		t.Fatalf("retrieve credentials from profile: %v", err)
	}
	payload := map[string]string{
		"access_key_id":     creds.AccessKeyID,
		"secret_access_key": creds.SecretAccessKey,
	}
	if creds.SessionToken != "" {
		payload["session_token"] = creds.SessionToken
	}
	b, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal cred payload: %v", err)
	}
	return b
}

func TestIntegration_Validate_KnownGoodCreds(t *testing.T) {
	creds := loadStaticCredsFromProfile(t)
	p := New()
	err := p.Validate(context.Background(), vault.NewSecretBlob(creds), vault.Metadata{"region": integrationRegion})
	if err != nil {
		t.Fatalf("Validate with SSO-derived static creds: %v", err)
	}
}

func TestIntegration_Validate_KnownBadCreds(t *testing.T) {
	if os.Getenv("AWS_PROFILE") == "" {
		t.Skip("SKIP: AWS_PROFILE unset (run via `make integration`)")
	}
	garbage := []byte(`{"access_key_id":"AKIAINVALIDFAKEKEY00","secret_access_key":"GARBAGE_SECRET_ACCESS_KEY"}`)
	p := New()
	err := p.Validate(context.Background(), vault.NewSecretBlob(garbage), vault.Metadata{"region": integrationRegion})
	if err == nil {
		t.Fatal("Validate with garbage creds returned nil; want ErrProviderValidation")
	}
	if !errors.Is(err, vault.ErrProviderValidation) {
		t.Errorf("Validate garbage err = %v, want ErrProviderValidation wrap", err)
	}
	if err.Error() == "" {
		t.Errorf("Validate garbage err.Error() is empty; the AWS reason should be wrapped in")
	}
}
