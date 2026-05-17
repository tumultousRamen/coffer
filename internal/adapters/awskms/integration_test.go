//go:build integration

// Integration test for the AWS KMS adapter. Runs against real KMS using
// SSO credentials picked up from AWS_PROFILE. Invoke via `make integration`.
// Skipped (with a loud message) when AWS_PROFILE is unset so it can't
// silently no-op in CI.
package awskms

import (
	"bytes"
	"context"
	"os"
	"testing"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/kms"
)

const (
	keyAlias = "alias/coffer-dev-master"
	region   = "us-west-1"
)

func newClient(t *testing.T) *kms.Client {
	t.Helper()
	if os.Getenv("AWS_PROFILE") == "" {
		t.Skip("SKIP: AWS_PROFILE unset (run via `make integration`)")
	}
	ctx := context.Background()
	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(region))
	if err != nil {
		t.Fatalf("load AWS config (is `aws sso login --profile $AWS_PROFILE` fresh?): %v", err)
	}
	return kms.NewFromConfig(cfg)
}

func TestKMS_GenerateAndDecrypt(t *testing.T) {
	a := New(newClient(t), keyAlias)
	ctx := context.Background()

	plaintext, ciphertext, err := a.GenerateDataKey(ctx, "test-user")
	if err != nil {
		t.Fatalf("GenerateDataKey: %v", err)
	}
	if len(plaintext) != 32 {
		t.Fatalf("plaintext DEK len=%d want 32 (AES-256)", len(plaintext))
	}
	if len(ciphertext) == 0 {
		t.Fatal("ciphertext DEK is empty")
	}

	got, err := a.Decrypt(ctx, ciphertext)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatal("Decrypt did not return the original plaintext DEK")
	}
}

func TestKMS_DecryptTampered(t *testing.T) {
	a := New(newClient(t), keyAlias)
	ctx := context.Background()

	_, ciphertext, err := a.GenerateDataKey(ctx, "test-user")
	if err != nil {
		t.Fatalf("GenerateDataKey: %v", err)
	}
	tampered := append([]byte(nil), ciphertext...)
	tampered[len(tampered)/2] ^= 0x01

	if _, err := a.Decrypt(ctx, tampered); err == nil {
		t.Fatal("Decrypt with tampered ciphertext must fail")
	}
}
