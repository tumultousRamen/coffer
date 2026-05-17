// Package awskms is the production KeyManager implementation backed by
// AWS KMS. It satisfies the internal/vault.KeyManager interface; the
// adapter is the only piece of the vault that imports the AWS KMS SDK.
//
// The adapter is intentionally thin: it does not load AWS config of its
// own, does not retry, and does not wrap calls with a circuit breaker.
// The composition root (cmd/vault/main.go, future) is responsible for
// config loading; resilience behaviors are deferred to a focused PRD
// per ADR 0008 §1 — wrapping the single KMS call site is a one-file
// change when that lands.
package awskms

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
)

// KeyManagerAdapter implements vault.KeyManager against AWS KMS.
type KeyManagerAdapter struct {
	client   *kms.Client
	keyAlias string
}

// New constructs an adapter bound to the given KMS client and key
// alias (e.g. "alias/coffer-dev-master"). The alias is pinned on every
// Decrypt call as defense-in-depth: a ciphertext encrypted under a
// different KMS key is rejected by KMS rather than silently decrypted.
func New(client *kms.Client, keyAlias string) *KeyManagerAdapter {
	return &KeyManagerAdapter{client: client, keyAlias: keyAlias}
}

// GenerateDataKey returns a freshly-minted 32-byte AES-256 DEK and its
// ciphertext wrapper under the configured CMK.
//
// userID is unused: AWS KMS has no tenancy model at the data-key level;
// the per-tenant scoping happens in the Cryptor's cache lookup. The
// parameter is part of the port signature so other KeyManager
// implementations (HSM-backed, file-backed for offline dev) can use it.
func (a *KeyManagerAdapter) GenerateDataKey(ctx context.Context, userID string) (plaintext, ciphertext []byte, err error) {
	_ = userID
	out, err := a.client.GenerateDataKey(ctx, &kms.GenerateDataKeyInput{
		KeyId:   aws.String(a.keyAlias),
		KeySpec: types.DataKeySpecAes256,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("awskms: GenerateDataKey: %w", err)
	}
	return out.Plaintext, out.CiphertextBlob, nil
}

// Decrypt unwraps a previously-issued ciphertext DEK. KeyId is pinned
// to the configured alias so KMS will reject ciphertexts encrypted
// under a different key (defense-in-depth).
func (a *KeyManagerAdapter) Decrypt(ctx context.Context, ciphertextDEK []byte) ([]byte, error) {
	out, err := a.client.Decrypt(ctx, &kms.DecryptInput{
		CiphertextBlob: ciphertextDEK,
		KeyId:          aws.String(a.keyAlias),
	})
	if err != nil {
		return nil, fmt.Errorf("awskms: Decrypt: %w", err)
	}
	return out.Plaintext, nil
}
