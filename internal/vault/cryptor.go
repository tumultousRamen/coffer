// Package vault — Cryptor implements the per-tenant envelope-encryption
// protocol from ADR 0003 on top of the KeyManager port and a DEKCache.
//
// Encrypt/Decrypt orchestrate AES-256-GCM with a fresh 96-bit random
// nonce per encryption and AAD = userID|credentialID|provider. The
// cache holds plaintext DEKs; cold misses are coalesced through a
// per-key singleflight group so a thundering herd fires exactly one
// KMS Decrypt (ADR 0004 §5).
package vault

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"

	"golang.org/x/sync/singleflight"
)

// nonceSize is the AES-GCM standard nonce length. Documented as a
// constant so it appears in code search; do not change without an ADR
// amendment (would invalidate every stored ciphertext).
const nonceSize = 12

// Cryptor holds the wiring needed to encrypt and decrypt credential
// secrets. It is stateless with respect to durable storage: callers
// pass the tenant's ciphertext-wrapped DEK in on every call and the
// Cryptor handles cache lookup, KMS unwrap on miss, AES-GCM encrypt
// or decrypt, and AAD binding.
type Cryptor struct {
	km    KeyManager
	cache DEKCache
	sf    singleflight.Group
}

// NewCryptor constructs a Cryptor over the given KeyManager and DEKCache.
func NewCryptor(km KeyManager, cache DEKCache) *Cryptor {
	return &Cryptor{km: km, cache: cache}
}

// Provision mints a fresh DEK for userID via the KeyManager. Returns the
// ciphertext-wrapped DEK for the caller to persist on the tenants row
// (ADR 0005). The plaintext DEK is cached so the immediately-following
// Encrypt does not pay another KMS round-trip.
func (c *Cryptor) Provision(ctx context.Context, userID string) ([]byte, error) {
	plaintextDEK, ciphertextDEK, err := c.km.GenerateDataKey(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("cryptor: generate data key: %w", err)
	}
	if len(plaintextDEK) != 32 {
		return nil, fmt.Errorf("cryptor: expected 32-byte AES-256 DEK, got %d", len(plaintextDEK))
	}
	c.cache.Put(userID, ciphertextDEK, plaintextDEK)
	return ciphertextDEK, nil
}

// Encrypt seals plaintext under the tenant's DEK using AES-256-GCM with
// a fresh random 96-bit nonce. AAD binds the ciphertext to its row so a
// swap-the-blob attack on storage is detected on decrypt (ADR 0003).
// Returns (ciphertext, nonce) — both must be persisted alongside the
// row's ciphertextDEK reference.
func (c *Cryptor) Encrypt(
	ctx context.Context,
	userID, credentialID, provider string,
	plaintext []byte,
	ciphertextDEK []byte,
) (ciphertext, nonce []byte, err error) {
	plaintextDEK, err := c.unwrap(ctx, userID, ciphertextDEK)
	if err != nil {
		return nil, nil, err
	}
	gcm, err := newGCM(plaintextDEK)
	if err != nil {
		return nil, nil, err
	}
	nonce = make([]byte, nonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return nil, nil, fmt.Errorf("cryptor: nonce: %w", err)
	}
	aad := buildAAD(userID, credentialID, provider)
	ciphertext = gcm.Seal(nil, nonce, plaintext, aad)
	return ciphertext, nonce, nil
}

// Decrypt opens a ciphertext produced by Encrypt for the same row
// (userID, credentialID, provider) and the same ciphertextDEK. Any
// tampering with ciphertext, nonce, or AAD inputs triggers a GCM auth
// failure (returned as an error).
func (c *Cryptor) Decrypt(
	ctx context.Context,
	userID, credentialID, provider string,
	ciphertext, nonce []byte,
	ciphertextDEK []byte,
) ([]byte, error) {
	if len(nonce) != nonceSize {
		return nil, fmt.Errorf("cryptor: nonce length: want %d, got %d", nonceSize, len(nonce))
	}
	plaintextDEK, err := c.unwrap(ctx, userID, ciphertextDEK)
	if err != nil {
		return nil, err
	}
	gcm, err := newGCM(plaintextDEK)
	if err != nil {
		return nil, err
	}
	aad := buildAAD(userID, credentialID, provider)
	plaintext, err := gcm.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		return nil, fmt.Errorf("cryptor: open: %w", err)
	}
	return plaintext, nil
}

// unwrap returns the plaintext DEK for (userID, ciphertextDEK). On a
// cache miss, concurrent callers for the same key coalesce via
// singleflight so KMS sees one Decrypt regardless of fan-in. Single-
// flight key matches the cache key so contention granularity is the
// same as eviction granularity.
func (c *Cryptor) unwrap(ctx context.Context, userID string, ciphertextDEK []byte) ([]byte, error) {
	if dek, ok := c.cache.Get(userID, ciphertextDEK); ok {
		return dek, nil
	}
	key := cacheKey(userID, ciphertextDEK)
	v, err, _ := c.sf.Do(key, func() (interface{}, error) {
		// Double-check: another goroutine may have populated the cache
		// while we waited for the singleflight slot.
		if dek, ok := c.cache.Get(userID, ciphertextDEK); ok {
			return dek, nil
		}
		plaintextDEK, err := c.km.Decrypt(ctx, ciphertextDEK)
		if err != nil {
			return nil, fmt.Errorf("cryptor: kms decrypt: %w", err)
		}
		if len(plaintextDEK) != 32 {
			return nil, fmt.Errorf("cryptor: expected 32-byte AES-256 DEK, got %d", len(plaintextDEK))
		}
		c.cache.Put(userID, ciphertextDEK, plaintextDEK)
		// Return a copy distinct from the one we just Put — the cache
		// owns its slice; concurrent callers receive their own copies
		// via cache.Get on the fast path next time around.
		out := make([]byte, len(plaintextDEK))
		copy(out, plaintextDEK)
		return out, nil
	})
	if err != nil {
		return nil, err
	}
	dek, ok := v.([]byte)
	if !ok {
		return nil, errors.New("cryptor: singleflight returned unexpected type")
	}
	return dek, nil
}

func newGCM(dek []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(dek)
	if err != nil {
		return nil, fmt.Errorf("cryptor: aes: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("cryptor: gcm: %w", err)
	}
	return gcm, nil
}

// buildAAD is the canonical AAD encoding for this vault: the literal
// bytes "userID|credentialID|provider". No escaping: all three inputs
// are constrained upstream to [a-zA-Z0-9-]+ (UUIDs and provider enums),
// so '|' is unambiguous as a separator. A test pins this exact byte
// sequence so a refactor that changes encoding fails before it can
// silently invalidate stored ciphertexts.
func buildAAD(userID, credentialID, provider string) []byte {
	return []byte(userID + "|" + credentialID + "|" + provider)
}
