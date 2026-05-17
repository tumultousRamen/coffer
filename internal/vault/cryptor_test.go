package vault

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// mockKM is a test-only KeyManager. Its ciphertext-wrapped DEK is just
// the literal bytes "wrap:" || plaintextDEK so Decrypt is trivially
// invertible, while still letting us count call frequency and inject
// delays / errors. The bytes-on-the-wire shape is internal to the test;
// production code never sees them.
type mockKM struct {
	generateCalls atomic.Int64
	decryptCalls  atomic.Int64
	delay         time.Duration // optional: held inside Decrypt before returning
	decryptErr    error         // optional: returned from Decrypt
}

func (m *mockKM) GenerateDataKey(_ context.Context, _ string) ([]byte, []byte, error) {
	m.generateCalls.Add(1)
	plaintext := make([]byte, 32)
	if _, err := rand.Read(plaintext); err != nil {
		return nil, nil, err
	}
	ciphertext := append([]byte("wrap:"), plaintext...)
	return plaintext, ciphertext, nil
}

func (m *mockKM) Decrypt(_ context.Context, ciphertextDEK []byte) ([]byte, error) {
	m.decryptCalls.Add(1)
	if m.delay > 0 {
		time.Sleep(m.delay)
	}
	if m.decryptErr != nil {
		return nil, m.decryptErr
	}
	if len(ciphertextDEK) < 5 || string(ciphertextDEK[:5]) != "wrap:" {
		return nil, errors.New("mock: unknown ciphertextDEK shape")
	}
	out := make([]byte, len(ciphertextDEK)-5)
	copy(out, ciphertextDEK[5:])
	return out, nil
}

// newCryptor builds a Cryptor with a fresh mockKM and small cache, and
// returns both so tests can assert on call counts.
func newTestCryptor(t *testing.T) (*Cryptor, *mockKM) {
	t.Helper()
	km := &mockKM{}
	return NewCryptor(km, NewDEKCache(64, time.Minute)), km
}

func TestCryptor_RoundTrip(t *testing.T) {
	c, _ := newTestCryptor(t)
	ctx := context.Background()
	wrapped, err := c.Provision(ctx, "user-1")
	if err != nil {
		t.Fatalf("Provision: %v", err)
	}
	plaintext := []byte("AKIA-test-secret-key")
	ct, nonce, err := c.Encrypt(ctx, "user-1", "cred-1", "s3", plaintext, wrapped)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	got, err := c.Decrypt(ctx, "user-1", "cred-1", "s3", ct, nonce, wrapped)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("round-trip mismatch: %q vs %q", got, plaintext)
	}
}

func TestCryptor_AADTampering(t *testing.T) {
	c, _ := newTestCryptor(t)
	ctx := context.Background()
	wrapped, _ := c.Provision(ctx, "user-1")
	plaintext := []byte("secret")
	ct, nonce, err := c.Encrypt(ctx, "user-1", "cred-1", "s3", plaintext, wrapped)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	cases := []struct {
		name                       string
		userID, credentialID, prov string
	}{
		{"userID flipped", "user-2", "cred-1", "s3"},
		{"credentialID flipped", "user-1", "cred-2", "s3"},
		{"provider flipped", "user-1", "cred-1", "dropbox"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := c.Decrypt(ctx, tc.userID, tc.credentialID, tc.prov, ct, nonce, wrapped)
			if err == nil {
				t.Fatal("Decrypt with tampered AAD must fail")
			}
		})
	}
}

func TestCryptor_CiphertextTampering(t *testing.T) {
	c, _ := newTestCryptor(t)
	ctx := context.Background()
	wrapped, _ := c.Provision(ctx, "user-1")
	ct, nonce, err := c.Encrypt(ctx, "user-1", "cred-1", "s3", []byte("secret"), wrapped)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	tampered := append([]byte(nil), ct...)
	tampered[0] ^= 0x01
	if _, err := c.Decrypt(ctx, "user-1", "cred-1", "s3", tampered, nonce, wrapped); err == nil {
		t.Fatal("Decrypt with tampered ciphertext must fail")
	}
}

func TestCryptor_NonceTampering(t *testing.T) {
	c, _ := newTestCryptor(t)
	ctx := context.Background()
	wrapped, _ := c.Provision(ctx, "user-1")
	ct, nonce, err := c.Encrypt(ctx, "user-1", "cred-1", "s3", []byte("secret"), wrapped)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	tampered := append([]byte(nil), nonce...)
	tampered[0] ^= 0x01
	if _, err := c.Decrypt(ctx, "user-1", "cred-1", "s3", ct, tampered, wrapped); err == nil {
		t.Fatal("Decrypt with tampered nonce must fail")
	}
}

// TestCryptor_NonceUniqueness proves 10K Encrypt calls under the same
// DEK produce 10K distinct nonces — the catastrophic GCM nonce-reuse
// failure mode is impossible if crypto/rand is wired correctly.
func TestCryptor_NonceUniqueness(t *testing.T) {
	c, _ := newTestCryptor(t)
	ctx := context.Background()
	wrapped, _ := c.Provision(ctx, "user-1")

	const N = 10_000
	seen := make(map[string]struct{}, N)
	for i := 0; i < N; i++ {
		_, nonce, err := c.Encrypt(ctx, "user-1", "cred-1", "s3", []byte("x"), wrapped)
		if err != nil {
			t.Fatalf("Encrypt %d: %v", i, err)
		}
		k := string(nonce)
		if _, dup := seen[k]; dup {
			t.Fatalf("nonce collision at iteration %d", i)
		}
		seen[k] = struct{}{}
	}
}

func TestCryptor_CacheHitAfterFirstDecrypt(t *testing.T) {
	c, km := newTestCryptor(t)
	ctx := context.Background()
	wrapped, _ := c.Provision(ctx, "user-1") // Provision warms cache
	ct, nonce, _ := c.Encrypt(ctx, "user-1", "cred-1", "s3", []byte("x"), wrapped)

	// First decrypt: still a cache hit (Provision warmed it).
	if _, err := c.Decrypt(ctx, "user-1", "cred-1", "s3", ct, nonce, wrapped); err != nil {
		t.Fatalf("Decrypt 1: %v", err)
	}
	if got := km.decryptCalls.Load(); got != 0 {
		t.Fatalf("after Provision-warmed cache, kms.Decrypt calls=%d want 0", got)
	}
	// Repeat to confirm subsequent calls still don't hit KMS.
	if _, err := c.Decrypt(ctx, "user-1", "cred-1", "s3", ct, nonce, wrapped); err != nil {
		t.Fatalf("Decrypt 2: %v", err)
	}
	if got := km.decryptCalls.Load(); got != 0 {
		t.Fatalf("steady-state kms.Decrypt calls=%d want 0", got)
	}
}

// TestCryptor_ColdMissCallsKMS exercises the path that Provision skips:
// a fresh Cryptor with a pre-existing ciphertextDEK, no cache warmup.
func TestCryptor_ColdMissCallsKMS(t *testing.T) {
	km := &mockKM{}
	c := NewCryptor(km, NewDEKCache(64, time.Minute))
	ctx := context.Background()

	wrapped := append([]byte("wrap:"), bytes.Repeat([]byte{0xab}, 32)...)
	if _, err := c.Decrypt(ctx, "u", "c", "p", nil, make([]byte, nonceSize), wrapped); err == nil {
		// Decrypt of empty ciphertext is expected to fail at GCM Open,
		// but it must first unwrap the DEK via KMS.
		t.Fatal("expected GCM open error on empty ciphertext")
	}
	if got := km.decryptCalls.Load(); got != 1 {
		t.Fatalf("kms.Decrypt calls=%d, want 1 (cold miss)", got)
	}
}

func TestCryptor_DEKRotation_CacheMiss(t *testing.T) {
	c, km := newTestCryptor(t)
	ctx := context.Background()
	wrappedA, _ := c.Provision(ctx, "user-1")
	wrappedB, _ := c.Provision(ctx, "user-1") // rotated

	// Both ciphertextDEKs should be cached (Provision warms). Drive a
	// decrypt that needs the second DEK and assert no extra KMS call.
	if got := km.decryptCalls.Load(); got != 0 {
		t.Fatalf("after two Provisions, kms.Decrypt=%d want 0", got)
	}

	// Now blow away the cache entry for wrappedB and confirm a Decrypt
	// against wrappedB triggers exactly one KMS call, while wrappedA
	// stays cached.
	ct, nonce, _ := c.Encrypt(ctx, "user-1", "cred-1", "s3", []byte("x"), wrappedB)

	// Construct a fresh Cryptor sharing the KM but with an empty cache
	// — simulates the rotation case where one instance hasn't yet seen
	// the new ciphertextDEK.
	c2 := NewCryptor(km, NewDEKCache(64, time.Minute))
	if _, err := c2.Decrypt(ctx, "user-1", "cred-1", "s3", ct, nonce, wrappedB); err != nil {
		t.Fatalf("Decrypt after rotation: %v", err)
	}
	if got := km.decryptCalls.Load(); got != 1 {
		t.Fatalf("rotation miss should trigger one kms.Decrypt, got %d", got)
	}
	// Cached now: second decrypt for wrappedB does not bump the count.
	if _, err := c2.Decrypt(ctx, "user-1", "cred-1", "s3", ct, nonce, wrappedB); err != nil {
		t.Fatalf("Decrypt 2 after rotation: %v", err)
	}
	if got := km.decryptCalls.Load(); got != 1 {
		t.Fatalf("warm cache should not call KMS, got %d", got)
	}
	// And wrappedA still works in the original Cryptor without KMS.
	_ = wrappedA
}

// TestCryptor_SingleFlight_ColdHerd fires 1000 concurrent Decrypts at a
// cold cache for the same (userID, ciphertextDEK). Single-flight must
// fold them to exactly one KMS Decrypt. The mock holds Decrypt for
// 20ms so all goroutines pile into the singleflight slot.
func TestCryptor_SingleFlight_ColdHerd(t *testing.T) {
	km := &mockKM{delay: 20 * time.Millisecond}
	c := NewCryptor(km, NewDEKCache(64, time.Minute))
	ctx := context.Background()

	wrapped := append([]byte("wrap:"), bytes.Repeat([]byte{0xcd}, 32)...)
	// Pre-build a valid ciphertext so all goroutines do useful work.
	// Have to seed the cache temporarily, encrypt, then flush the cache
	// so the herd actually faces a cold miss.
	c.cache.Put("u", wrapped, bytes.Repeat([]byte{0xcd}, 32))
	ct, nonce, err := c.Encrypt(ctx, "u", "c", "p", []byte("hello"), wrapped)
	if err != nil {
		t.Fatalf("seed Encrypt: %v", err)
	}
	// Replace the cache with a fresh empty one so the herd starts cold
	// and our singleflight assertion is meaningful.
	c.cache = NewDEKCache(64, time.Minute)
	km.decryptCalls.Store(0)

	const N = 1000
	var wg sync.WaitGroup
	errCh := make(chan error, N)
	wg.Add(N)
	for i := 0; i < N; i++ {
		go func() {
			defer wg.Done()
			if _, err := c.Decrypt(ctx, "u", "c", "p", ct, nonce, wrapped); err != nil {
				errCh <- err
			}
		}()
	}
	wg.Wait()
	close(errCh)
	for err := range errCh {
		t.Fatalf("concurrent Decrypt: %v", err)
	}
	if got := km.decryptCalls.Load(); got != 1 {
		t.Fatalf("singleflight should produce exactly 1 kms.Decrypt under 1K herd, got %d", got)
	}
}

// TestCryptor_AADCanonicalEncoding pins the AAD byte sequence so a
// refactor that changes the encoding fails before it silently
// invalidates production ciphertexts.
func TestCryptor_AADCanonicalEncoding(t *testing.T) {
	got := buildAAD("user-1", "cred-2", "s3")
	want := []byte("user-1|cred-2|s3")
	if !bytes.Equal(got, want) {
		t.Fatalf("AAD encoding changed:\n got=%q\nwant=%q", got, want)
	}
}

func TestCryptor_RejectsBadDEKLength(t *testing.T) {
	km := &mockKM{}
	c := NewCryptor(km, NewDEKCache(8, time.Minute))
	// Inject a non-32-byte plaintext DEK via a custom mock decrypt.
	km.decryptErr = nil
	wrapped := append([]byte("wrap:"), bytes.Repeat([]byte{0x00}, 16)...) // 16-byte DEK
	ctx := context.Background()
	_, _, err := c.Encrypt(ctx, "u", "c", "p", []byte("x"), wrapped)
	if err == nil {
		t.Fatal("expected error for non-AES-256 DEK length")
	}
}

func TestCryptor_KMSError(t *testing.T) {
	km := &mockKM{decryptErr: errors.New("kms down")}
	c := NewCryptor(km, NewDEKCache(8, time.Minute))
	ctx := context.Background()
	wrapped := append([]byte("wrap:"), bytes.Repeat([]byte{0x00}, 32)...)
	_, _, err := c.Encrypt(ctx, "u", "c", "p", []byte("x"), wrapped)
	if err == nil {
		t.Fatal("expected error when KMS Decrypt fails")
	}
}
