package servicecontract

import (
	"context"
	"crypto/rand"
	"errors"
	"sync"
	"sync/atomic"

	"github.com/tumultousRamen/coffer/internal/vault"
)

// CountingKeyManager is a test-only vault.KeyManager. It produces real
// 32-byte AES-256 keys via crypto/rand so AES-GCM seal / open are
// genuinely exercised; the "wrap" is the literal prefix "fake:" ||
// plaintextDEK so Decrypt is invertible without touching any external
// system. Atomic counters expose GenerateDataKey and Decrypt
// invocations so scenarios can assert call-frequency properties (e.g.
// "second credential for the same tenant must not trigger a fresh
// GenerateDataKey").
//
// Bytes-on-the-wire shape is internal to tests. Production code never
// observes them.
type CountingKeyManager struct {
	generateCalls atomic.Int64
	decryptCalls  atomic.Int64

	mu       sync.Mutex
	rotateOK bool // set to true to allow repeated GenerateDataKey under same userID
}

// NewCountingKeyManager returns a fresh CountingKeyManager with zero
// counters.
func NewCountingKeyManager() *CountingKeyManager {
	return &CountingKeyManager{}
}

// GenerateCalls returns the number of GenerateDataKey invocations
// observed since construction.
func (m *CountingKeyManager) GenerateCalls() int64 {
	return m.generateCalls.Load()
}

// DecryptCalls returns the number of Decrypt invocations observed
// since construction.
func (m *CountingKeyManager) DecryptCalls() int64 {
	return m.decryptCalls.Load()
}

// GenerateDataKey returns a freshly-minted 32-byte AES-256 key and its
// "wrapped" form (literally "fake:" prefix). userID is intentionally
// unused; the AWS KMS adapter behaves the same way (tenancy is
// enforced via the Cryptor's cache, not by the KeyManager).
func (m *CountingKeyManager) GenerateDataKey(_ context.Context, _ string) ([]byte, []byte, error) {
	m.generateCalls.Add(1)
	plaintext := make([]byte, 32)
	if _, err := rand.Read(plaintext); err != nil {
		return nil, nil, err
	}
	ciphertext := append([]byte("fake:"), plaintext...)
	return plaintext, ciphertext, nil
}

// Decrypt unwraps a ciphertextDEK produced by GenerateDataKey. The
// expected shape is "fake:" || plaintext; anything else is a wiring
// bug in the test and surfaces as a typed error.
func (m *CountingKeyManager) Decrypt(_ context.Context, ciphertextDEK []byte) ([]byte, error) {
	m.decryptCalls.Add(1)
	if len(ciphertextDEK) < 5 || string(ciphertextDEK[:5]) != "fake:" {
		return nil, errors.New("servicecontract: unknown ciphertextDEK shape")
	}
	out := make([]byte, len(ciphertextDEK)-5)
	copy(out, ciphertextDEK[5:])
	return out, nil
}

// Static interface check — port shape drift breaks the build.
var _ vault.KeyManager = (*CountingKeyManager)(nil)
