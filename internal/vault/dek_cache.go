package vault

import (
	"crypto/sha256"
	"encoding/hex"
	"sync"
	"time"

	lru "github.com/hashicorp/golang-lru/v2"
)

// DEKCache holds plaintext data-encryption keys keyed by (userID,
// ciphertextDEK). The cache is the only place plaintext DEKs live in
// process memory; on eviction (capacity, TTL, or rotation) the byte
// slice is overwritten with zeros (defense-in-depth per ADR 0004).
//
// Implementations are safe for concurrent use.
type DEKCache interface {
	// Get returns a freshly-allocated copy of the plaintext DEK and ok=true
	// on a live cache entry. A miss (no entry, or entry past TTL) returns
	// nil, false. Returning a copy isolates callers from eviction-time
	// zeroing of the cache's own slice.
	Get(userID string, ciphertextDEK []byte) (plaintextDEK []byte, ok bool)

	// Put stores a copy of plaintextDEK under (userID, ciphertextDEK) with
	// an expiry of now()+ttl. Replaces any existing entry for the same key
	// (and zeroes the previous entry's plaintext via OnEvict).
	Put(userID string, ciphertextDEK, plaintextDEK []byte)
}

// entry is the cache value. plaintextDEK is the live byte slice the
// cache owns; OnEvicted zeroes it.
type entry struct {
	plaintextDEK []byte
	expiresAt    time.Time
}

// dekCache is the production implementation backed by golang-lru/v2.
type dekCache struct {
	mu  sync.Mutex // serializes lookup+expiry-remove against Put/eviction
	lru *lru.Cache[string, *entry]
	ttl time.Duration
	now func() time.Time
}

// NewDEKCache returns a DEKCache with the given LRU capacity and TTL,
// using time.Now for expiry checks. ADR 0004 sets the production defaults
// (~100K entries, 5-minute TTL).
func NewDEKCache(maxEntries int, ttl time.Duration) DEKCache {
	return newDEKCache(maxEntries, ttl, time.Now)
}

// NewDEKCacheWithClock is a test-only constructor that injects a clock
// function so TTL expiry can be exercised deterministically.
func NewDEKCacheWithClock(maxEntries int, ttl time.Duration, now func() time.Time) DEKCache {
	return newDEKCache(maxEntries, ttl, now)
}

func newDEKCache(maxEntries int, ttl time.Duration, now func() time.Time) *dekCache {
	c := &dekCache{ttl: ttl, now: now}
	// OnEvicted zeros the plaintext bytes the cache owned. Triggered on
	// LRU capacity eviction, explicit Remove (used for TTL expiry), and
	// Put replacement of an existing key.
	lc, err := lru.NewWithEvict[string, *entry](maxEntries, func(_ string, v *entry) {
		zero(v.plaintextDEK)
	})
	if err != nil {
		// lru.NewWithEvict only errors on size<=0. NewDEKCache callers
		// pass a fixed ADR-0004 value; this is a programmer error.
		panic(err)
	}
	c.lru = lc
	return c
}

func (c *dekCache) Get(userID string, ciphertextDEK []byte) ([]byte, bool) {
	key := cacheKey(userID, ciphertextDEK)
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.lru.Get(key)
	if !ok {
		return nil, false
	}
	if !c.now().Before(e.expiresAt) {
		// Past TTL: remove (triggers OnEvicted zeroing) and miss.
		c.lru.Remove(key)
		return nil, false
	}
	out := make([]byte, len(e.plaintextDEK))
	copy(out, e.plaintextDEK)
	return out, true
}

func (c *dekCache) Put(userID string, ciphertextDEK, plaintextDEK []byte) {
	key := cacheKey(userID, ciphertextDEK)
	owned := make([]byte, len(plaintextDEK))
	copy(owned, plaintextDEK)
	c.mu.Lock()
	defer c.mu.Unlock()
	c.lru.Add(key, &entry{
		plaintextDEK: owned,
		expiresAt:    c.now().Add(c.ttl),
	})
}

// cacheKey scopes by userID and tags the wrapped DEK identity so a
// rotation (new ciphertextDEK for the same user) is treated as a fresh
// entry. SHA-256 truncated to 8 bytes is sufficient: the userID prefix
// confines collisions to within one tenant's own rotated DEKs.
func cacheKey(userID string, ciphertextDEK []byte) string {
	sum := sha256.Sum256(ciphertextDEK)
	return userID + ":" + hex.EncodeToString(sum[:8])
}

// zero overwrites b with zeros. Used by OnEvicted to wipe plaintext DEKs.
func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
