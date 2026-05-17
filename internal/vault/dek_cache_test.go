package vault

import (
	"bytes"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestDEKCache_HitAndMiss(t *testing.T) {
	c := NewDEKCache(8, time.Minute)
	dek := []byte("0123456789abcdef0123456789abcdef")
	wrapped := []byte("ct-1")

	if _, ok := c.Get("user-1", wrapped); ok {
		t.Fatal("Get on empty cache must miss")
	}
	c.Put("user-1", wrapped, dek)
	got, ok := c.Get("user-1", wrapped)
	if !ok {
		t.Fatal("Get after Put must hit")
	}
	if !bytes.Equal(got, dek) {
		t.Fatalf("Get returned wrong bytes: %x vs %x", got, dek)
	}
	if _, ok := c.Get("user-2", wrapped); ok {
		t.Fatal("Get with different userID must miss")
	}
	if _, ok := c.Get("user-1", []byte("ct-2")); ok {
		t.Fatal("Get with different ciphertextDEK must miss (rotation)")
	}
}

func TestDEKCache_GetReturnsCopy(t *testing.T) {
	c := NewDEKCache(8, time.Minute)
	dek := []byte("0123456789abcdef0123456789abcdef")
	c.Put("u", []byte("ct"), dek)
	got1, _ := c.Get("u", []byte("ct"))
	// Mutating the returned slice must not affect future Gets.
	for i := range got1 {
		got1[i] = 0xff
	}
	got2, _ := c.Get("u", []byte("ct"))
	if !bytes.Equal(got2, dek) {
		t.Fatalf("cache returned aliased slice; second Get mutated: %x", got2)
	}
}

func TestDEKCache_TTLExpiry(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	clock := func() time.Time { return now }
	c := NewDEKCacheWithClock(8, time.Minute, clock)

	c.Put("u", []byte("ct"), []byte("0123456789abcdef0123456789abcdef"))
	if _, ok := c.Get("u", []byte("ct")); !ok {
		t.Fatal("expected hit immediately after Put")
	}
	now = now.Add(time.Minute) // exactly at expiry — treat as expired
	if _, ok := c.Get("u", []byte("ct")); ok {
		t.Fatal("expected miss at TTL boundary")
	}
	now = now.Add(time.Hour)
	if _, ok := c.Get("u", []byte("ct")); ok {
		t.Fatal("expected miss well past TTL")
	}
}

func TestDEKCache_LRUEviction(t *testing.T) {
	c := NewDEKCache(2, time.Minute)
	c.Put("u", []byte("ct-a"), []byte("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"))
	c.Put("u", []byte("ct-b"), []byte("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"))
	c.Put("u", []byte("ct-c"), []byte("cccccccccccccccccccccccccccccccc"))

	if _, ok := c.Get("u", []byte("ct-a")); ok {
		t.Fatal("oldest entry should have been evicted")
	}
	if _, ok := c.Get("u", []byte("ct-b")); !ok {
		t.Fatal("ct-b should still be present")
	}
	if _, ok := c.Get("u", []byte("ct-c")); !ok {
		t.Fatal("ct-c should still be present")
	}
}

// TestDEKCache_ZeroOnEvict verifies the OnEvicted callback wipes the
// plaintext slice the cache owns. We can't peek into the cache's owned
// slice directly, so we drive eviction and assert the ZeroAware
// instrumentation hook fires with all-zeros bytes.
func TestDEKCache_ZeroOnEvict(t *testing.T) {
	c := newDEKCache(2, time.Minute, time.Now)

	// Capture the byte slices the cache stores by reaching into the entry
	// before eviction. We snapshot the pointer/length, force eviction,
	// then read the same backing array.
	c.Put("u", []byte("ct-a"), []byte("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"))
	e, ok := c.lru.Peek(cacheKey("u", []byte("ct-a")))
	if !ok {
		t.Fatal("entry should be present")
	}
	owned := e.plaintextDEK // shares backing array with cache's slice

	c.Put("u", []byte("ct-b"), []byte("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"))
	c.Put("u", []byte("ct-c"), []byte("cccccccccccccccccccccccccccccccc")) // evicts ct-a

	for i, b := range owned {
		if b != 0 {
			t.Fatalf("plaintextDEK[%d]=%x; expected zero after eviction", i, b)
		}
	}
}

func TestDEKCache_ZeroOnTTLExpiry(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	clock := func() time.Time { return now }
	c := newDEKCache(8, time.Minute, clock)

	c.Put("u", []byte("ct"), []byte("0123456789abcdef0123456789abcdef"))
	e, _ := c.lru.Peek(cacheKey("u", []byte("ct")))
	owned := e.plaintextDEK

	now = now.Add(time.Minute) // expire
	if _, ok := c.Get("u", []byte("ct")); ok {
		t.Fatal("expected miss past TTL")
	}
	for i, b := range owned {
		if b != 0 {
			t.Fatalf("plaintextDEK[%d]=%x; expected zero after TTL eviction", i, b)
		}
	}
}

func TestDEKCache_RaceSafety(t *testing.T) {
	c := NewDEKCache(64, time.Minute)
	const writers, readers, iters = 8, 8, 1000

	var wg sync.WaitGroup
	var hits, misses atomic.Int64

	for i := 0; i < writers; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			ct := []byte{byte(id)}
			dek := []byte("0123456789abcdef0123456789abcdef")
			for j := 0; j < iters; j++ {
				c.Put("u", ct, dek)
			}
		}(i)
	}
	for i := 0; i < readers; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			ct := []byte{byte(id % writers)}
			for j := 0; j < iters; j++ {
				if _, ok := c.Get("u", ct); ok {
					hits.Add(1)
				} else {
					misses.Add(1)
				}
			}
		}(i)
	}
	wg.Wait()
	// We don't assert hit/miss counts — only that the race detector is
	// silent and the test completes.
	_ = hits.Load() + misses.Load()
}
