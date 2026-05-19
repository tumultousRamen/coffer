package vault

import (
	"context"
	"errors"
	"sync"
	"testing"
)

// stubProvider is a minimal Provider used only by the registry tests
// here. The richer ConfigurableProvider lives in
// internal/vault/providertest, but importing it from this package
// would create an import cycle (providertest depends on vault).
type stubProvider struct {
	name string
}

func (stubProvider) NeedsScheduledRefresh() bool { return false }
func (stubProvider) Validate(_ context.Context, _ SecretBlob, _ Metadata) error {
	return nil
}
func (s stubProvider) Refresh(_ context.Context, c Credential) (Credential, error) {
	return c, nil
}

func TestProviderRegistry_RegisterAndGet(t *testing.T) {
	r := NewProviderRegistry()
	want := stubProvider{name: "s3"}
	r.Register("s3", want)

	got, err := r.Get("s3")
	if err != nil {
		t.Fatalf("Get(s3) err = %v, want nil", err)
	}
	if got.(stubProvider).name != "s3" {
		t.Errorf("Get(s3) returned %v, want stubProvider{s3}", got)
	}
}

func TestProviderRegistry_GetUnknownReturnsErrProviderUnknown(t *testing.T) {
	r := NewProviderRegistry()
	r.Register("s3", stubProvider{name: "s3"})

	_, err := r.Get("dropbox")
	if !errors.Is(err, ErrProviderUnknown) {
		t.Errorf("Get(dropbox) err = %v, want ErrProviderUnknown", err)
	}
}

func TestProviderRegistry_RegisterTwiceOverwrites(t *testing.T) {
	r := NewProviderRegistry()
	r.Register("s3", stubProvider{name: "first"})
	r.Register("s3", stubProvider{name: "second"})

	got, err := r.Get("s3")
	if err != nil {
		t.Fatalf("Get(s3) err = %v, want nil", err)
	}
	if got.(stubProvider).name != "second" {
		t.Errorf("Get(s3) name = %q, want second (Register must overwrite)", got.(stubProvider).name)
	}
}

func TestProviderRegistry_ConcurrentSafeUnderRace(t *testing.T) {
	// Under `go test -race`, this test surfaces map-concurrent-access
	// data races if the RWMutex is ever removed.
	r := NewProviderRegistry()
	r.Register("s3", stubProvider{name: "s3"})

	const goroutines = 32
	var wg sync.WaitGroup
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = r.Get("s3")
		}()
	}
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			r.Register("s3", stubProvider{name: "s3"})
		}(i)
	}
	wg.Wait()
}

// Compile-time guarantee that NewProviderRegistry returns a value
// satisfying the small consumer-facing interface.
var _ ProviderLookup = (*ProviderRegistry)(nil)
