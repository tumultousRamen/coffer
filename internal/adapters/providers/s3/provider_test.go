package s3

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	awss3 "github.com/aws/aws-sdk-go-v2/service/s3"

	"github.com/tumultousRamen/coffer/internal/vault"
)

// fakeListBuckets is the test seam: scenarios assign callOpt to
// control whether ListBuckets succeeds, fails, or hangs.
type fakeListBuckets struct {
	err   error
	delay time.Duration
}

func (f *fakeListBuckets) ListBuckets(ctx context.Context, _ *awss3.ListBucketsInput, _ ...func(*awss3.Options)) (*awss3.ListBucketsOutput, error) {
	if f.delay > 0 {
		select {
		case <-time.After(f.delay):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	if f.err != nil {
		return nil, f.err
	}
	return &awss3.ListBucketsOutput{}, nil
}

// providerWith builds a Provider whose client factory returns the
// supplied fake. Lets each scenario stage a different AWS-side
// outcome without touching the real SDK.
func providerWith(t *testing.T, fake *fakeListBuckets) *Provider {
	t.Helper()
	return &Provider{
		newClient: func(_ context.Context, _, _, _, _ string) (listBucketsAPI, error) {
			return fake, nil
		},
		timeout: validateTimeout,
	}
}

func TestNeedsScheduledRefresh_False(t *testing.T) {
	if New().NeedsScheduledRefresh() {
		t.Errorf("S3 NeedsScheduledRefresh = true, want false (ADR 0001 secret-store mode)")
	}
}

func TestRefresh_NoOp(t *testing.T) {
	p := New()
	cred := vault.Credential{ID: "abc", Provider: "s3", Label: "p"}
	got, err := p.Refresh(context.Background(), cred)
	if err != nil {
		t.Fatalf("Refresh err = %v, want nil", err)
	}
	if got.ID != cred.ID || got.Provider != cred.Provider || got.Label != cred.Label {
		t.Errorf("Refresh mutated credential: got %+v, want %+v", got, cred)
	}
}

func TestValidate_HappyPath(t *testing.T) {
	p := providerWith(t, &fakeListBuckets{})
	secret := vault.NewSecretBlob([]byte(`{"access_key_id":"AKIAEXAMPLE","secret_access_key":"shh"}`))
	err := p.Validate(context.Background(), secret, vault.Metadata{"region": "us-west-1"})
	if err != nil {
		t.Errorf("Validate err = %v, want nil", err)
	}
}

func TestValidate_MalformedJSON(t *testing.T) {
	p := providerWith(t, &fakeListBuckets{})
	secret := vault.NewSecretBlob([]byte(`{not json`))
	err := p.Validate(context.Background(), secret, vault.Metadata{"region": "us-west-1"})
	if !errors.Is(err, vault.ErrProviderValidation) {
		t.Fatalf("Validate malformed err = %v, want ErrProviderValidation", err)
	}
	if !strings.Contains(err.Error(), "JSON") && !strings.Contains(err.Error(), "json") {
		t.Errorf("Validate malformed reason = %q, want it to mention JSON", err.Error())
	}
}

func TestValidate_MissingAccessKey(t *testing.T) {
	p := providerWith(t, &fakeListBuckets{})
	secret := vault.NewSecretBlob([]byte(`{"secret_access_key":"shh"}`))
	err := p.Validate(context.Background(), secret, vault.Metadata{"region": "us-west-1"})
	if !errors.Is(err, vault.ErrProviderValidation) {
		t.Errorf("Validate missing access_key_id err = %v, want ErrProviderValidation", err)
	}
}

func TestValidate_MissingSecretAccessKey(t *testing.T) {
	p := providerWith(t, &fakeListBuckets{})
	secret := vault.NewSecretBlob([]byte(`{"access_key_id":"AKIAEXAMPLE"}`))
	err := p.Validate(context.Background(), secret, vault.Metadata{"region": "us-west-1"})
	if !errors.Is(err, vault.ErrProviderValidation) {
		t.Errorf("Validate missing secret_access_key err = %v, want ErrProviderValidation", err)
	}
}

func TestValidate_ExtraFieldsIgnored(t *testing.T) {
	// Forward-compat with STS broker mode adding a session_token.
	p := providerWith(t, &fakeListBuckets{})
	secret := vault.NewSecretBlob([]byte(`{"access_key_id":"AKIA","secret_access_key":"s","session_token":"future"}`))
	err := p.Validate(context.Background(), secret, vault.Metadata{"region": "us-west-1"})
	if err != nil {
		t.Errorf("Validate with extra fields err = %v, want nil", err)
	}
}

func TestValidate_MissingRegion(t *testing.T) {
	p := providerWith(t, &fakeListBuckets{})
	secret := vault.NewSecretBlob([]byte(`{"access_key_id":"AKIA","secret_access_key":"s"}`))
	err := p.Validate(context.Background(), secret, vault.Metadata{})
	if !errors.Is(err, vault.ErrProviderValidation) {
		t.Fatalf("Validate missing region err = %v, want ErrProviderValidation", err)
	}
	if !strings.Contains(err.Error(), "region") {
		t.Errorf("reason = %q, want it to mention region", err.Error())
	}
}

func TestValidate_EmptyRegion(t *testing.T) {
	p := providerWith(t, &fakeListBuckets{})
	secret := vault.NewSecretBlob([]byte(`{"access_key_id":"AKIA","secret_access_key":"s"}`))
	err := p.Validate(context.Background(), secret, vault.Metadata{"region": ""})
	if !errors.Is(err, vault.ErrProviderValidation) {
		t.Errorf("Validate empty region err = %v, want ErrProviderValidation", err)
	}
}

func TestValidate_NonStringRegion(t *testing.T) {
	p := providerWith(t, &fakeListBuckets{})
	secret := vault.NewSecretBlob([]byte(`{"access_key_id":"AKIA","secret_access_key":"s"}`))
	err := p.Validate(context.Background(), secret, vault.Metadata{"region": 42})
	if !errors.Is(err, vault.ErrProviderValidation) {
		t.Errorf("Validate non-string region err = %v, want ErrProviderValidation", err)
	}
}

func TestValidate_AWSDenial(t *testing.T) {
	awsErr := errors.New("InvalidAccessKeyId: The AWS Access Key Id you provided does not exist in our records.")
	p := providerWith(t, &fakeListBuckets{err: awsErr})
	secret := vault.NewSecretBlob([]byte(`{"access_key_id":"AKIA","secret_access_key":"s"}`))
	err := p.Validate(context.Background(), secret, vault.Metadata{"region": "us-west-1"})
	if !errors.Is(err, vault.ErrProviderValidation) {
		t.Fatalf("Validate AWS denial err = %v, want ErrProviderValidation", err)
	}
	if !strings.Contains(err.Error(), "InvalidAccessKeyId") {
		t.Errorf("reason = %q, want it to surface AWS error verbatim", err.Error())
	}
}

func TestValidate_TimeoutWrapped(t *testing.T) {
	// 50ms client-side timeout, 200ms delay → context.DeadlineExceeded
	// must be wrapped as ErrProviderValidation with a clear reason.
	p := &Provider{
		newClient: func(_ context.Context, _, _, _, _ string) (listBucketsAPI, error) {
			return &fakeListBuckets{delay: 200 * time.Millisecond}, nil
		},
		timeout: 50 * time.Millisecond,
	}
	secret := vault.NewSecretBlob([]byte(`{"access_key_id":"AKIA","secret_access_key":"s"}`))
	err := p.Validate(context.Background(), secret, vault.Metadata{"region": "us-west-1"})
	if !errors.Is(err, vault.ErrProviderValidation) {
		t.Fatalf("Validate timeout err = %v, want ErrProviderValidation", err)
	}
	if !strings.Contains(err.Error(), "timed out") && !strings.Contains(err.Error(), "deadline") {
		t.Errorf("reason = %q, want it to mention timeout/deadline", err.Error())
	}
}

func TestValidate_ClientFactoryError(t *testing.T) {
	factoryErr := errors.New("aws sdk: can't load config")
	p := &Provider{
		newClient: func(_ context.Context, _, _, _, _ string) (listBucketsAPI, error) {
			return nil, factoryErr
		},
		timeout: validateTimeout,
	}
	secret := vault.NewSecretBlob([]byte(`{"access_key_id":"AKIA","secret_access_key":"s"}`))
	err := p.Validate(context.Background(), secret, vault.Metadata{"region": "us-west-1"})
	if !errors.Is(err, vault.ErrProviderValidation) {
		t.Errorf("Validate client-factory err = %v, want ErrProviderValidation", err)
	}
}
