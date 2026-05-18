// Package s3 is the vault.Provider implementation for Amazon S3.
//
// S3 sits in secret-store mode per ADR 0001: the vault stores the
// long-lived access_key_id / secret_access_key pair and returns it
// plaintext to workers. There is no scheduled refresh
// (NeedsScheduledRefresh returns false) — static AWS access keys
// don't expire on a fixed cadence. Production evolution to STS
// broker mode is contained in this single package per ADR 0001.
//
// Validate calls s3:ListBuckets with the user's submitted credentials
// (NOT the vault's own AWS identity) to prove the key works against
// real AWS before the row is encrypted and persisted. Failures
// (parse, missing region, AWS denial, timeout) are wrapped in
// vault.ErrProviderValidation so the REST transport can surface a
// 422 with the AWS-side reason in the response body.
//
// Why ListBuckets rather than HeadBucket: one credential serves many
// transfer jobs against many buckets in this product, so the
// registration step deliberately doesn't bind a credential to a
// specific bucket. ListBuckets is what AWS recommends for
// credential-validity probes; minimum IAM cost is
// s3:ListAllMyBuckets.
//
// Hexagonal discipline: this package imports internal/vault (for the
// SecretBlob, Metadata, Provider, and ErrProviderValidation types)
// and the AWS SDK. The Service is the only consumer; the REST
// transport never imports this package directly.
package s3

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	awss3 "github.com/aws/aws-sdk-go-v2/service/s3"

	"github.com/tumultousRamen/coffer/internal/vault"
)

// validateTimeout caps the s3:ListBuckets probe so a slow or hung
// AWS endpoint cannot park a POST handler indefinitely. AWS S3
// ListBuckets P99 is typically 50–200ms; 5s covers transient
// slowness without blowing the write SLO budget.
const validateTimeout = 5 * time.Second

// secretPayload is the wire shape of the JSON document the vault
// stores under the encrypted Secret field for an S3 credential.
//
// SessionToken is forward-compat with STS broker mode (ADR 0001
// evolution) and is also consumed today so that integration tests
// driven from an SSO-derived AWS_PROFILE (which yields temporary
// credentials requiring a session token) can authenticate. It is
// optional — long-lived IAM access keys omit it and authenticate
// fine.
type secretPayload struct {
	AccessKeyID     string `json:"access_key_id"`
	SecretAccessKey string `json:"secret_access_key"`
	SessionToken    string `json:"session_token,omitempty"`
}

// listBucketsAPI is the slim slice of *s3.Client this provider
// actually calls. Declaring it as an interface lets tests substitute
// a fake without spinning up the real SDK; production wires the
// concrete client built by configLoader.
type listBucketsAPI interface {
	ListBuckets(ctx context.Context, params *awss3.ListBucketsInput, optFns ...func(*awss3.Options)) (*awss3.ListBucketsOutput, error)
}

// clientFactory builds a listBucketsAPI from the user's submitted
// access keys, optional STS session token, and a region. The default
// factory builds a real S3 SDK client; tests override.
type clientFactory func(ctx context.Context, key, secret, sessionToken, region string) (listBucketsAPI, error)

// Provider implements vault.Provider for S3 (secret-store mode per
// ADR 0001).
type Provider struct {
	newClient clientFactory
	timeout   time.Duration
}

// New returns an S3 Provider wired with the real AWS SDK client
// factory. The validate timeout is the package default
// (validateTimeout). Tests should construct a Provider directly via
// the unexported fields where needed.
func New() *Provider {
	return &Provider{
		newClient: defaultClientFactory,
		timeout:   validateTimeout,
	}
}

// NeedsScheduledRefresh returns false — S3 access keys are static
// and do not expire on a fixed cadence (ADR 0001 table; ADR 0006).
// The future refresh worker will skip enqueueing a refresh_jobs row
// for S3 credentials on this signal.
func (p *Provider) NeedsScheduledRefresh() bool { return false }

// Refresh is a no-op for S3: static credentials never expire so the
// stored row is the current row. Returns c unchanged.
func (p *Provider) Refresh(_ context.Context, c vault.Credential) (vault.Credential, error) {
	return c, nil
}

// Validate parses the secret as {access_key_id, secret_access_key},
// pulls the AWS region from metadata, and calls s3:ListBuckets with
// the user's credentials under a 5s deadline. Any failure — parse,
// missing region, AWS denial, network error, deadline — is wrapped
// in vault.ErrProviderValidation so the REST transport surfaces
// 422 with the AWS-side reason in the body.
//
// TODO(production): scrub sensitive AWS error details (canonical
// user IDs, account IDs that may appear in error strings) from the
// wrapped reason. Trial mode surfaces verbatim for debugging.
func (p *Provider) Validate(ctx context.Context, secret vault.SecretBlob, metadata vault.Metadata) error {
	var payload secretPayload
	if err := json.Unmarshal(secret.Reveal(), &payload); err != nil {
		return fmt.Errorf("%w: secret is not valid JSON: %v", vault.ErrProviderValidation, err)
	}
	if payload.AccessKeyID == "" {
		return fmt.Errorf("%w: access_key_id missing from secret", vault.ErrProviderValidation)
	}
	if payload.SecretAccessKey == "" {
		return fmt.Errorf("%w: secret_access_key missing from secret", vault.ErrProviderValidation)
	}

	region, err := regionFromMetadata(metadata)
	if err != nil {
		return err
	}

	probeCtx, cancel := context.WithTimeout(ctx, p.timeout)
	defer cancel()

	client, err := p.newClient(probeCtx, payload.AccessKeyID, payload.SecretAccessKey, payload.SessionToken, region)
	if err != nil {
		return fmt.Errorf("%w: aws config: %v", vault.ErrProviderValidation, err)
	}

	if _, err := client.ListBuckets(probeCtx, &awss3.ListBucketsInput{}); err != nil {
		// Surface the AWS error verbatim — for trial-mode debugging
		// the InvalidAccessKeyId / SignatureDoesNotMatch reasons are
		// useful in the 422 body. Production hardening will scrub.
		if errors.Is(err, context.DeadlineExceeded) {
			return fmt.Errorf("%w: aws ListBuckets timed out after %s", vault.ErrProviderValidation, p.timeout)
		}
		return fmt.Errorf("%w: %v", vault.ErrProviderValidation, err)
	}
	return nil
}

// regionFromMetadata pulls the "region" key out of the metadata map.
// Missing, non-string, or empty values produce a clear validation
// error rather than passing an empty region to the AWS SDK (which
// would yield a more obscure SDK-side error).
func regionFromMetadata(metadata vault.Metadata) (string, error) {
	raw, ok := metadata["region"]
	if !ok {
		return "", fmt.Errorf("%w: region missing from metadata", vault.ErrProviderValidation)
	}
	region, ok := raw.(string)
	if !ok {
		return "", fmt.Errorf("%w: metadata.region is not a string", vault.ErrProviderValidation)
	}
	if region == "" {
		return "", fmt.Errorf("%w: metadata.region is empty", vault.ErrProviderValidation)
	}
	return region, nil
}

// defaultClientFactory builds a real *awss3.Client using a one-off
// aws.Config sourced from static credentials. The config has no
// lifetime beyond this single Validate call, so there is no
// long-lived AWS identity to manage for the probe. sessionToken is
// empty for long-lived IAM keys; non-empty when the caller passed an
// STS-derived triple (used by the integration test against SSO).
func defaultClientFactory(ctx context.Context, key, secret, sessionToken, region string) (listBucketsAPI, error) {
	cfg, err := config.LoadDefaultConfig(ctx,
		config.WithRegion(region),
		config.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(key, secret, sessionToken)),
	)
	if err != nil {
		return nil, err
	}
	// Defense in depth: ensure the SDK does not silently fall back to
	// an ambient profile / instance role if static creds somehow fail
	// to load. The static provider above is required; this line
	// disables any environment-derived credential fallback.
	cfg.Credentials = aws.NewCredentialsCache(credentials.NewStaticCredentialsProvider(key, secret, sessionToken))
	return awss3.NewFromConfig(cfg), nil
}

// Compile-time guarantee that *Provider satisfies the vault.Provider
// port. Catches signature drift at build time rather than at runtime
// from a missed Register call.
var _ vault.Provider = (*Provider)(nil)
