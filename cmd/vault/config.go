// Package main — config loader for cmd/vault. Pulled into its own
// file so it can be exercised by main_test.go in isolation.
package main

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"strconv"
	"time"
)

// Config holds the entire boot configuration parsed from env vars.
// Per ADR 0010 §2: env vars only — no flags, no files. Defaults
// match the foundation runbook (us-west-1, alias/coffer-dev-master,
// :8443 / :8080, 5min/100k DEK cache).
type Config struct {
	PGURL            string
	AWSRegion        string
	KMSKeyID         string
	GrantPubKey      ed25519.PublicKey
	GRPCListen       string
	HTTPListen       string
	DEKCacheTTL      time.Duration
	DEKCacheMaxItems int
}

// loadConfig parses environment variables into a Config. Returns a
// human-readable error naming the offending variable on the first
// failure; the caller maps that to exit 2.
func loadConfig() (*Config, error) {
	cfg := &Config{
		PGURL:            os.Getenv("COFFER_PG_URL"),
		AWSRegion:        getenvOr("COFFER_AWS_REGION", "us-west-1"),
		KMSKeyID:         getenvOr("COFFER_AWS_KMS_KEY_ID", "alias/coffer-dev-master"),
		GRPCListen:       getenvOr("COFFER_GRPC_LISTEN", ":8443"),
		HTTPListen:       getenvOr("COFFER_HTTP_LISTEN", ":8080"),
		DEKCacheMaxItems: 100_000,
		DEKCacheTTL:      300 * time.Second,
	}
	if cfg.PGURL == "" {
		return nil, errors.New("COFFER_PG_URL not set")
	}

	pemBytes := os.Getenv("COFFER_GRANT_PUBKEY_PEM")
	if pemBytes == "" {
		return nil, errors.New("COFFER_GRANT_PUBKEY_PEM not set")
	}
	pub, err := parseEd25519PublicKeyPEM([]byte(pemBytes))
	if err != nil {
		return nil, fmt.Errorf("COFFER_GRANT_PUBKEY_PEM: %w", err)
	}
	cfg.GrantPubKey = pub

	if v := os.Getenv("COFFER_DEK_CACHE_TTL_SECONDS"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n <= 0 {
			return nil, fmt.Errorf("COFFER_DEK_CACHE_TTL_SECONDS: invalid positive integer %q", v)
		}
		cfg.DEKCacheTTL = time.Duration(n) * time.Second
	}
	if v := os.Getenv("COFFER_DEK_CACHE_MAX_ENTRIES"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n <= 0 {
			return nil, fmt.Errorf("COFFER_DEK_CACHE_MAX_ENTRIES: invalid positive integer %q", v)
		}
		cfg.DEKCacheMaxItems = n
	}
	return cfg, nil
}

func getenvOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

// parseEd25519PublicKeyPEM accepts a PEM block holding a PKIX-encoded
// public key and asserts it is ed25519. Production keys are minted by
// the control plane (or, for the trial, the gateway) and supplied to
// the vault as PEM via env var.
func parseEd25519PublicKeyPEM(b []byte) (ed25519.PublicKey, error) {
	block, _ := pem.Decode(b)
	if block == nil {
		return nil, errors.New("no PEM block found")
	}
	if block.Type != "PUBLIC KEY" {
		return nil, fmt.Errorf("unexpected PEM type %q, want PUBLIC KEY", block.Type)
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse PKIX: %w", err)
	}
	pub, ok := parsed.(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("public key is %T, want ed25519.PublicKey", parsed)
	}
	return pub, nil
}
