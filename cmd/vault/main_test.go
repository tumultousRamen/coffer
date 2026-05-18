package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"strings"
	"testing"
)

// mustPEM generates a fresh ed25519 keypair and returns the PEM
// encoding of the public key — exactly what production gets via
// COFFER_GRANT_PUBKEY_PEM.
func mustPEM(t *testing.T) string {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey: %v", err)
	}
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatalf("MarshalPKIXPublicKey: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
}

func TestLoadConfig_OK(t *testing.T) {
	t.Setenv("COFFER_PG_URL", "postgres://x:y@h:6543/d")
	t.Setenv("COFFER_GRANT_PUBKEY_PEM", mustPEM(t))

	cfg, err := loadConfig()
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	if cfg.PGURL == "" || cfg.GrantPubKey == nil {
		t.Errorf("config not populated: %+v", cfg)
	}
	if cfg.AWSRegion != "us-west-1" {
		t.Errorf("default AWSRegion = %q, want us-west-1", cfg.AWSRegion)
	}
	if cfg.KMSKeyID != "alias/coffer-dev-master" {
		t.Errorf("default KMSKeyID = %q", cfg.KMSKeyID)
	}
	if cfg.GRPCListen != ":8443" || cfg.HTTPListen != ":8080" {
		t.Errorf("default listen addrs wrong: grpc=%q http=%q", cfg.GRPCListen, cfg.HTTPListen)
	}
	if cfg.DEKCacheMaxItems != 100_000 || cfg.DEKCacheTTL.Seconds() != 300 {
		t.Errorf("default DEK cache wrong: %d/%v", cfg.DEKCacheMaxItems, cfg.DEKCacheTTL)
	}
}

func TestLoadConfig_MissingPGURL(t *testing.T) {
	t.Setenv("COFFER_PG_URL", "")
	t.Setenv("COFFER_GRANT_PUBKEY_PEM", mustPEM(t))
	_, err := loadConfig()
	if err == nil || !strings.Contains(err.Error(), "COFFER_PG_URL") {
		t.Errorf("loadConfig missing PG URL err = %v, want mention of COFFER_PG_URL", err)
	}
}

func TestLoadConfig_MissingPubKey(t *testing.T) {
	t.Setenv("COFFER_PG_URL", "postgres://x:y@h:6543/d")
	t.Setenv("COFFER_GRANT_PUBKEY_PEM", "")
	_, err := loadConfig()
	if err == nil || !strings.Contains(err.Error(), "COFFER_GRANT_PUBKEY_PEM") {
		t.Errorf("loadConfig missing pubkey err = %v, want mention of COFFER_GRANT_PUBKEY_PEM", err)
	}
}

func TestLoadConfig_BadPubKeyPEM(t *testing.T) {
	t.Setenv("COFFER_PG_URL", "postgres://x:y@h:6543/d")
	t.Setenv("COFFER_GRANT_PUBKEY_PEM", "not a PEM block")
	_, err := loadConfig()
	if err == nil || !strings.Contains(err.Error(), "COFFER_GRANT_PUBKEY_PEM") {
		t.Errorf("loadConfig bad PEM err = %v, want mention of COFFER_GRANT_PUBKEY_PEM", err)
	}
}

func TestLoadConfig_BadDEKCacheTTL(t *testing.T) {
	t.Setenv("COFFER_PG_URL", "postgres://x:y@h:6543/d")
	t.Setenv("COFFER_GRANT_PUBKEY_PEM", mustPEM(t))
	t.Setenv("COFFER_DEK_CACHE_TTL_SECONDS", "not-a-number")
	_, err := loadConfig()
	if err == nil {
		t.Error("loadConfig bad TTL err = nil, want non-nil")
	}
}

func TestLoadConfig_NonEd25519Key(t *testing.T) {
	// Construct an RSA public key PEM (a different key type) and
	// confirm the loader rejects it.
	t.Setenv("COFFER_PG_URL", "postgres://x:y@h:6543/d")
	// Smallest path: a syntactically valid PEM block with the wrong
	// type tag; the type-check in parseEd25519PublicKeyPEM rejects.
	t.Setenv("COFFER_GRANT_PUBKEY_PEM", "-----BEGIN RSA PUBLIC KEY-----\nMA==\n-----END RSA PUBLIC KEY-----\n")
	_, err := loadConfig()
	if err == nil {
		t.Error("loadConfig non-ed25519 PEM err = nil, want non-nil")
	}
}
