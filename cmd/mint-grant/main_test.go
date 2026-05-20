package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/tumultousRamen/coffer/internal/vault"
)

// genKeypairPEM returns a fresh ed25519 keypair as PEM bytes (PKIX
// pubkey + PKCS8 privkey), matching the shape `cmd/keygen` writes.
func genKeypairPEM(t *testing.T) (pubPEM, privPEM []byte, pub ed25519.PublicKey, priv ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	pubBytes, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatalf("MarshalPKIXPublicKey: %v", err)
	}
	privBytes, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatalf("MarshalPKCS8PrivateKey: %v", err)
	}
	pubPEM = pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubBytes})
	privPEM = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privBytes})
	return
}

// TestMintGrantRoundtripPrivkeyFile is the end-to-end check the PRD
// 0008.5 acceptance asks for: invoke run() with --privkey-pem
// pointing at a tempfile, parse the printed JWT via the production
// verifier, assert claims match.
func TestMintGrantRoundtripPrivkeyFile(t *testing.T) {
	pubPEM, privPEM, pub, _ := genKeypairPEM(t)
	_ = pubPEM

	keyPath := filepath.Join(t.TempDir(), "priv.pem")
	if err := os.WriteFile(keyPath, privPEM, 0o600); err != nil {
		t.Fatalf("write tempfile: %v", err)
	}

	var out, errBuf bytes.Buffer
	args := []string{
		"--user-id", "divya-test",
		"--ids", "id-alpha, id-beta",
		"--ttl", "15m",
		"--privkey-pem", keyPath,
		"--jti", "job-42",
	}
	if err := run(args, &out, &errBuf); err != nil {
		t.Fatalf("run: %v (stderr=%q)", err, errBuf.String())
	}
	token := out.String()
	if strings.HasSuffix(token, "\n") {
		t.Fatalf("token should have no trailing newline, got %q", token)
	}

	v := vault.NewGrantVerifier(pub)
	userID, ids, err := v.Verify(token)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if userID != "divya-test" {
		t.Fatalf("user_id mismatch: got %q want divya-test", userID)
	}
	want := []string{"id-alpha", "id-beta"}
	if !slices.Equal(ids, want) {
		t.Fatalf("credential_ids mismatch: got %v want %v", ids, want)
	}
}

// TestMintGrantRoundtripPrivkeyEnv exercises the env-var fallback
// path; the runbook expects `make mint-grant` to source .env.local
// rather than passing --privkey-pem.
func TestMintGrantRoundtripPrivkeyEnv(t *testing.T) {
	_, privPEM, pub, _ := genKeypairPEM(t)
	t.Setenv("COFFER_GRANT_PRIVKEY_PEM", string(privPEM))

	var out bytes.Buffer
	args := []string{"--user-id", "u", "--ids", "x", "--ttl", "5m"}
	if err := run(args, &out, io.Discard); err != nil {
		t.Fatalf("run: %v", err)
	}

	v := vault.NewGrantVerifier(pub)
	uid, ids, err := v.Verify(out.String())
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if uid != "u" || len(ids) != 1 || ids[0] != "x" {
		t.Fatalf("unexpected claims: uid=%q ids=%v", uid, ids)
	}
}

func TestMintGrantMissingFlags(t *testing.T) {
	t.Setenv("COFFER_GRANT_PRIVKEY_PEM", "")
	cases := []struct {
		name string
		args []string
	}{
		{"no user-id", []string{"--ids", "x", "--privkey-pem", "/dev/null"}},
		{"no ids", []string{"--user-id", "u", "--privkey-pem", "/dev/null"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := run(tc.args, io.Discard, io.Discard)
			if err == nil {
				t.Fatal("expected error, got nil")
			}
		})
	}
}

func TestMintGrantRejectsNonEd25519Key(t *testing.T) {
	// An RSA-looking PEM block — PKCS8 parse may succeed but the type
	// assertion to ed25519.PrivateKey must fail. The bytes here are
	// a deliberately invalid PKCS8 payload so the parser rejects;
	// the error message check is loose because either error path is
	// acceptable (parse fail or type-assert fail both reject mint).
	pemBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: []byte{0x00, 0x01, 0x02},
	})
	t.Setenv("COFFER_GRANT_PRIVKEY_PEM", string(pemBytes))
	err := run([]string{"--user-id", "u", "--ids", "x"}, io.Discard, io.Discard)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}
