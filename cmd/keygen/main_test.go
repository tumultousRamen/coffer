package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"testing"
)

// TestKeygenRoundtrip is the acceptance check from PRD 0008.5: the
// printed pubkey verifies a message signed by the printed privkey.
// Captures stdout via a buffer, parses both PEM blocks, signs and
// verifies. Failure here means the output of `make gen-keys` is not
// directly usable as the COFFER_GRANT_*_PEM env vars — which is the
// only thing this binary exists to do.
func TestKeygenRoundtrip(t *testing.T) {
	var out bytes.Buffer
	if err := run(rand.Reader, &out); err != nil {
		t.Fatalf("run: %v", err)
	}
	raw := out.Bytes()

	pubBlock, rest := pem.Decode(raw)
	if pubBlock == nil || pubBlock.Type != "PUBLIC KEY" {
		t.Fatalf("first PEM block missing or wrong type: %+v", pubBlock)
	}
	privBlock, _ := pem.Decode(rest)
	if privBlock == nil || privBlock.Type != "PRIVATE KEY" {
		t.Fatalf("second PEM block missing or wrong type: %+v", privBlock)
	}

	pubAny, err := x509.ParsePKIXPublicKey(pubBlock.Bytes)
	if err != nil {
		t.Fatalf("ParsePKIXPublicKey: %v", err)
	}
	pub, ok := pubAny.(ed25519.PublicKey)
	if !ok {
		t.Fatalf("public key type: got %T want ed25519.PublicKey", pubAny)
	}

	privAny, err := x509.ParsePKCS8PrivateKey(privBlock.Bytes)
	if err != nil {
		t.Fatalf("ParsePKCS8PrivateKey: %v", err)
	}
	priv, ok := privAny.(ed25519.PrivateKey)
	if !ok {
		t.Fatalf("private key type: got %T want ed25519.PrivateKey", privAny)
	}

	msg := []byte("the foundation runbook reminds us about port 6543")
	sig := ed25519.Sign(priv, msg)
	if !ed25519.Verify(pub, msg, sig) {
		t.Fatal("signature did not verify with paired public key")
	}
}
