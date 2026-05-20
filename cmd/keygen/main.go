// cmd/keygen generates a fresh ed25519 keypair for trial-mode
// capability-token signing. The PUBLIC half is what the vault binary
// reads via COFFER_GRANT_PUBKEY_PEM to verify grant tokens (ADR 0002,
// PRD 0002); the PRIVATE half is what cmd/mint-grant / the control
// plane uses to mint those tokens.
//
// Production keys come from the control plane — this binary is
// dev-only. Each invocation produces fresh keys; rotate at will.
//
// Usage:
//
//	make gen-keys   # alias for `make keygen`
//	make keygen
//	# or
//	go run ./cmd/keygen
//
// Output is two PEM blocks to stdout, separated by labelled banners.
// Pipe / copy as needed; the binary does not write files.
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"os"
)

func main() {
	if err := run(rand.Reader, os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "keygen:", err)
		os.Exit(1)
	}
}

// run is the testable entry point. randSrc is the entropy source
// (crypto/rand.Reader in production). out receives the two PEM blocks
// with banner lines between them.
func run(randSrc io.Reader, out io.Writer) error {
	pub, priv, err := ed25519.GenerateKey(randSrc)
	if err != nil {
		return fmt.Errorf("ed25519.GenerateKey: %w", err)
	}
	pubBytes, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return fmt.Errorf("marshal public: %w", err)
	}
	privBytes, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return fmt.Errorf("marshal private: %w", err)
	}
	fmt.Fprintln(out, "--- PUBLIC (paste into COFFER_GRANT_PUBKEY_PEM) ---")
	fmt.Fprint(out, string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubBytes})))
	fmt.Fprintln(out, "--- PRIVATE (paste into COFFER_GRANT_PRIVKEY_PEM; never commit) ---")
	fmt.Fprint(out, string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privBytes})))
	return nil
}
