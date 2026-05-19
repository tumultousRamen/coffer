// cmd/keygen generates a fresh ed25519 keypair for trial-mode
// capability-token signing. The PUBLIC half is what the vault binary
// reads via COFFER_GRANT_PUBKEY_PEM to verify grant tokens (ADR 0002,
// PRD 0002); the PRIVATE half is what the demo / control plane uses
// to mint those tokens.
//
// Production keys come from the control plane — this binary is
// dev-only. Each invocation produces fresh keys; rotate at will.
//
// Usage:
//
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
	"os"
)

func main() {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		fmt.Fprintf(os.Stderr, "keygen: ed25519.GenerateKey: %v\n", err)
		os.Exit(1)
	}
	pubBytes, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		fmt.Fprintf(os.Stderr, "keygen: marshal public: %v\n", err)
		os.Exit(1)
	}
	privBytes, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		fmt.Fprintf(os.Stderr, "keygen: marshal private: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("--- PUBLIC (paste into COFFER_GRANT_PUBKEY_PEM) ---")
	fmt.Print(string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubBytes})))
	fmt.Println("--- PRIVATE (stash for grant-token signing) ---")
	fmt.Print(string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privBytes})))
}
