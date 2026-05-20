// cmd/mint-grant is a dev-only CLI that mints a capability token
// (grant JWT) for testing the worker-facing gRPC fetch path. It is
// a thin wrapper over vault.MintGrant — any future change to the
// grant claims schema propagates automatically (PRD 0008.5).
//
// In production, grant tokens are minted by the control plane's
// signing service which holds the ed25519 private key. This CLI
// exists so a developer with both halves of the keypair in
// .env.local can produce a token for grpcurl. Never deploy.
//
// Usage:
//
//	go run ./cmd/mint-grant --user-id divya --ids id1,id2 --ttl 15m
//	# or via Makefile:
//	make mint-grant USER=divya IDS=id1,id2 TTL=15m
//
// Flags:
//
//	--user-id      sub claim (required)
//	--ids          comma-separated credential IDs (required)
//	--ttl          token lifetime (default 15m)
//	--privkey-pem  path to private key PEM; if empty, reads
//	               $COFFER_GRANT_PRIVKEY_PEM from env
//	--jti          job_id claim (optional; vault.MintGrant picks a
//	               placeholder if empty)
//
// Token is written to stdout without a trailing newline so the
// output pipes cleanly into other commands.
package main

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/tumultousRamen/coffer/internal/vault"
)

func main() {
	if err := run(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, "mint-grant:", err)
		os.Exit(1)
	}
}

// run is the testable entry point. Args is os.Args[1:]; stdout
// receives the token; stderr receives flag-parser usage on bad input.
func run(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("mint-grant", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var (
		userID     = fs.String("user-id", "", "sub claim (required)")
		idsCSV     = fs.String("ids", "", "comma-separated credential IDs (required)")
		ttl        = fs.Duration("ttl", 15*time.Minute, "token lifetime")
		privKeyPEM = fs.String("privkey-pem", "", "path to ed25519 private key PEM (default: read $COFFER_GRANT_PRIVKEY_PEM)")
		jti        = fs.String("jti", "", "job_id claim (optional)")
	)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *userID == "" {
		return errors.New("--user-id is required")
	}
	if *idsCSV == "" {
		return errors.New("--ids is required")
	}

	pemBytes, err := readPrivKeyPEM(*privKeyPEM)
	if err != nil {
		return err
	}
	priv, err := parseEd25519PrivKeyPEM(pemBytes)
	if err != nil {
		return err
	}

	ids := splitTrim(*idsCSV)
	if len(ids) == 0 {
		return errors.New("--ids parsed empty after trimming")
	}

	token, err := vault.MintGrant(priv, *userID, ids, *ttl, *jti)
	if err != nil {
		return fmt.Errorf("MintGrant: %w", err)
	}
	// No trailing newline — callers commonly capture this into a
	// shell variable and append their own context.
	_, err = io.WriteString(stdout, token)
	return err
}

// readPrivKeyPEM returns the PEM bytes from a file path if path is
// non-empty, otherwise reads $COFFER_GRANT_PRIVKEY_PEM. Returns a
// descriptive error if neither source is populated.
func readPrivKeyPEM(path string) ([]byte, error) {
	if path != "" {
		b, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", path, err)
		}
		return b, nil
	}
	env := os.Getenv("COFFER_GRANT_PRIVKEY_PEM")
	if env == "" {
		return nil, errors.New("--privkey-pem not set and COFFER_GRANT_PRIVKEY_PEM env var is empty")
	}
	return []byte(env), nil
}

// parseEd25519PrivKeyPEM accepts a PKCS8-encoded ed25519 private key
// PEM (the shape `cmd/keygen` emits). Rejects any other key type
// loudly — silent acceptance of an RSA key here would mint tokens the
// vault refuses.
func parseEd25519PrivKeyPEM(p []byte) (ed25519.PrivateKey, error) {
	block, _ := pem.Decode(p)
	if block == nil {
		return nil, errors.New("privkey PEM: no PEM block found")
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse PKCS8 private key: %w", err)
	}
	priv, ok := key.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("expected ed25519 private key, got %T", key)
	}
	return priv, nil
}

func splitTrim(csv string) []string {
	parts := strings.Split(csv, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}
