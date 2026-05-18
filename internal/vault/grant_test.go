package vault

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// newKeypair returns a fresh ed25519 keypair for a single test. Each
// test minting + verifying with its own keypair keeps cases isolated.
func newKeypair(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey: %v", err)
	}
	return pub, priv
}

func TestGrantVerifier_Verify_Valid(t *testing.T) {
	pub, priv := newKeypair(t)
	v := NewGrantVerifier(pub)

	token, err := MintGrant(priv, "user-1", []string{"cred-a", "cred-b"}, 5*time.Minute, "job-42")
	if err != nil {
		t.Fatalf("MintGrant: %v", err)
	}
	sub, ids, err := v.Verify(token)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if sub != "user-1" {
		t.Errorf("sub = %q, want user-1", sub)
	}
	if len(ids) != 2 || ids[0] != "cred-a" || ids[1] != "cred-b" {
		t.Errorf("credential_ids = %v, want [cred-a cred-b]", ids)
	}
}

func TestGrantVerifier_Verify_Expired(t *testing.T) {
	pub, priv := newKeypair(t)
	v := NewGrantVerifier(pub)

	// Mint a token that expired well beyond the clock-skew leeway.
	token, err := MintGrant(priv, "user-1", []string{"cred-a"}, -10*time.Minute, "j")
	if err != nil {
		t.Fatalf("MintGrant: %v", err)
	}
	_, _, err = v.Verify(token)
	if !errors.Is(err, ErrGrantExpired) {
		t.Errorf("Verify expired = %v, want ErrGrantExpired", err)
	}
}

func TestGrantVerifier_Verify_BadSignature(t *testing.T) {
	pubA, privA := newKeypair(t)
	_, privB := newKeypair(t)
	_ = privA

	v := NewGrantVerifier(pubA)
	// Sign with B but verify against A.
	token, err := MintGrant(privB, "user-1", []string{"cred-a"}, 5*time.Minute, "j")
	if err != nil {
		t.Fatalf("MintGrant: %v", err)
	}
	_, _, err = v.Verify(token)
	if !errors.Is(err, ErrGrantSignature) {
		t.Errorf("Verify bad signature = %v, want ErrGrantSignature", err)
	}
}

func TestGrantVerifier_Verify_WrongAudience(t *testing.T) {
	pub, priv := newKeypair(t)
	v := NewGrantVerifier(pub)

	claims := Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    GrantIssuer,
			Subject:   "user-1",
			Audience:  jwt.ClaimStrings{"some-other-service"},
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(5 * time.Minute)),
		},
		CredentialIDs: []string{"cred-a"},
	}
	token, err := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims).SignedString(priv)
	if err != nil {
		t.Fatalf("SignedString: %v", err)
	}
	_, _, err = v.Verify(token)
	if !errors.Is(err, ErrGrantWrongAudience) {
		t.Errorf("Verify wrong aud = %v, want ErrGrantWrongAudience", err)
	}
}

func TestGrantVerifier_Verify_WrongIssuer(t *testing.T) {
	pub, priv := newKeypair(t)
	v := NewGrantVerifier(pub)

	claims := Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    "not-the-control-plane",
			Subject:   "user-1",
			Audience:  jwt.ClaimStrings{GrantAudience},
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(5 * time.Minute)),
		},
		CredentialIDs: []string{"cred-a"},
	}
	token, err := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims).SignedString(priv)
	if err != nil {
		t.Fatalf("SignedString: %v", err)
	}
	_, _, err = v.Verify(token)
	if !errors.Is(err, ErrGrantWrongIssuer) {
		t.Errorf("Verify wrong iss = %v, want ErrGrantWrongIssuer", err)
	}
}

func TestGrantVerifier_Verify_MissingSub(t *testing.T) {
	pub, priv := newKeypair(t)
	v := NewGrantVerifier(pub)

	claims := Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    GrantIssuer,
			Audience:  jwt.ClaimStrings{GrantAudience},
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(5 * time.Minute)),
		},
		CredentialIDs: []string{"cred-a"},
	}
	token, err := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims).SignedString(priv)
	if err != nil {
		t.Fatalf("SignedString: %v", err)
	}
	_, _, err = v.Verify(token)
	if !errors.Is(err, ErrGrantMissingClaim) {
		t.Errorf("Verify missing sub = %v, want ErrGrantMissingClaim", err)
	}
}

func TestGrantVerifier_Verify_MissingCredentialIDs(t *testing.T) {
	pub, priv := newKeypair(t)
	v := NewGrantVerifier(pub)

	token, err := MintGrant(priv, "user-1", []string{}, 5*time.Minute, "j")
	if err != nil {
		t.Fatalf("MintGrant: %v", err)
	}
	_, _, err = v.Verify(token)
	if !errors.Is(err, ErrGrantMissingClaim) {
		t.Errorf("Verify missing credential_ids = %v, want ErrGrantMissingClaim", err)
	}
}

func TestGrantVerifier_Verify_Malformed(t *testing.T) {
	pub, _ := newKeypair(t)
	v := NewGrantVerifier(pub)

	_, _, err := v.Verify("not-a-jwt-at-all")
	if !errors.Is(err, ErrGrantMalformed) {
		t.Errorf("Verify garbage = %v, want ErrGrantMalformed", err)
	}
}

func TestGrantVerifier_Verify_FutureIATBeyondSkew(t *testing.T) {
	pub, priv := newKeypair(t)
	v := NewGrantVerifier(pub)

	future := time.Now().Add(10 * time.Minute) // far beyond grantClockSkew
	claims := Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    GrantIssuer,
			Subject:   "user-1",
			Audience:  jwt.ClaimStrings{GrantAudience},
			IssuedAt:  jwt.NewNumericDate(future),
			NotBefore: jwt.NewNumericDate(future),
			ExpiresAt: jwt.NewNumericDate(future.Add(5 * time.Minute)),
		},
		CredentialIDs: []string{"cred-a"},
	}
	token, err := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims).SignedString(priv)
	if err != nil {
		t.Fatalf("SignedString: %v", err)
	}
	_, _, err = v.Verify(token)
	if !errors.Is(err, ErrGrantExpired) {
		t.Errorf("Verify future iat = %v, want ErrGrantExpired (nbf in future)", err)
	}
}

func TestNewGrantVerifier_PanicsOnEmptyKey(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Errorf("NewGrantVerifier did not panic on empty key")
		}
	}()
	_ = NewGrantVerifier(nil)
}
