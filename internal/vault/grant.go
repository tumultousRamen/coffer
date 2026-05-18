// Package vault — GrantVerifier verifies the per-job capability
// tokens that transfer workers present on every GetCredentials call
// (ADR 0002). A grant token is a JWT signed by the control plane
// (ed25519) bearing a sub (user_id), a credential_ids list naming
// the exact rows the token authorizes, an aud of "coffer-vault",
// an iss of "coffer-control-plane", and an exp typically ~15min
// after iat.
//
// The vault holds only the public key. Production token minting
// lives in the control plane / gateway; the MintGrant helper in
// this file exists for tests and the trial gateway and uses the
// caller-supplied private key.
package vault

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// Claims is the schema baked into every grant token. Mirrors ADR
// 0002's "Token claims" list; the JSON tags pin the wire shape.
type Claims struct {
	jwt.RegisteredClaims
	CredentialIDs []string `json:"credential_ids"`
}

const (
	GrantIssuer   = "coffer-control-plane"
	GrantAudience = "coffer-vault"

	// grantClockSkew is the leeway we apply to iat/exp checks to
	// tolerate small clock drift between the control plane and the
	// vault. ADR 0002 doesn't pin a value; 60s is the JWT convention.
	grantClockSkew = 60 * time.Second
)

// Grant-verification sentinel errors. The transport layer maps these
// to gRPC Unauthenticated; the service layer surfaces them up the
// stack. Callers compare with errors.Is rather than string-matching.
var (
	ErrGrantMalformed     = errors.New("vault: grant malformed")
	ErrGrantSignature     = errors.New("vault: grant signature invalid")
	ErrGrantExpired       = errors.New("vault: grant expired")
	ErrGrantWrongAudience = errors.New("vault: grant wrong audience")
	ErrGrantWrongIssuer   = errors.New("vault: grant wrong issuer")
	ErrGrantMissingClaim  = errors.New("vault: grant missing claim")
)

// GrantVerifier verifies grant tokens against a fixed ed25519 public
// key. Safe for concurrent use; the underlying jwt library is.
type GrantVerifier struct {
	pubKey ed25519.PublicKey
}

// NewGrantVerifier constructs a verifier bound to pubKey. A nil key
// is rejected at construction time — a misconfigured vault should
// fail loudly at boot rather than silently accept every signature.
func NewGrantVerifier(pubKey ed25519.PublicKey) *GrantVerifier {
	if len(pubKey) != ed25519.PublicKeySize {
		panic(fmt.Sprintf("vault: GrantVerifier needs %d-byte ed25519 public key, got %d", ed25519.PublicKeySize, len(pubKey)))
	}
	return &GrantVerifier{pubKey: pubKey}
}

// Verify parses, signature-checks, and claim-validates token. On
// success it returns (userID, allowedCredentialIDs).
//
// The set of checks: signature (ed25519), iss == GrantIssuer,
// aud contains GrantAudience, exp > now - skew, iat <= now + skew,
// sub non-empty, credential_ids non-empty. Any failure returns a
// typed sentinel; the transport interceptor maps them all to gRPC
// Unauthenticated with a generic message (the typed value never
// reaches the worker — it stays in vault logs for incident analysis).
func (v *GrantVerifier) Verify(token string) (userID string, allowedIDs []string, err error) {
	parser := jwt.NewParser(
		jwt.WithValidMethods([]string{"EdDSA"}),
		jwt.WithIssuer(GrantIssuer),
		jwt.WithAudience(GrantAudience),
		jwt.WithLeeway(grantClockSkew),
		jwt.WithExpirationRequired(),
	)
	var claims Claims
	parsed, err := parser.ParseWithClaims(token, &claims, func(t *jwt.Token) (interface{}, error) {
		// Parser is already restricted to EdDSA above; this is the
		// key-resolution callback the library requires.
		return v.pubKey, nil
	})
	if err != nil {
		return "", nil, mapJWTError(err)
	}
	if !parsed.Valid {
		return "", nil, ErrGrantSignature
	}
	if claims.Subject == "" {
		return "", nil, fmt.Errorf("%w: sub", ErrGrantMissingClaim)
	}
	if len(claims.CredentialIDs) == 0 {
		return "", nil, fmt.Errorf("%w: credential_ids", ErrGrantMissingClaim)
	}
	return claims.Subject, claims.CredentialIDs, nil
}

// mapJWTError narrows a jwt/v5 parsing error to one of the typed
// grant sentinels. The library uses errors.Is-compatible sentinels
// for each failure mode, so the translation is mechanical.
func mapJWTError(err error) error {
	switch {
	case errors.Is(err, jwt.ErrTokenExpired), errors.Is(err, jwt.ErrTokenNotValidYet):
		return ErrGrantExpired
	case errors.Is(err, jwt.ErrTokenInvalidAudience):
		return ErrGrantWrongAudience
	case errors.Is(err, jwt.ErrTokenInvalidIssuer):
		return ErrGrantWrongIssuer
	case errors.Is(err, jwt.ErrSignatureInvalid),
		errors.Is(err, jwt.ErrTokenSignatureInvalid),
		errors.Is(err, jwt.ErrTokenUnverifiable):
		return ErrGrantSignature
	case errors.Is(err, jwt.ErrTokenMalformed),
		errors.Is(err, jwt.ErrTokenInvalidClaims),
		errors.Is(err, jwt.ErrTokenRequiredClaimMissing):
		return ErrGrantMalformed
	}
	// Default: malformed. The transport layer collapses all these
	// onto Unauthenticated anyway; differentiating beyond this point
	// only matters for vault-side telemetry.
	return fmt.Errorf("%w: %v", ErrGrantMalformed, err)
}

// MintGrant signs a grant token with privKey for the given userID +
// credentialIDs with the given lifetime. Intended for tests and the
// trial gateway — production token minting lives in the control
// plane (which uses a different process and a different private
// key entirely). Kept in the same file as Verify so the wire shape
// stays in one place.
//
// jti is the audit-correlation job_id per ADR 0002; callers that
// don't have one (test helpers) can pass an empty string and the
// helper will pick a placeholder.
func MintGrant(
	privKey ed25519.PrivateKey,
	userID string,
	credentialIDs []string,
	ttl time.Duration,
	jti string,
) (string, error) {
	if len(privKey) != ed25519.PrivateKeySize {
		return "", fmt.Errorf("vault: MintGrant needs %d-byte ed25519 private key, got %d", ed25519.PrivateKeySize, len(privKey))
	}
	now := time.Now()
	if jti == "" {
		jti = "test-job"
	}
	claims := Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    GrantIssuer,
			Subject:   userID,
			Audience:  jwt.ClaimStrings{GrantAudience},
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(ttl)),
			ID:        jti,
		},
		CredentialIDs: credentialIDs,
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims)
	return tok.SignedString(privKey)
}
