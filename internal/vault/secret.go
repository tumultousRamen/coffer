package vault

import (
	"fmt"
	"log/slog"
)

// redactedMarker is what every output channel of SecretBlob emits in place
// of raw plaintext. Defined once so tests and impl agree on the literal.
const redactedMarker = "[REDACTED]"

// SecretBlob holds raw secret bytes (e.g. an S3 secret access key or an
// OAuth refresh token). The zero value is empty and safe to use.
//
// SecretBlob is redacted across every standard output channel:
// fmt formatting verbs, JSON marshalling, and slog. The only path to
// the underlying plaintext is Reveal — every call site is greppable.
type SecretBlob struct {
	raw []byte
}

// NewSecretBlob returns a SecretBlob holding a copy of b. The copy
// prevents external mutation aliasing — callers may safely reuse or
// zero their input slice after construction.
func NewSecretBlob(b []byte) SecretBlob {
	c := make([]byte, len(b))
	copy(c, b)
	return SecretBlob{raw: c}
}

// Reveal returns the raw plaintext bytes. This is the only path to
// plaintext; the name is deliberately loud so call sites are easy to
// audit via grep.
func (s SecretBlob) Reveal() []byte {
	return s.raw
}

func (s SecretBlob) String() string {
	return redactedMarker
}

// Format implements fmt.Formatter so that %v, %+v, %s, %q, %#v and any
// other verb all emit the redaction marker rather than the raw bytes.
func (s SecretBlob) Format(state fmt.State, _ rune) {
	_, _ = fmt.Fprint(state, redactedMarker)
}

func (s SecretBlob) MarshalJSON() ([]byte, error) {
	return []byte(`"` + redactedMarker + `"`), nil
}

// LogValue implements slog.LogValuer so structured logs that include a
// SecretBlob as an attribute value emit the redaction marker.
func (s SecretBlob) LogValue() slog.Value {
	return slog.StringValue(redactedMarker)
}
