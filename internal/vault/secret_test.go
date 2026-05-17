package vault

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"testing"
)

// plaintextProbe is the canary string. If it ever appears in the output of
// any standard channel for a SecretBlob, the redaction invariant is broken.
const plaintextProbe = "hunter2"

func TestSecretBlob_RedactedAcrossAllChannels(t *testing.T) {
	s := NewSecretBlob([]byte(plaintextProbe))

	jsonOut, err := json.Marshal(s)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}

	var slogBuf bytes.Buffer
	slogger := slog.New(slog.NewJSONHandler(&slogBuf, nil))
	slogger.Info("test", "secret", s)

	cases := []struct {
		name string
		got  string
	}{
		{"String", s.String()},
		{"Sprintf_v", fmt.Sprintf("%v", s)},
		{"Sprintf_plus_v", fmt.Sprintf("%+v", s)},
		{"Sprintf_s", fmt.Sprintf("%s", s)},
		{"Sprintf_q", fmt.Sprintf("%q", s)},
		{"Sprintf_hash_v", fmt.Sprintf("%#v", s)},
		{"Sprintf_struct_wrapping", fmt.Sprintf("%+v", struct{ S SecretBlob }{s})},
		{"json_Marshal", string(jsonOut)},
		{"slog", slogBuf.String()},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if !strings.Contains(tc.got, redactedMarker) {
				t.Errorf("output missing %q marker: %s", redactedMarker, tc.got)
			}
			if strings.Contains(tc.got, plaintextProbe) {
				t.Errorf("output leaked plaintext %q: %s", plaintextProbe, tc.got)
			}
		})
	}
}

func TestSecretBlob_Reveal_RoundTrip(t *testing.T) {
	in := []byte("any-bytes-here")
	got := NewSecretBlob(in).Reveal()
	if !bytes.Equal(got, in) {
		t.Errorf("Reveal returned %q, want %q", got, in)
	}
}

func TestNewSecretBlob_CopiesInput(t *testing.T) {
	original := []byte("original")
	buf := make([]byte, len(original))
	copy(buf, original)

	s := NewSecretBlob(buf)

	// Mutate the caller's slice after construction.
	for i := range buf {
		buf[i] = 'X'
	}

	if !bytes.Equal(s.Reveal(), original) {
		t.Errorf("SecretBlob aliased caller's slice: Reveal()=%q, want %q", s.Reveal(), original)
	}
}

func TestSecretBlob_ZeroValueRedacts(t *testing.T) {
	var s SecretBlob
	if s.String() != redactedMarker {
		t.Errorf("zero-value String()=%q, want %q", s.String(), redactedMarker)
	}
	out, err := json.Marshal(s)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	if !strings.Contains(string(out), redactedMarker) {
		t.Errorf("zero-value json=%q missing %q", out, redactedMarker)
	}
}
