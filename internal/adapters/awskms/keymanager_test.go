package awskms

import "testing"

// TestNew_PinsKeyAlias is the only thing meaningfully unit-testable for
// a thin SDK wrapper. Real coverage lives in integration_test.go
// (build tag: integration) where the round-trip against real KMS runs.
func TestNew_PinsKeyAlias(t *testing.T) {
	a := New(nil, "alias/coffer-dev-master")
	if a == nil {
		t.Fatal("New returned nil")
	}
	if a.keyAlias != "alias/coffer-dev-master" {
		t.Fatalf("keyAlias=%q want alias/coffer-dev-master", a.keyAlias)
	}
}
