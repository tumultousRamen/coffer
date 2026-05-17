package vault

import (
	"reflect"
	"testing"
)

// TestCredentialSummary_HasNoSecretField is a defense-in-depth structural
// guard: even if someone adds a field to CredentialSummary in the future,
// this test fails the build if that field's type is (or contains) a
// SecretBlob. The compile-time read-back guard from ADR 0007 §3 depends
// on CredentialSummary staying secret-free.
func TestCredentialSummary_HasNoSecretField(t *testing.T) {
	secretType := reflect.TypeOf(SecretBlob{})
	target := reflect.TypeOf(CredentialSummary{})

	for i := 0; i < target.NumField(); i++ {
		f := target.Field(i)
		if typeContains(f.Type, secretType) {
			t.Errorf("CredentialSummary field %q has type %v which contains SecretBlob — violates ADR 0007 §3",
				f.Name, f.Type)
		}
	}
}

// typeContains reports whether t is, or transitively contains, target.
// Walks struct fields, slice/array/map element types, and pointer
// indirections. Stops at non-struct kinds to avoid runaway recursion on
// recursive types.
func typeContains(t, target reflect.Type) bool {
	if t == target {
		return true
	}
	switch t.Kind() {
	case reflect.Ptr, reflect.Slice, reflect.Array, reflect.Chan:
		return typeContains(t.Elem(), target)
	case reflect.Map:
		return typeContains(t.Key(), target) || typeContains(t.Elem(), target)
	case reflect.Struct:
		for i := 0; i < t.NumField(); i++ {
			if typeContains(t.Field(i).Type, target) {
				return true
			}
		}
	}
	return false
}
