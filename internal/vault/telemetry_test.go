package vault

import (
	"reflect"
	"testing"
)

// TestField_NoSecretConstructor asserts that none of the Field
// constructors accept a SecretBlob (or anything containing one). Go
// has no package-level reflection, so we list the constructors
// explicitly — adding a new one without listing it here is fine; the
// risk this test guards against is someone adding `func Secret(name
// string, v SecretBlob) Field`, which the existing list would catch
// only if added. To make the guard load-bearing we therefore also walk
// Field's own struct fields and assert none has SecretBlob type.
func TestField_NoSecretConstructor(t *testing.T) {
	secretType := reflect.TypeOf(SecretBlob{})

	constructors := map[string]any{
		"String": String,
		"Int":    Int,
		"Bool":   Bool,
		"Error":  Error,
	}
	for name, fn := range constructors {
		ft := reflect.TypeOf(fn)
		for i := 0; i < ft.NumIn(); i++ {
			if typeContains(ft.In(i), secretType) {
				t.Errorf("Field constructor %s parameter %d has type %v containing SecretBlob",
					name, i, ft.In(i))
			}
		}
	}

	// Defense in depth: Field's own fields must not carry a SecretBlob.
	fieldType := reflect.TypeOf(Field{})
	for i := 0; i < fieldType.NumField(); i++ {
		f := fieldType.Field(i)
		if typeContains(f.Type, secretType) {
			t.Errorf("Field struct field %q has type %v containing SecretBlob", f.Name, f.Type)
		}
	}
}

func TestAuditEvent_HasNoSecretField(t *testing.T) {
	secretType := reflect.TypeOf(SecretBlob{})
	target := reflect.TypeOf(AuditEvent{})
	for i := 0; i < target.NumField(); i++ {
		f := target.Field(i)
		if typeContains(f.Type, secretType) {
			t.Errorf("AuditEvent field %q has type %v containing SecretBlob — violates ADR 0009 §4",
				f.Name, f.Type)
		}
	}
}

func TestLabel_HasNoSecretField(t *testing.T) {
	secretType := reflect.TypeOf(SecretBlob{})
	target := reflect.TypeOf(Label{})
	for i := 0; i < target.NumField(); i++ {
		f := target.Field(i)
		if typeContains(f.Type, secretType) {
			t.Errorf("Label field %q has type %v containing SecretBlob", f.Name, f.Type)
		}
	}
}

func TestSpanAttrValue_HasNoSecretField(t *testing.T) {
	secretType := reflect.TypeOf(SecretBlob{})
	target := reflect.TypeOf(SpanAttrValue{})
	for i := 0; i < target.NumField(); i++ {
		f := target.Field(i)
		if typeContains(f.Type, secretType) {
			t.Errorf("SpanAttrValue field %q has type %v containing SecretBlob", f.Name, f.Type)
		}
	}
}
