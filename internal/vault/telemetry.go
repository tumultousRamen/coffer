package vault

import "context"

// Telemetry is the unified facade that wraps logging, metrics, tracing
// and audit-log emission (ADR 0009 §1). Application code depends only
// on this interface; the OTel / slog / stdout implementation lives in
// internal/adapters/telemetry/ and is wired in cmd/vault/.
//
// Field, AuditEvent and Label are intentionally constrained so that
// no observability call site can carry a SecretBlob — the type system
// enforces what would otherwise be reviewer discipline.
type Telemetry interface {
	Info(ctx context.Context, msg string, fields ...Field)
	Warn(ctx context.Context, msg string, fields ...Field)
	Error(ctx context.Context, err error, msg string, fields ...Field)
	Audit(ctx context.Context, event AuditEvent)
	StartSpan(ctx context.Context, name string) (context.Context, Span)
	Counter(name string, labels ...Label) Counter
	Histogram(name string, labels ...Label) Histogram
	Gauge(name string, labels ...Label) Gauge
}

// Span is the minimal tracing handle returned by StartSpan. End closes
// the span. AddAttribute records a key/value pair on the span; values
// are typed string|int64|bool so a SecretBlob cannot be attached.
type Span interface {
	End()
	AddAttribute(key string, value SpanAttrValue)
	RecordError(err error)
}

// SpanAttrValue is the closed set of values that may be attached to a
// span attribute. The set deliberately excludes SecretBlob.
type SpanAttrValue struct {
	kind    fieldKind
	strVal  string
	intVal  int64
	boolVal bool
}

func SpanAttrString(s string) SpanAttrValue { return SpanAttrValue{kind: fieldString, strVal: s} }
func SpanAttrInt(i int64) SpanAttrValue     { return SpanAttrValue{kind: fieldInt, intVal: i} }
func SpanAttrBool(b bool) SpanAttrValue     { return SpanAttrValue{kind: fieldBool, boolVal: b} }

// Counter, Histogram and Gauge are minimal metric handles. Each Add /
// Observe / Set call accepts only a numeric value; labels are bound
// when the handle is created via Telemetry.Counter / .Histogram / .Gauge.
type Counter interface {
	Inc()
	Add(delta float64)
}

type Histogram interface {
	Observe(value float64)
}

type Gauge interface {
	Set(value float64)
	Add(delta float64)
}

// Label is a metric label. Both name and value are plain strings so a
// SecretBlob cannot be carried as a label value.
type Label struct {
	Name  string
	Value string
}

// fieldKind discriminates the variant a Field carries.
type fieldKind uint8

const (
	fieldString fieldKind = iota + 1
	fieldInt
	fieldBool
	fieldError
)

// Field is a structured log key/value pair. Construction is restricted
// to the String / Int / Bool / Error helpers below — there is no
// SecretBlob constructor, so a secret cannot enter the logging path
// (ADR 0009 §4).
//
// The internal value fields are unexported and typed: there is no
// `any`-shaped slot a SecretBlob could be injected into.
type Field struct {
	name    string
	kind    fieldKind
	strVal  string
	intVal  int64
	boolVal bool
	errVal  error
}

// Name returns the field's label.
func (f Field) Name() string { return f.name }

// Kind, StringValue, IntValue, BoolValue, ErrorValue are inspection
// hooks for adapter implementations (e.g. the OTel exporter).
func (f Field) Kind() fieldKind   { return f.kind }
func (f Field) StringValue() string { return f.strVal }
func (f Field) IntValue() int64     { return f.intVal }
func (f Field) BoolValue() bool     { return f.boolVal }
func (f Field) ErrorValue() error   { return f.errVal }

// String constructs a string-valued log field.
func String(name, value string) Field {
	return Field{name: name, kind: fieldString, strVal: value}
}

// Int constructs an int64-valued log field.
func Int(name string, value int64) Field {
	return Field{name: name, kind: fieldInt, intVal: value}
}

// Bool constructs a bool-valued log field.
func Bool(name string, value bool) Field {
	return Field{name: name, kind: fieldBool, boolVal: value}
}

// Error constructs an error-valued log field.
func Error(name string, err error) Field {
	return Field{name: name, kind: fieldError, errVal: err}
}

// AuditEvent is the structured payload for security-relevant events
// (ADR 0009 §4). Every field is string-typed; there is no slot for a
// SecretBlob.
type AuditEvent struct {
	Action       string // e.g. "credential.read", "credential.create"
	UserID       string
	CredentialID string
	JobID        string
	Provider     string
	Outcome      string // "success" | "failure"
	Reason       string // free-form, secret-free
}
