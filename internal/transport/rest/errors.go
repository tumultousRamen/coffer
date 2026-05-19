package rest

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strings"

	"github.com/tumultousRamen/coffer/internal/vault"
)

// errMissingUserID is the sentinel returned by readUserID when the
// caller did not set X-User-Id. Trial-only — production gateway
// JWT-verifies and injects the header before forwarding.
var errMissingUserID = errors.New("rest: X-User-Id header required")

// errUnsupportedMediaType is returned when POST/PUT arrive without
// Content-Type: application/json (or a charset-suffixed variant).
var errUnsupportedMediaType = errors.New("rest: unsupported media type")

// writeError narrows vault sentinels (and a few transport-only
// sentinels) to HTTP status codes per the table in PRD 0007 §2.
//
// Mirror of grpc.mapStatus: error messages elide internal detail so
// the body cannot help an attacker map the system. The status code
// carries the semantic; the body is a generic human-readable hint.
func writeError(w http.ResponseWriter, r *http.Request, logger *slog.Logger, err error) {
	switch {
	case errors.Is(err, errMissingUserID):
		writeJSON(w, http.StatusBadRequest, ErrorResponse{Error: "X-User-Id header required"})

	case errors.Is(err, errUnsupportedMediaType):
		writeJSON(w, http.StatusUnsupportedMediaType, ErrorResponse{Error: "Content-Type must be application/json"})

	case errors.Is(err, vault.ErrNotFound):
		writeJSON(w, http.StatusNotFound, ErrorResponse{Error: "not found"})

	case errors.Is(err, vault.ErrAlreadyExists):
		writeJSON(w, http.StatusConflict, ErrorResponse{Error: "credential with that provider+label already exists"})

	case errors.Is(err, vault.ErrTenantNotProvisioned):
		writeJSON(w, http.StatusPreconditionFailed, ErrorResponse{Error: "tenant not provisioned"})

	case errors.Is(err, vault.ErrUnauthorized):
		writeJSON(w, http.StatusForbidden, ErrorResponse{Error: "unauthorized"})

	case errors.Is(err, vault.ErrInvalidArgument):
		writeJSON(w, http.StatusBadRequest, ErrorResponse{Error: "invalid argument"})

	case errors.Is(err, vault.ErrProviderUnknown):
		// Per the providers.go doc: ErrProviderUnknown surfaces as 400
		// — caller passed a provider string the vault has no adapter for.
		writeJSON(w, http.StatusBadRequest, ErrorResponse{Error: "unknown provider"})

	case errors.Is(err, vault.ErrProviderValidation):
		// 422 Unprocessable Entity: the request was well-formed and
		// the provider was known, but the secret failed the provider's
		// authentication probe. PRD 0008 §5: the provider-side reason
		// (e.g. the AWS InvalidAccessKeyId message) is surfaced in the
		// body for trial-mode debugging. Production hardening will
		// scrub sensitive substrings (account IDs, canonical user IDs)
		// from this reason — see the TODO at the wrap site in the S3
		// provider.
		writeJSON(w, http.StatusUnprocessableEntity, ErrorResponse{
			Error:  "provider validation failed",
			Reason: providerValidationReason(err),
		})

	case errors.Is(err, context.DeadlineExceeded):
		writeJSON(w, http.StatusGatewayTimeout, ErrorResponse{Error: "deadline exceeded"})

	case errors.Is(err, context.Canceled):
		// Client gave up; nothing useful to send but be explicit.
		writeJSON(w, 499, ErrorResponse{Error: "client canceled"})

	default:
		// Log the real error server-side; respond with a generic
		// message. The audit trail lives in the log, not the body.
		if logger != nil {
			logger.Error("rest: internal error",
				"path", r.URL.Path,
				"method", r.Method,
				"err", err.Error(),
			)
		}
		writeJSON(w, http.StatusInternalServerError, ErrorResponse{Error: "internal"})
	}
}

// providerValidationReason extracts the provider-side reason from an
// ErrProviderValidation-wrapped error. Providers wrap as
// `fmt.Errorf("%w: <reason>", vault.ErrProviderValidation)`, so the
// reason follows the first ": " after the sentinel's literal. If the
// wrap shape ever drifts (e.g. extra wrap layers), returns the full
// error string minus the sentinel prefix — never the empty string,
// so the body always carries some diagnostic.
func providerValidationReason(err error) string {
	const sep = ": "
	msg := err.Error()
	sentinel := vault.ErrProviderValidation.Error()
	rest := strings.TrimPrefix(msg, sentinel)
	if rest == msg {
		// Sentinel wasn't the prefix — the error was wrapped with
		// additional context before the provider wrap. Strip the
		// sentinel substring wherever it appears.
		if idx := strings.Index(msg, sentinel); idx >= 0 {
			rest = msg[idx+len(sentinel):]
		} else {
			return msg
		}
	}
	return strings.TrimPrefix(rest, sep)
}

// writeJSON encodes v as JSON, sets the content type, and writes the
// status code. Errors from encoding are unlikely (all writer types
// in this package are JSON-safe stdlib structs) and silently dropped —
// the response is partially written by the time encoding fails, so
// there is nothing useful to recover.
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
