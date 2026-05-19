// Package rest is the user-facing transport adapter for the
// credential lifecycle (ADR 0007 §2; PRD 0007). It exposes five
// HTTP routes that delegate to vault.Service:
//
//	POST   /v1/credentials       → Service.CreateCredential
//	GET    /v1/credentials       → Service.ListCredentials
//	GET    /v1/credentials/{id}  → Service.GetCredentialSummary
//	PUT    /v1/credentials/{id}  → Service.ReplaceCredential
//	DELETE /v1/credentials/{id}  → Service.DeleteCredential
//
// Trial-mode auth: the caller's identity is read from the X-User-Id
// header. ADR 0007 §2 makes the gateway responsible for JWT
// verification and for injecting this header in production; trial
// callers (curl, CI scripts) set it directly. A missing or empty
// header is a 400, not a 401 — the trial has no auth concept; the
// gateway returns 401 after JWT verification fails in production.
//
// Hexagonal discipline: this package imports internal/vault for
// Service + sentinels and does NOT import internal/adapters.
// `make check-imports` enforces this.
package rest

import (
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strings"

	"github.com/tumultousRamen/coffer/internal/vault"
)

// maxBodyBytes caps incoming POST/PUT body size to defend the
// process from a malicious oversized upload. 1 MiB is enormous for
// a credential payload (real S3 keys + metadata are well under 4 KB).
const maxBodyBytes = 1 << 20

// Handler wires the credential-lifecycle HTTP routes to a
// vault.Service. logger is used only for the 5xx fall-through in
// writeError — request-level logging is the composition root's job
// (cmd/vault wraps the mux with whatever access logger it wants).
type Handler struct {
	svc    *vault.Service
	logger *slog.Logger
}

// NewHandler constructs a Handler. svc must be non-nil. logger may
// be nil; if it is, internal errors are silently mapped to 500 with
// the generic body.
func NewHandler(svc *vault.Service, logger *slog.Logger) *Handler {
	return &Handler{svc: svc, logger: logger}
}

// Register attaches all five lifecycle routes to mux. Routes use
// Go 1.22+ ServeMux method+path patterns (e.g. "POST /v1/credentials"),
// which the stdlib resolves natively. No third-party router.
//
// The same mux is used for /healthz and /readyz in cmd/vault/main.go;
// the patterns here do not collide.
func (h *Handler) Register(mux *http.ServeMux) {
	mux.HandleFunc("POST /v1/credentials", h.create)
	mux.HandleFunc("GET /v1/credentials", h.list)
	mux.HandleFunc("GET /v1/credentials/{id}", h.getByID)
	mux.HandleFunc("PUT /v1/credentials/{id}", h.replace)
	mux.HandleFunc("DELETE /v1/credentials/{id}", h.delete)
}

func (h *Handler) create(w http.ResponseWriter, r *http.Request) {
	userID, err := readUserID(r)
	if err != nil {
		writeError(w, r, h.logger, err)
		return
	}
	if err := requireJSON(r); err != nil {
		writeError(w, r, h.logger, err)
		return
	}

	var req CreateRequest
	if err := decodeBody(w, r, &req); err != nil {
		writeBodyError(w, r, h.logger, err)
		return
	}

	if req.Provider == "" || req.Label == "" || len(req.Secret) == 0 {
		writeJSON(w, http.StatusBadRequest, ErrorResponse{
			Error: "provider, label, and secret are required",
		})
		return
	}

	id, err := h.svc.CreateCredential(
		r.Context(), userID, req.Provider, req.Label, req.Secret, vault.Metadata(req.Metadata),
	)
	if err != nil {
		writeError(w, r, h.logger, err)
		return
	}
	writeJSON(w, http.StatusCreated, CreateResponse{ID: id})
}

func (h *Handler) list(w http.ResponseWriter, r *http.Request) {
	userID, err := readUserID(r)
	if err != nil {
		writeError(w, r, h.logger, err)
		return
	}

	summaries, err := h.svc.ListCredentials(r.Context(), userID)
	if err != nil {
		writeError(w, r, h.logger, err)
		return
	}
	out := ListResponse{Credentials: make([]SummaryResponse, 0, len(summaries))}
	for _, s := range summaries {
		out.Credentials = append(out.Credentials, toSummaryResponse(s))
	}
	writeJSON(w, http.StatusOK, out)
}

func (h *Handler) getByID(w http.ResponseWriter, r *http.Request) {
	userID, err := readUserID(r)
	if err != nil {
		writeError(w, r, h.logger, err)
		return
	}
	id := r.PathValue("id")
	if id == "" {
		writeJSON(w, http.StatusBadRequest, ErrorResponse{Error: "credential id required"})
		return
	}

	sum, err := h.svc.GetCredentialSummary(r.Context(), userID, id)
	if err != nil {
		writeError(w, r, h.logger, err)
		return
	}
	writeJSON(w, http.StatusOK, toSummaryResponse(sum))
}

func (h *Handler) replace(w http.ResponseWriter, r *http.Request) {
	userID, err := readUserID(r)
	if err != nil {
		writeError(w, r, h.logger, err)
		return
	}
	id := r.PathValue("id")
	if id == "" {
		writeJSON(w, http.StatusBadRequest, ErrorResponse{Error: "credential id required"})
		return
	}
	if err := requireJSON(r); err != nil {
		writeError(w, r, h.logger, err)
		return
	}

	var req ReplaceRequest
	if err := decodeBody(w, r, &req); err != nil {
		writeBodyError(w, r, h.logger, err)
		return
	}
	if len(req.Secret) == 0 {
		writeJSON(w, http.StatusBadRequest, ErrorResponse{Error: "secret is required"})
		return
	}

	if err := h.svc.ReplaceCredential(
		r.Context(), userID, id, req.Secret, vault.Metadata(req.Metadata),
	); err != nil {
		writeError(w, r, h.logger, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) delete(w http.ResponseWriter, r *http.Request) {
	userID, err := readUserID(r)
	if err != nil {
		writeError(w, r, h.logger, err)
		return
	}
	id := r.PathValue("id")
	if id == "" {
		writeJSON(w, http.StatusBadRequest, ErrorResponse{Error: "credential id required"})
		return
	}

	if err := h.svc.DeleteCredential(r.Context(), userID, id); err != nil {
		writeError(w, r, h.logger, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// readUserID extracts the trial-mode caller identity. ADR 0007 §2:
// "vault service trusts the gateway's verified header. For the
// trial, the gateway issues stub JWTs." This PRD short-circuits the
// gateway; the trial caller sets the header directly.
func readUserID(r *http.Request) (string, error) {
	v := strings.TrimSpace(r.Header.Get("X-User-Id"))
	if v == "" {
		return "", errMissingUserID
	}
	return v, nil
}

// requireJSON enforces Content-Type: application/json on POST/PUT.
// Accepts charset suffixes (e.g. "application/json; charset=utf-8").
func requireJSON(r *http.Request) error {
	ct := r.Header.Get("Content-Type")
	// Strip parameters; the bare type must equal application/json.
	if idx := strings.Index(ct, ";"); idx >= 0 {
		ct = ct[:idx]
	}
	if strings.TrimSpace(strings.ToLower(ct)) != "application/json" {
		return errUnsupportedMediaType
	}
	return nil
}

// decodeBody applies MaxBytesReader, strict JSON decode (rejects
// unknown fields and trailing data), and returns the decoder error
// for the caller to triage via writeBodyError.
func decodeBody(w http.ResponseWriter, r *http.Request, dst any) error {
	r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return err
	}
	// Reject trailing tokens to avoid "{...}{...}" confusing the
	// idempotency story (a future Redis-backed PRD will hash the
	// body and any two-document body should produce two hashes).
	if dec.More() {
		return errors.New("trailing data after JSON document")
	}
	return nil
}

// writeBodyError narrows decoder failures into the right HTTP
// status: MaxBytesError → 413, everything else → 400 with a generic
// "invalid json" message.
func writeBodyError(w http.ResponseWriter, r *http.Request, logger *slog.Logger, err error) {
	var mbe *http.MaxBytesError
	if errors.As(err, &mbe) {
		writeJSON(w, http.StatusRequestEntityTooLarge, ErrorResponse{Error: "request body too large"})
		return
	}
	if errors.Is(err, io.EOF) {
		writeJSON(w, http.StatusBadRequest, ErrorResponse{Error: "invalid json: empty body"})
		return
	}
	writeJSON(w, http.StatusBadRequest, ErrorResponse{Error: "invalid json"})
}

func toSummaryResponse(s vault.CredentialSummary) SummaryResponse {
	return SummaryResponse{
		ID:        s.ID,
		Provider:  s.Provider,
		Label:     s.Label,
		Status:    string(s.Status),
		CreatedAt: s.CreatedAt,
	}
}
