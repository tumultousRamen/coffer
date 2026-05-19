package rest_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tumultousRamen/coffer/internal/transport/rest"
	"github.com/tumultousRamen/coffer/internal/vault"
	"github.com/tumultousRamen/coffer/internal/vault/providertest"
)

// newRig builds a real vault.Service backed by inline memstore + a
// fake KeyManager, wires the REST handler onto a fresh ServeMux,
// and returns the mux so tests can issue requests via
// httptest.NewRecorder. No network, no port races.
func newRig(t *testing.T) *http.ServeMux {
	t.Helper()
	return newRigWithLookup(t, providertest.PermissiveRegistry())
}

// newRigWithLookup is the variant for tests that exercise the
// provider-validation surface — caller supplies a custom
// ProviderLookup (typically a strict registry holding a
// ConfigurableProvider whose ValidateErr is set per case).
func newRigWithLookup(t *testing.T, lookup vault.ProviderLookup) *http.ServeMux {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey: %v", err)
	}
	verifier := vault.NewGrantVerifier(pub)

	km := &fakeKM{}
	cache := vault.NewDEKCache(64, time.Minute)
	cryptor := vault.NewCryptor(km, cache)
	tenants := newInMemTenants()
	store := newInMemCreds(tenants)
	svc := vault.NewService(store, tenants, cryptor, verifier, lookup)

	mux := http.NewServeMux()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	rest.NewHandler(svc, logger).Register(mux)
	return mux
}

func doJSON(t *testing.T, mux *http.ServeMux, method, path, userID string, body any) *httptest.ResponseRecorder {
	t.Helper()
	var buf bytes.Buffer
	if body != nil {
		if err := json.NewEncoder(&buf).Encode(body); err != nil {
			t.Fatalf("encode body: %v", err)
		}
	}
	r := httptest.NewRequest(method, path, &buf)
	if userID != "" {
		r.Header.Set("X-User-Id", userID)
	}
	if body != nil {
		r.Header.Set("Content-Type", "application/json")
	}
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, r)
	return w
}

func decodeJSON[T any](t *testing.T, w *httptest.ResponseRecorder) T {
	t.Helper()
	var v T
	if err := json.NewDecoder(w.Body).Decode(&v); err != nil {
		t.Fatalf("decode response: %v (body=%q)", err, w.Body.String())
	}
	return v
}

// --- Happy paths ---

func TestPOST_CreateCredential_201(t *testing.T) {
	mux := newRig(t)
	w := doJSON(t, mux, "POST", "/v1/credentials", "user-1", rest.CreateRequest{
		Provider: "s3",
		Label:    "prod_bucket",
		Secret:   []byte("aws-secret-bytes"),
		Metadata: map[string]any{"region": "us-west-1"},
	})
	if w.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201 (body=%q)", w.Code, w.Body.String())
	}
	resp := decodeJSON[rest.CreateResponse](t, w)
	if resp.ID == "" {
		t.Errorf("ID empty in 201 response")
	}
}

func TestGET_ListCredentials_200(t *testing.T) {
	mux := newRig(t)
	for i, label := range []string{"a", "b", "c"} {
		w := doJSON(t, mux, "POST", "/v1/credentials", "user-1", rest.CreateRequest{
			Provider: "s3", Label: label,
			Secret: []byte(fmt.Sprintf("s-%d", i)),
		})
		if w.Code != http.StatusCreated {
			t.Fatalf("seed %d: status = %d, want 201", i, w.Code)
		}
	}

	w := doJSON(t, mux, "GET", "/v1/credentials", "user-1", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	resp := decodeJSON[rest.ListResponse](t, w)
	if len(resp.Credentials) != 3 {
		t.Errorf("len(Credentials) = %d, want 3", len(resp.Credentials))
	}
	for _, c := range resp.Credentials {
		if c.Status != "active" {
			t.Errorf("status = %q, want active", c.Status)
		}
		if c.CreatedAt.IsZero() {
			t.Errorf("created_at zero")
		}
	}
}

func TestGET_GetByID_200(t *testing.T) {
	mux := newRig(t)
	w := doJSON(t, mux, "POST", "/v1/credentials", "user-1", rest.CreateRequest{
		Provider: "s3", Label: "p", Secret: []byte("s"),
	})
	created := decodeJSON[rest.CreateResponse](t, w)

	w = doJSON(t, mux, "GET", "/v1/credentials/"+created.ID, "user-1", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	sum := decodeJSON[rest.SummaryResponse](t, w)
	if sum.ID != created.ID {
		t.Errorf("id = %q, want %q", sum.ID, created.ID)
	}
	if sum.Provider != "s3" || sum.Label != "p" {
		t.Errorf("(provider,label) = (%q,%q), want (s3,p)", sum.Provider, sum.Label)
	}
	if sum.Status != "active" {
		t.Errorf("status = %q, want active", sum.Status)
	}
}

func TestPUT_Replace_204(t *testing.T) {
	mux := newRig(t)
	w := doJSON(t, mux, "POST", "/v1/credentials", "user-1", rest.CreateRequest{
		Provider: "s3", Label: "p", Secret: []byte("v1"),
	})
	created := decodeJSON[rest.CreateResponse](t, w)

	w = doJSON(t, mux, "PUT", "/v1/credentials/"+created.ID, "user-1", rest.ReplaceRequest{
		Secret: []byte("v2"),
	})
	if w.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204 (body=%q)", w.Code, w.Body.String())
	}
}

func TestDELETE_204(t *testing.T) {
	mux := newRig(t)
	w := doJSON(t, mux, "POST", "/v1/credentials", "user-1", rest.CreateRequest{
		Provider: "s3", Label: "p", Secret: []byte("s"),
	})
	created := decodeJSON[rest.CreateResponse](t, w)

	w = doJSON(t, mux, "DELETE", "/v1/credentials/"+created.ID, "user-1", nil)
	if w.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204", w.Code)
	}
	// Verify the row is gone.
	w = doJSON(t, mux, "GET", "/v1/credentials/"+created.ID, "user-1", nil)
	if w.Code != http.StatusNotFound {
		t.Errorf("post-delete GET = %d, want 404", w.Code)
	}
}

// --- Auth (X-User-Id) ---

func TestMissingUserID_400(t *testing.T) {
	mux := newRig(t)
	w := doJSON(t, mux, "GET", "/v1/credentials", "", nil)
	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
}

func TestEmptyUserID_400(t *testing.T) {
	mux := newRig(t)
	r := httptest.NewRequest("GET", "/v1/credentials", nil)
	r.Header.Set("X-User-Id", "   ") // whitespace only — trimmed to empty
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, r)
	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
}

// --- Validation ---

func TestMalformedJSON_400(t *testing.T) {
	mux := newRig(t)
	r := httptest.NewRequest("POST", "/v1/credentials", strings.NewReader("{not json"))
	r.Header.Set("X-User-Id", "user-1")
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, r)
	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400 (body=%q)", w.Code, w.Body.String())
	}
}

func TestMissingProvider_400(t *testing.T) {
	mux := newRig(t)
	w := doJSON(t, mux, "POST", "/v1/credentials", "user-1", rest.CreateRequest{
		Label: "p", Secret: []byte("s"),
	})
	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
}

func TestMissingLabel_400(t *testing.T) {
	mux := newRig(t)
	w := doJSON(t, mux, "POST", "/v1/credentials", "user-1", rest.CreateRequest{
		Provider: "s3", Secret: []byte("s"),
	})
	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
}

func TestMissingSecret_400(t *testing.T) {
	mux := newRig(t)
	w := doJSON(t, mux, "POST", "/v1/credentials", "user-1", rest.CreateRequest{
		Provider: "s3", Label: "p",
	})
	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
}

func TestPUT_MissingSecret_400(t *testing.T) {
	mux := newRig(t)
	w := doJSON(t, mux, "POST", "/v1/credentials", "user-1", rest.CreateRequest{
		Provider: "s3", Label: "p", Secret: []byte("s"),
	})
	created := decodeJSON[rest.CreateResponse](t, w)
	w = doJSON(t, mux, "PUT", "/v1/credentials/"+created.ID, "user-1", rest.ReplaceRequest{})
	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
}

func TestWrongContentType_415(t *testing.T) {
	mux := newRig(t)
	r := httptest.NewRequest("POST", "/v1/credentials", strings.NewReader(`{"provider":"s3"}`))
	r.Header.Set("X-User-Id", "user-1")
	r.Header.Set("Content-Type", "text/plain")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, r)
	if w.Code != http.StatusUnsupportedMediaType {
		t.Errorf("status = %d, want 415", w.Code)
	}
}

func TestContentTypeWithCharset_OK(t *testing.T) {
	mux := newRig(t)
	body := bytes.NewBufferString(`{"provider":"s3","label":"p","secret":"czE="}`)
	r := httptest.NewRequest("POST", "/v1/credentials", body)
	r.Header.Set("X-User-Id", "user-1")
	r.Header.Set("Content-Type", "application/json; charset=utf-8")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, r)
	if w.Code != http.StatusCreated {
		t.Errorf("status = %d, want 201 (body=%q)", w.Code, w.Body.String())
	}
}

func TestBodyTooLarge_413(t *testing.T) {
	mux := newRig(t)
	// A 1.5 MiB payload trips the 1 MiB MaxBytesReader cap.
	big := make([]byte, (1<<20)+(1<<19))
	for i := range big {
		big[i] = 'a'
	}
	// Wrap as a JSON document so the decoder reads bytes before
	// the limit fires.
	doc := fmt.Sprintf(`{"provider":"s3","label":"p","secret":"%s"}`, strings.Repeat("A", len(big)))
	r := httptest.NewRequest("POST", "/v1/credentials", strings.NewReader(doc))
	r.Header.Set("X-User-Id", "user-1")
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, r)
	if w.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("status = %d, want 413", w.Code)
	}
}

// --- Sentinels ---

func TestGET_Missing_404(t *testing.T) {
	mux := newRig(t)
	// Seed so the tenant exists; ensures the not-found path is on
	// the credential, not the tenant.
	_ = doJSON(t, mux, "POST", "/v1/credentials", "user-1", rest.CreateRequest{
		Provider: "s3", Label: "p", Secret: []byte("s"),
	})
	w := doJSON(t, mux, "GET", "/v1/credentials/missing-id", "user-1", nil)
	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", w.Code)
	}
}

func TestPOST_DuplicateProviderLabel_409(t *testing.T) {
	mux := newRig(t)
	w := doJSON(t, mux, "POST", "/v1/credentials", "user-1", rest.CreateRequest{
		Provider: "s3", Label: "p", Secret: []byte("s"),
	})
	if w.Code != http.StatusCreated {
		t.Fatalf("first POST status = %d, want 201", w.Code)
	}
	w = doJSON(t, mux, "POST", "/v1/credentials", "user-1", rest.CreateRequest{
		Provider: "s3", Label: "p", Secret: []byte("s2"),
	})
	if w.Code != http.StatusConflict {
		t.Errorf("duplicate POST status = %d, want 409 (body=%q)", w.Code, w.Body.String())
	}
}

func TestCrossUserIsolation_404(t *testing.T) {
	mux := newRig(t)
	w := doJSON(t, mux, "POST", "/v1/credentials", "user-A", rest.CreateRequest{
		Provider: "s3", Label: "p", Secret: []byte("s"),
	})
	created := decodeJSON[rest.CreateResponse](t, w)

	// Seed user-B so the tenant exists for them too — otherwise the
	// not-found would conflate with not-provisioned.
	_ = doJSON(t, mux, "POST", "/v1/credentials", "user-B", rest.CreateRequest{
		Provider: "s3", Label: "p-b", Secret: []byte("s"),
	})
	w = doJSON(t, mux, "GET", "/v1/credentials/"+created.ID, "user-B", nil)
	if w.Code != http.StatusNotFound {
		t.Errorf("user-B reading user-A's id: status = %d, want 404", w.Code)
	}
}

// --- Provider validation (PRD 0008 §5) ---

func TestPOST_UnknownProvider_400(t *testing.T) {
	// Strict empty registry → Get("dropbox") returns ErrProviderUnknown.
	mux := newRigWithLookup(t, vault.NewProviderRegistry())
	w := doJSON(t, mux, "POST", "/v1/credentials", "user-1", rest.CreateRequest{
		Provider: "dropbox", Label: "p", Secret: []byte("s"),
	})
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 (body=%q)", w.Code, w.Body.String())
	}
	er := decodeJSON[rest.ErrorResponse](t, w)
	if !strings.Contains(strings.ToLower(er.Error), "unknown provider") {
		t.Errorf("error body = %q, want it to mention unknown provider", er.Error)
	}
}

func TestPOST_ValidationFailure_422_WithReason(t *testing.T) {
	prov := &providertest.ConfigurableProvider{
		ValidateErr: fmt.Errorf("%w: InvalidAccessKeyId: bad key", vault.ErrProviderValidation),
	}
	reg := vault.NewProviderRegistry()
	reg.Register("s3", prov)
	mux := newRigWithLookup(t, reg)

	w := doJSON(t, mux, "POST", "/v1/credentials", "user-1", rest.CreateRequest{
		Provider: "s3", Label: "p", Secret: []byte("garbage"),
	})
	if w.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status = %d, want 422 (body=%q)", w.Code, w.Body.String())
	}
	er := decodeJSON[rest.ErrorResponse](t, w)
	if !strings.Contains(strings.ToLower(er.Error), "provider validation") {
		t.Errorf("error category = %q, want it to mention provider validation", er.Error)
	}
	if !strings.Contains(er.Reason, "InvalidAccessKeyId") {
		t.Errorf("reason field = %q, want it to contain the wrapped AWS reason", er.Reason)
	}
}

func TestPUT_ValidationFailure_422_LeavesRowUntouched(t *testing.T) {
	prov := &providertest.ConfigurableProvider{}
	reg := vault.NewProviderRegistry()
	reg.Register("s3", prov)
	mux := newRigWithLookup(t, reg)

	// Seed a credential.
	w := doJSON(t, mux, "POST", "/v1/credentials", "user-1", rest.CreateRequest{
		Provider: "s3", Label: "p", Secret: []byte("v1"),
	})
	if w.Code != http.StatusCreated {
		t.Fatalf("seed status = %d, want 201", w.Code)
	}
	created := decodeJSON[rest.CreateResponse](t, w)

	// Flip provider to reject; PUT must 422 and the row must still exist.
	prov.ValidateErr = fmt.Errorf("%w: SignatureDoesNotMatch", vault.ErrProviderValidation)
	w = doJSON(t, mux, "PUT", "/v1/credentials/"+created.ID, "user-1", rest.ReplaceRequest{
		Secret: []byte("v2"),
	})
	if w.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status = %d, want 422 (body=%q)", w.Code, w.Body.String())
	}
	er := decodeJSON[rest.ErrorResponse](t, w)
	if !strings.Contains(er.Reason, "SignatureDoesNotMatch") {
		t.Errorf("reason = %q, want it to surface the AWS-side detail", er.Reason)
	}

	// Original row still readable.
	w = doJSON(t, mux, "GET", "/v1/credentials/"+created.ID, "user-1", nil)
	if w.Code != http.StatusOK {
		t.Errorf("post-rejected-PUT GET status = %d, want 200 (row must be untouched)", w.Code)
	}
}

// --- Response shape sanity ---

func TestErrorResponse_GenericBody(t *testing.T) {
	mux := newRig(t)
	w := doJSON(t, mux, "GET", "/v1/credentials/missing", "user-1", nil)
	body := w.Body.String()
	// The body must be a single-field {"error":"..."} document.
	var er rest.ErrorResponse
	if err := json.Unmarshal([]byte(body), &er); err != nil {
		t.Fatalf("error body did not decode as ErrorResponse: %v (body=%q)", err, body)
	}
	if er.Error == "" {
		t.Errorf("error message empty")
	}
}

// --- SLO budget (in-process memstore) ---

func TestPOST_WriteBudget_Memstore(t *testing.T) {
	mux := newRig(t)
	start := time.Now()
	w := doJSON(t, mux, "POST", "/v1/credentials", "user-budget", rest.CreateRequest{
		Provider: "s3", Label: "p", Secret: []byte("s"),
	})
	elapsed := time.Since(start)
	if w.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201", w.Code)
	}
	// Loose 50ms budget vs. the 200ms production write SLO.
	// Memstore + fake-KM should be sub-millisecond on real hardware;
	// 50ms is generous CI headroom.
	if elapsed > 50*time.Millisecond {
		t.Errorf("POST took %v, want <50ms (in-process memstore)", elapsed)
	}
}

// =====================================================================
// Inline test fixtures (no internal/adapters import — preserves
// hexagonal discipline enforced by `make check-imports`). Mirror of
// internal/transport/grpc/server_test.go's inMemTenants/inMemCreds.
// =====================================================================

type fakeKM struct{}

func (m *fakeKM) GenerateDataKey(_ context.Context, _ string) ([]byte, []byte, error) {
	plaintext := make([]byte, 32)
	if _, err := rand.Read(plaintext); err != nil {
		return nil, nil, err
	}
	return plaintext, append([]byte("fake:"), plaintext...), nil
}

func (m *fakeKM) Decrypt(_ context.Context, ciphertextDEK []byte) ([]byte, error) {
	if len(ciphertextDEK) < 5 || string(ciphertextDEK[:5]) != "fake:" {
		return nil, errors.New("fakeKM: bad ciphertextDEK")
	}
	out := make([]byte, len(ciphertextDEK)-5)
	copy(out, ciphertextDEK[5:])
	return out, nil
}

type inMemTenants struct {
	mu   sync.Mutex
	data map[string][]byte
}

func newInMemTenants() *inMemTenants { return &inMemTenants{data: map[string][]byte{}} }

func (t *inMemTenants) GetEncryptedDEK(_ context.Context, userID string) ([]byte, int, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	b, ok := t.data[userID]
	if !ok {
		return nil, 0, vault.ErrNotFound
	}
	out := make([]byte, len(b))
	copy(out, b)
	return out, 1, nil
}

func (t *inMemTenants) PutEncryptedDEK(_ context.Context, userID string, dek []byte) ([]byte, int, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if existing, ok := t.data[userID]; ok {
		out := make([]byte, len(existing))
		copy(out, existing)
		return out, 1, nil
	}
	stored := make([]byte, len(dek))
	copy(stored, dek)
	t.data[userID] = stored
	out := make([]byte, len(stored))
	copy(out, stored)
	return out, 1, nil
}

type inMemCredRow struct {
	cred    vault.Credential
	status  vault.Status
	created time.Time
}

type inMemCreds struct {
	mu      sync.Mutex
	byUser  map[string]map[string]inMemCredRow
	pl      map[string]map[string]string // userID → "provider|label" → credID
	tenants *inMemTenants
}

func newInMemCreds(tenants *inMemTenants) *inMemCreds {
	return &inMemCreds{
		byUser:  map[string]map[string]inMemCredRow{},
		pl:      map[string]map[string]string{},
		tenants: tenants,
	}
}

func plKey(provider, label string) string { return provider + "|" + label }

func (s *inMemCreds) Get(_ context.Context, userID string, ids []string) ([]vault.Credential, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	bucket := s.byUser[userID]
	out := make([]vault.Credential, 0, len(ids))
	for _, id := range ids {
		if r, ok := bucket[id]; ok {
			out = append(out, r.cred)
		}
	}
	return out, nil
}

func (s *inMemCreds) List(_ context.Context, userID string) ([]vault.CredentialSummary, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	bucket := s.byUser[userID]
	out := make([]vault.CredentialSummary, 0, len(bucket))
	for id, r := range bucket {
		out = append(out, vault.CredentialSummary{
			ID: id, Provider: r.cred.Provider, Label: r.cred.Label,
			Status: r.status, CreatedAt: r.created,
		})
	}
	return out, nil
}

func (s *inMemCreds) Create(ctx context.Context, userID string, c vault.Credential) error {
	if _, _, err := s.tenants.GetEncryptedDEK(ctx, userID); err != nil {
		return vault.ErrTenantNotProvisioned
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.byUser[userID]; !ok {
		s.byUser[userID] = map[string]inMemCredRow{}
		s.pl[userID] = map[string]string{}
	}
	if _, exists := s.byUser[userID][c.ID]; exists {
		return vault.ErrAlreadyExists
	}
	key := plKey(c.Provider, c.Label)
	if _, exists := s.pl[userID][key]; exists {
		return vault.ErrAlreadyExists
	}
	s.byUser[userID][c.ID] = inMemCredRow{
		cred: c, status: vault.StatusActive, created: time.Now(),
	}
	s.pl[userID][key] = c.ID
	return nil
}

func (s *inMemCreds) Replace(_ context.Context, userID string, c vault.Credential) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.byUser[userID][c.ID]
	if !ok {
		return vault.ErrNotFound
	}
	r.cred = c
	s.byUser[userID][c.ID] = r
	return nil
}

func (s *inMemCreds) Delete(_ context.Context, userID, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.byUser[userID][id]
	if !ok {
		return vault.ErrNotFound
	}
	delete(s.byUser[userID], id)
	delete(s.pl[userID], plKey(r.cred.Provider, r.cred.Label))
	return nil
}

var (
	_ vault.CredentialStore = (*inMemCreds)(nil)
	_ vault.TenantStore     = (*inMemTenants)(nil)
)
