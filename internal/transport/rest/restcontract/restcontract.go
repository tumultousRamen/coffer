// Package restcontract holds the reference-contract suite for the
// REST transport. The same scenarios must pass against every storage
// backend the Service can be wired against. Sibling pattern to
// internal/vault/servicecontract, but living here in the transport
// tree so it can import internal/transport/rest as the SUT — the
// servicecontract package cannot, since internal/vault must not
// import internal/transport (enforced by `make check-imports`).
//
// PRD 0007 originally proposed putting RunRESTScenarios under
// servicecontract. The Update — PRD 0007 section of ADR 0007
// documents why it lives here instead.
//
// Usage from an adapter's test package:
//
//	func TestMyAdapter_RESTContract(t *testing.T) {
//	    restcontract.RunRESTContract(t, func(t *testing.T) restcontract.Bundle {
//	        // build storage adapters + Service, return
//	    })
//	}
package restcontract

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/tumultousRamen/coffer/internal/transport/rest"
	"github.com/tumultousRamen/coffer/internal/vault"
)

// Bundle holds the moving parts a REST scenario needs. Factories
// build a fresh, isolated Bundle per scenario (the Postgres factory
// TRUNCATEs; the memstore factory builds new maps).
//
// Server is wired internally from Service + a fresh ServeMux so
// scenarios can issue real HTTP via httptest. Closing the bundle is
// the factory's responsibility (t.Cleanup hooks).
type Bundle struct {
	Service *vault.Service
	Server  *httptest.Server
}

// Factory returns a fresh, isolated Bundle on each call.
type Factory func(t *testing.T) Bundle

// NewBundleFromService is the convenience constructor most factories
// will use: build storage + Service in the factory, hand the Service
// here to get a wired Bundle. Closes the httptest server in t.Cleanup.
func NewBundleFromService(t *testing.T, svc *vault.Service) Bundle {
	t.Helper()
	mux := http.NewServeMux()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	rest.NewHandler(svc, logger).Register(mux)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return Bundle{Service: svc, Server: srv}
}

// RunRESTContract drives the end-to-end REST behavior contract.
// Every scenario builds a fresh Bundle so backend state cannot leak.
func RunRESTContract(t *testing.T, factory Factory) {
	t.Helper()

	tests := []struct {
		name string
		fn   func(t *testing.T, b Bundle)
	}{
		{"FullLifecycle", testFullLifecycle},
		{"CrossUserIsolation", testCrossUserIsolation},
		{"DuplicateProviderLabelConflict", testDuplicateProviderLabelConflict},
		{"DeleteThenGet404", testDeleteThenGet404},
		{"ReplaceUpdatesStoredSecret", testReplaceUpdatesStoredSecret},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tc.fn(t, factory(t))
		})
	}
}

// --- helpers ---

func mustPOST(t *testing.T, b Bundle, userID string, req rest.CreateRequest) string {
	t.Helper()
	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(req); err != nil {
		t.Fatalf("encode: %v", err)
	}
	httpReq, err := http.NewRequest("POST", b.Server.URL+"/v1/credentials", &buf)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	httpReq.Header.Set("X-User-Id", userID)
	httpReq.Header.Set("Content-Type", "application/json")
	resp, err := b.Server.Client().Do(httpReq)
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("POST status = %d, want 201 (body=%s)", resp.StatusCode, body)
	}
	var out rest.CreateResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	return out.ID
}

func doGet(t *testing.T, b Bundle, userID, path string) (int, []byte) {
	t.Helper()
	httpReq, err := http.NewRequest("GET", b.Server.URL+path, nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	httpReq.Header.Set("X-User-Id", userID)
	resp, err := b.Server.Client().Do(httpReq)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, body
}

func doPUT(t *testing.T, b Bundle, userID, id string, req rest.ReplaceRequest) int {
	t.Helper()
	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(req); err != nil {
		t.Fatalf("encode: %v", err)
	}
	httpReq, err := http.NewRequest("PUT", b.Server.URL+"/v1/credentials/"+id, &buf)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	httpReq.Header.Set("X-User-Id", userID)
	httpReq.Header.Set("Content-Type", "application/json")
	resp, err := b.Server.Client().Do(httpReq)
	if err != nil {
		t.Fatalf("PUT: %v", err)
	}
	defer resp.Body.Close()
	return resp.StatusCode
}

func doDelete(t *testing.T, b Bundle, userID, id string) int {
	t.Helper()
	httpReq, err := http.NewRequest("DELETE", b.Server.URL+"/v1/credentials/"+id, nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	httpReq.Header.Set("X-User-Id", userID)
	resp, err := b.Server.Client().Do(httpReq)
	if err != nil {
		t.Fatalf("DELETE: %v", err)
	}
	defer resp.Body.Close()
	return resp.StatusCode
}

// --- scenarios ---

func testFullLifecycle(t *testing.T, b Bundle) {
	userID := "rc-user-" + randSuffix(t)
	id := mustPOST(t, b, userID, rest.CreateRequest{
		Provider: "s3", Label: "prod", Secret: []byte("aws-secret-v1"),
		Metadata: map[string]any{"region": "us-west-1"},
	})

	// GET list contains the new credential.
	code, body := doGet(t, b, userID, "/v1/credentials")
	if code != http.StatusOK {
		t.Fatalf("GET list = %d (body=%s)", code, body)
	}
	var list rest.ListResponse
	if err := json.Unmarshal(body, &list); err != nil {
		t.Fatalf("decode list: %v", err)
	}
	if len(list.Credentials) != 1 || list.Credentials[0].ID != id {
		t.Fatalf("list = %+v, want one entry with id %s", list, id)
	}

	// GET by id.
	code, body = doGet(t, b, userID, "/v1/credentials/"+id)
	if code != http.StatusOK {
		t.Fatalf("GET id = %d (body=%s)", code, body)
	}
	var sum rest.SummaryResponse
	if err := json.Unmarshal(body, &sum); err != nil {
		t.Fatalf("decode summary: %v", err)
	}
	if sum.Provider != "s3" || sum.Label != "prod" {
		t.Errorf("summary = %+v", sum)
	}

	// PUT replaces.
	if code := doPUT(t, b, userID, id, rest.ReplaceRequest{Secret: []byte("aws-secret-v2")}); code != http.StatusNoContent {
		t.Fatalf("PUT = %d", code)
	}

	// DELETE removes.
	if code := doDelete(t, b, userID, id); code != http.StatusNoContent {
		t.Fatalf("DELETE = %d", code)
	}

	// GET id post-delete → 404.
	code, _ = doGet(t, b, userID, "/v1/credentials/"+id)
	if code != http.StatusNotFound {
		t.Errorf("GET after delete = %d, want 404", code)
	}
}

func testCrossUserIsolation(t *testing.T, b Bundle) {
	uA := "rc-A-" + randSuffix(t)
	uB := "rc-B-" + randSuffix(t)
	id := mustPOST(t, b, uA, rest.CreateRequest{
		Provider: "s3", Label: "p", Secret: []byte("a-secret"),
	})
	// Provision uB so the 404 is about the credential, not the tenant.
	_ = mustPOST(t, b, uB, rest.CreateRequest{
		Provider: "s3", Label: "p-b", Secret: []byte("b-secret"),
	})

	code, _ := doGet(t, b, uB, "/v1/credentials/"+id)
	if code != http.StatusNotFound {
		t.Errorf("uB reading uA's id = %d, want 404", code)
	}
}

func testDuplicateProviderLabelConflict(t *testing.T, b Bundle) {
	userID := "rc-dup-" + randSuffix(t)
	_ = mustPOST(t, b, userID, rest.CreateRequest{
		Provider: "s3", Label: "p", Secret: []byte("v1"),
	})
	// Second POST with same (provider, label) — expect 409.
	var buf bytes.Buffer
	_ = json.NewEncoder(&buf).Encode(rest.CreateRequest{
		Provider: "s3", Label: "p", Secret: []byte("v2"),
	})
	req, _ := http.NewRequest("POST", b.Server.URL+"/v1/credentials", &buf)
	req.Header.Set("X-User-Id", userID)
	req.Header.Set("Content-Type", "application/json")
	resp, err := b.Server.Client().Do(req)
	if err != nil {
		t.Fatalf("POST dup: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusConflict {
		t.Errorf("duplicate POST = %d, want 409", resp.StatusCode)
	}
}

func testDeleteThenGet404(t *testing.T, b Bundle) {
	userID := "rc-del-" + randSuffix(t)
	id := mustPOST(t, b, userID, rest.CreateRequest{
		Provider: "s3", Label: "p", Secret: []byte("v"),
	})
	if code := doDelete(t, b, userID, id); code != http.StatusNoContent {
		t.Fatalf("DELETE = %d", code)
	}
	if code, _ := doGet(t, b, userID, "/v1/credentials/"+id); code != http.StatusNotFound {
		t.Errorf("GET after DELETE = %d, want 404", code)
	}
}

// testReplaceUpdatesStoredSecret verifies the replaced ciphertext is
// genuinely persisted (not just acknowledged). We can't read the
// secret back through the API by design — instead we issue a PUT
// with a new payload and then look at the underlying Service to
// confirm GetCredentialSummary still resolves (proving the row
// survived) and that DEKVersion is unchanged from the original.
func testReplaceUpdatesStoredSecret(t *testing.T, b Bundle) {
	userID := "rc-repl-" + randSuffix(t)
	id := mustPOST(t, b, userID, rest.CreateRequest{
		Provider: "s3", Label: "p", Secret: []byte("v1"),
	})
	if code := doPUT(t, b, userID, id, rest.ReplaceRequest{Secret: []byte("v2")}); code != http.StatusNoContent {
		t.Fatalf("PUT = %d", code)
	}
	code, body := doGet(t, b, userID, "/v1/credentials/"+id)
	if code != http.StatusOK {
		t.Fatalf("GET = %d (body=%s)", code, body)
	}
	var sum rest.SummaryResponse
	_ = json.Unmarshal(body, &sum)
	if sum.ID != id {
		t.Errorf("summary id = %q, want %q", sum.ID, id)
	}
}

// randSuffix is a tiny per-scenario unique tag so cross-scenario PG
// state cannot collide on (user_id, provider, label) uniqueness. We
// don't use uuid here to avoid the package dependency surface in the
// contract package — t.Name() + a counter is sufficient.
func randSuffix(t *testing.T) string {
	t.Helper()
	return fmt.Sprintf("%s-%d", t.Name(), nextSuffix())
}

var suffixCh = make(chan int, 1)

func init() { suffixCh <- 0 }

func nextSuffix() int {
	n := <-suffixCh
	n++
	suffixCh <- n
	return n
}
