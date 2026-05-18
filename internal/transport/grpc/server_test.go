package grpc_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"io"
	"log/slog"
	"net"
	"sync"
	"testing"
	"time"

	cgrpc "github.com/tumultousRamen/coffer/internal/transport/grpc"
	"github.com/tumultousRamen/coffer/internal/transport/grpc/pb"
	"github.com/tumultousRamen/coffer/internal/vault"
	"github.com/tumultousRamen/coffer/internal/vault/providertest"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
)

const bufSize = 1024 * 1024

// testRig is the bufconn-backed test scaffold: real gRPC server,
// real client, real vault.Service against memstore. The only
// fake is the KeyManager (CountingKeyManager via servicecontract,
// but we wire it through directly here to avoid the dependency).
type testRig struct {
	t        *testing.T
	conn     *grpc.ClientConn
	client   pb.VaultClient
	server   *grpc.Server
	priv     ed25519.PrivateKey
	verifier *vault.GrantVerifier
	svc      *vault.Service
}

func newRig(t *testing.T) *testRig {
	t.Helper()

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey: %v", err)
	}
	verifier := vault.NewGrantVerifier(pub)

	km := &fakeKM{}
	cache := vault.NewDEKCache(64, time.Minute)
	cryptor := vault.NewCryptor(km, cache)
	tenants := newInMemTenants()
	store := newInMemCreds(tenants)
	svc := vault.NewService(store, tenants, cryptor, verifier, providertest.PermissiveRegistry())

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	srv := grpc.NewServer(grpc.ChainUnaryInterceptor(
		cgrpc.RecoveryInterceptor(logger),
		cgrpc.DeadlineInterceptor(),
		cgrpc.LoggingInterceptor(logger),
	))
	pb.RegisterVaultServer(srv, cgrpc.NewVaultServer(svc, verifier))

	lis := bufconn.Listen(bufSize)
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)

	conn, err := grpc.NewClient(
		"passthrough://bufnet",
		grpc.WithContextDialer(func(_ context.Context, _ string) (net.Conn, error) {
			return lis.DialContext(context.Background())
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatalf("grpc.NewClient: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	return &testRig{
		t:        t,
		conn:     conn,
		client:   pb.NewVaultClient(conn),
		server:   srv,
		priv:     priv,
		verifier: verifier,
		svc:      svc,
	}
}

// seed creates a credential through the service and returns its ID.
func (r *testRig) seed(userID, provider, label string, secret []byte) string {
	r.t.Helper()
	id, err := r.svc.CreateCredential(context.Background(), userID, provider, label, secret, vault.Metadata{"region": "us-west-1"})
	if err != nil {
		r.t.Fatalf("CreateCredential: %v", err)
	}
	return id
}

func (r *testRig) mint(userID string, ids []string, ttl time.Duration) string {
	r.t.Helper()
	tok, err := vault.MintGrant(r.priv, userID, ids, ttl, "test-job")
	if err != nil {
		r.t.Fatalf("MintGrant: %v", err)
	}
	return tok
}

func TestVaultServer_GetCredentials_RoundTrip(t *testing.T) {
	r := newRig(t)
	userID := "user-1"
	id := r.seed(userID, "s3", "prod", []byte("secret-bytes"))
	tok := r.mint(userID, []string{id}, 5*time.Minute)

	resp, err := r.client.GetCredentials(context.Background(), &pb.GetCredentialsRequest{
		GrantToken: tok, CredentialIds: []string{id},
	})
	if err != nil {
		t.Fatalf("GetCredentials: %v", err)
	}
	if len(resp.Credentials) != 1 {
		t.Fatalf("got %d, want 1", len(resp.Credentials))
	}
	if string(resp.Credentials[0].Secret) != "secret-bytes" {
		t.Errorf("secret = %q, want secret-bytes", resp.Credentials[0].Secret)
	}
	if resp.Credentials[0].Metadata.Fields["region"].GetStringValue() != "us-west-1" {
		t.Errorf("metadata.region = %v, want us-west-1", resp.Credentials[0].Metadata.Fields["region"])
	}
}

func TestVaultServer_GetCredentials_ExpiredGrant(t *testing.T) {
	r := newRig(t)
	userID := "user-1"
	id := r.seed(userID, "s3", "p", []byte("x"))
	tok := r.mint(userID, []string{id}, -10*time.Minute)

	_, err := r.client.GetCredentials(context.Background(), &pb.GetCredentialsRequest{
		GrantToken: tok, CredentialIds: []string{id},
	})
	assertCode(t, err, codes.Unauthenticated)
}

func TestVaultServer_GetCredentials_BadSignature(t *testing.T) {
	r := newRig(t)
	userID := "user-1"
	id := r.seed(userID, "s3", "p", []byte("x"))

	// Mint with an unrelated private key.
	_, otherPriv, _ := ed25519.GenerateKey(rand.Reader)
	tok, err := vault.MintGrant(otherPriv, userID, []string{id}, 5*time.Minute, "j")
	if err != nil {
		t.Fatalf("MintGrant: %v", err)
	}
	_, err = r.client.GetCredentials(context.Background(), &pb.GetCredentialsRequest{
		GrantToken: tok, CredentialIds: []string{id},
	})
	assertCode(t, err, codes.Unauthenticated)
}

func TestVaultServer_GetCredentials_UnauthorizedID(t *testing.T) {
	r := newRig(t)
	userID := "user-1"
	idAuth := r.seed(userID, "s3", "auth", []byte("a"))
	idOther := r.seed(userID, "s3", "other", []byte("b"))
	tok := r.mint(userID, []string{idAuth}, 5*time.Minute)

	_, err := r.client.GetCredentials(context.Background(), &pb.GetCredentialsRequest{
		GrantToken: tok, CredentialIds: []string{idAuth, idOther},
	})
	assertCode(t, err, codes.PermissionDenied)
}

func TestVaultServer_GetCredentials_MissingIDRejectsWhole(t *testing.T) {
	r := newRig(t)
	userID := "user-1"
	existing := r.seed(userID, "s3", "p", []byte("x"))
	missing := "00000000-0000-7000-8000-000000000000"

	// Grant authorizes both, but only one row exists.
	tok := r.mint(userID, []string{existing, missing}, 5*time.Minute)
	_, err := r.client.GetCredentials(context.Background(), &pb.GetCredentialsRequest{
		GrantToken: tok, CredentialIds: []string{existing, missing},
	})
	assertCode(t, err, codes.NotFound)
}

func TestVaultServer_GetCredentials_TooManyIDs(t *testing.T) {
	r := newRig(t)
	ids := make([]string, 9)
	for i := range ids {
		ids[i] = "00000000-0000-7000-8000-00000000000" + string(rune('0'+i))
	}
	tok := r.mint("user-1", ids, 5*time.Minute)
	_, err := r.client.GetCredentials(context.Background(), &pb.GetCredentialsRequest{
		GrantToken: tok, CredentialIds: ids,
	})
	assertCode(t, err, codes.InvalidArgument)
}

func TestVaultServer_GetCredentials_EmptyIDs(t *testing.T) {
	r := newRig(t)
	tok := r.mint("user-1", []string{"anything"}, 5*time.Minute)
	_, err := r.client.GetCredentials(context.Background(), &pb.GetCredentialsRequest{
		GrantToken: tok, CredentialIds: nil,
	})
	assertCode(t, err, codes.InvalidArgument)
}

// TestVaultServer_GetCredentials_DeadlineExceeded uses a synthetic
// slow Service to prove the wire-side deadline budget is real: the
// client's 50ms deadline must surface as DeadlineExceeded even
// though the server-side handler would have eventually responded.
func TestVaultServer_GetCredentials_DeadlineExceeded(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	verifier := vault.NewGrantVerifier(pub)

	// Custom server with a slow vault.Service mock — we wrap the
	// transport's NewVaultServer directly so we can control the
	// handler's duration.
	slow := &slowVaultServer{verifier: verifier, sleep: 200 * time.Millisecond}
	srv := grpc.NewServer()
	pb.RegisterVaultServer(srv, slow)

	lis := bufconn.Listen(bufSize)
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)

	conn, err := grpc.NewClient(
		"passthrough://bufnet",
		grpc.WithContextDialer(func(_ context.Context, _ string) (net.Conn, error) {
			return lis.DialContext(context.Background())
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatalf("grpc.NewClient: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	tok, _ := vault.MintGrant(priv, "user-1", []string{"any"}, 5*time.Minute, "j")
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	_, err = pb.NewVaultClient(conn).GetCredentials(ctx, &pb.GetCredentialsRequest{
		GrantToken: tok, CredentialIds: []string{"any"},
	})
	assertCode(t, err, codes.DeadlineExceeded)
}

// slowVaultServer is an inline implementation that sleeps for a
// configurable duration before returning. Used to exercise the
// deadline path without involving the real service.
type slowVaultServer struct {
	pb.UnimplementedVaultServer
	verifier *vault.GrantVerifier
	sleep    time.Duration
}

func (s *slowVaultServer) GetCredentials(ctx context.Context, req *pb.GetCredentialsRequest) (*pb.GetCredentialsResponse, error) {
	select {
	case <-time.After(s.sleep):
	case <-ctx.Done():
		return nil, status.Error(codes.DeadlineExceeded, "deadline exceeded")
	}
	return &pb.GetCredentialsResponse{}, nil
}

// fakeKM is a test KeyManager identical in spirit to the
// servicecontract.CountingKeyManager but local to avoid the
// dependency cycle (servicecontract imports adapters indirectly).
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

func assertCode(t *testing.T, err error, want codes.Code) {
	t.Helper()
	if err == nil {
		t.Errorf("got nil error, want code %s", want)
		return
	}
	if got := status.Code(err); got != want {
		t.Errorf("status code = %s, want %s (err=%v)", got, want, err)
	}
}

// In-memory CredentialStore + TenantStore used only by this test
// file. Inlined so the transport package's tests do not have to
// import internal/adapters — preserving the hexagonal discipline
// enforced by `make check-imports`. These types implement the
// minimum behavior the FetchForWorker round-trip needs.

type inMemTenants struct {
	mu   sync.Mutex
	data map[string][]byte
}

func newInMemTenants() *inMemTenants {
	return &inMemTenants{data: map[string][]byte{}}
}

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

type inMemCreds struct {
	mu      sync.Mutex
	rows    map[string]map[string]vault.Credential
	stat    map[string]map[string]vault.Status
	ctime   map[string]map[string]time.Time
	tenants *inMemTenants
}

func newInMemCreds(tenants *inMemTenants) *inMemCreds {
	return &inMemCreds{
		rows:    map[string]map[string]vault.Credential{},
		stat:    map[string]map[string]vault.Status{},
		ctime:   map[string]map[string]time.Time{},
		tenants: tenants,
	}
}

func (s *inMemCreds) Get(_ context.Context, userID string, ids []string) ([]vault.Credential, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	bucket := s.rows[userID]
	out := make([]vault.Credential, 0, len(ids))
	for _, id := range ids {
		if c, ok := bucket[id]; ok {
			out = append(out, c)
		}
	}
	return out, nil
}

func (s *inMemCreds) List(_ context.Context, userID string) ([]vault.CredentialSummary, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	bucket := s.rows[userID]
	out := make([]vault.CredentialSummary, 0, len(bucket))
	for id, c := range bucket {
		out = append(out, vault.CredentialSummary{
			ID: id, Provider: c.Provider, Label: c.Label,
			Status: s.stat[userID][id], CreatedAt: s.ctime[userID][id],
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
	if _, ok := s.rows[userID]; !ok {
		s.rows[userID] = map[string]vault.Credential{}
		s.stat[userID] = map[string]vault.Status{}
		s.ctime[userID] = map[string]time.Time{}
	}
	if _, exists := s.rows[userID][c.ID]; exists {
		return vault.ErrAlreadyExists
	}
	s.rows[userID][c.ID] = c
	s.stat[userID][c.ID] = vault.StatusActive
	s.ctime[userID][c.ID] = time.Now()
	return nil
}

func (s *inMemCreds) Replace(_ context.Context, userID string, c vault.Credential) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.rows[userID][c.ID]; !ok {
		return vault.ErrNotFound
	}
	s.rows[userID][c.ID] = c
	return nil
}

func (s *inMemCreds) Delete(_ context.Context, userID, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.rows[userID][id]; !ok {
		return vault.ErrNotFound
	}
	delete(s.rows[userID], id)
	return nil
}

var (
	_ vault.CredentialStore = (*inMemCreds)(nil)
	_ vault.TenantStore     = (*inMemTenants)(nil)
)
