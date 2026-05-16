package memstore

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/tumultousRamen/coffer/internal/vault"
)

func newCred(id, provider, label, secret string) vault.Credential {
	return vault.Credential{
		ID:       id,
		Provider: provider,
		Label:    label,
		Secret:   vault.NewSecretBlob([]byte(secret)),
		Metadata: vault.Metadata{"region": "us-west-1"},
	}
}

// TestStore_ImplementsCredentialStore is a compile-time guard: this
// file fails to build if memstore.Store ever drifts from the port
// contract.
func TestStore_ImplementsCredentialStore(t *testing.T) {
	var _ vault.CredentialStore = New()
}

// TestStore_RoundTrip exercises the full lifecycle: create, read,
// list, replace (verifying the new secret is returned), delete, and
// confirm the credential is gone. This is the reference behavior the
// real Postgres adapter in PRD 0003 must reproduce.
func TestStore_RoundTrip(t *testing.T) {
	ctx := context.Background()
	s := New()
	const userID = "user-1"

	c := newCred("cred-1", "s3", "prod_bucket", "secret-v1")
	if err := s.Create(ctx, userID, c); err != nil {
		t.Fatalf("Create: %v", err)
	}

	got, err := s.Get(ctx, userID, []string{"cred-1"})
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if len(got) != 1 || got[0].ID != "cred-1" {
		t.Fatalf("Get returned %+v, want one credential with ID cred-1", got)
	}
	if !bytes.Equal(got[0].Secret.Reveal(), []byte("secret-v1")) {
		t.Errorf("Get secret = %q, want %q", got[0].Secret.Reveal(), "secret-v1")
	}

	summaries, err := s.List(ctx, userID)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(summaries) != 1 || summaries[0].ID != "cred-1" {
		t.Fatalf("List returned %+v, want one summary with ID cred-1", summaries)
	}
	if summaries[0].Status != vault.StatusActive {
		t.Errorf("List status = %q, want %q", summaries[0].Status, vault.StatusActive)
	}
	if summaries[0].CreatedAt.IsZero() {
		t.Errorf("List CreatedAt is zero, want non-zero")
	}

	c2 := newCred("cred-1", "s3", "prod_bucket", "secret-v2")
	if err := s.Replace(ctx, userID, c2); err != nil {
		t.Fatalf("Replace: %v", err)
	}
	got, err = s.Get(ctx, userID, []string{"cred-1"})
	if err != nil {
		t.Fatalf("Get after Replace: %v", err)
	}
	if !bytes.Equal(got[0].Secret.Reveal(), []byte("secret-v2")) {
		t.Errorf("Get after Replace secret = %q, want %q", got[0].Secret.Reveal(), "secret-v2")
	}

	if err := s.Delete(ctx, userID, "cred-1"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := s.Get(ctx, userID, []string{"cred-1"}); !errors.Is(err, vault.ErrNotFound) {
		t.Errorf("Get after Delete err = %v, want ErrNotFound", err)
	}
}

func TestStore_Create_DuplicateReturnsAlreadyExists(t *testing.T) {
	ctx := context.Background()
	s := New()
	c := newCred("cred-1", "s3", "prod", "x")
	if err := s.Create(ctx, "user-1", c); err != nil {
		t.Fatalf("first Create: %v", err)
	}
	err := s.Create(ctx, "user-1", c)
	if !errors.Is(err, vault.ErrAlreadyExists) {
		t.Errorf("duplicate Create err = %v, want ErrAlreadyExists", err)
	}
}

func TestStore_Get_UnknownUserReturnsNotFound(t *testing.T) {
	s := New()
	_, err := s.Get(context.Background(), "no-such-user", []string{"cred-1"})
	if !errors.Is(err, vault.ErrNotFound) {
		t.Errorf("err = %v, want ErrNotFound", err)
	}
}

func TestStore_Get_PartialUnknownReturnsNotFound(t *testing.T) {
	ctx := context.Background()
	s := New()
	if err := s.Create(ctx, "user-1", newCred("cred-1", "s3", "p", "x")); err != nil {
		t.Fatalf("Create: %v", err)
	}
	// Asking for one known + one unknown ID must fail wholesale, not
	// return a partial result — partial fulfillment leaks existence.
	_, err := s.Get(ctx, "user-1", []string{"cred-1", "cred-missing"})
	if !errors.Is(err, vault.ErrNotFound) {
		t.Errorf("err = %v, want ErrNotFound", err)
	}
}

func TestStore_Get_PreservesIDOrder(t *testing.T) {
	ctx := context.Background()
	s := New()
	for _, id := range []string{"cred-a", "cred-b", "cred-c"} {
		if err := s.Create(ctx, "user-1", newCred(id, "s3", "p", "x")); err != nil {
			t.Fatalf("Create %s: %v", id, err)
		}
	}
	got, err := s.Get(ctx, "user-1", []string{"cred-c", "cred-a", "cred-b"})
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	wantOrder := []string{"cred-c", "cred-a", "cred-b"}
	for i, want := range wantOrder {
		if got[i].ID != want {
			t.Errorf("position %d: ID = %q, want %q", i, got[i].ID, want)
		}
	}
}

func TestStore_Replace_MissingReturnsNotFound(t *testing.T) {
	s := New()
	err := s.Replace(context.Background(), "user-1", newCred("cred-1", "s3", "p", "x"))
	if !errors.Is(err, vault.ErrNotFound) {
		t.Errorf("err = %v, want ErrNotFound", err)
	}
}

func TestStore_Delete_MissingReturnsNotFound(t *testing.T) {
	s := New()
	err := s.Delete(context.Background(), "user-1", "cred-1")
	if !errors.Is(err, vault.ErrNotFound) {
		t.Errorf("err = %v, want ErrNotFound", err)
	}
}

func TestStore_List_UnknownUserReturnsEmpty(t *testing.T) {
	s := New()
	got, err := s.List(context.Background(), "no-such-user")
	if err != nil {
		t.Errorf("err = %v, want nil", err)
	}
	if len(got) != 0 {
		t.Errorf("List = %v, want empty", got)
	}
}

func TestStore_Tenancy_IsolatedAcrossUsers(t *testing.T) {
	ctx := context.Background()
	s := New()
	if err := s.Create(ctx, "user-1", newCred("cred-1", "s3", "p", "u1-secret")); err != nil {
		t.Fatalf("Create user-1: %v", err)
	}
	if err := s.Create(ctx, "user-2", newCred("cred-1", "s3", "p", "u2-secret")); err != nil {
		t.Fatalf("Create user-2: %v", err)
	}
	// Same ID across users must not collide. user-2 cannot reach
	// user-1's row even when asking for the same ID.
	got, err := s.Get(ctx, "user-2", []string{"cred-1"})
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !bytes.Equal(got[0].Secret.Reveal(), []byte("u2-secret")) {
		t.Errorf("user-2 read user-1's data: secret = %q", got[0].Secret.Reveal())
	}
}
