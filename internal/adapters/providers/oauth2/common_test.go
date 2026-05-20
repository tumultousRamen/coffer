package oauth2

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

func newTestClient(t *testing.T, handler http.HandlerFunc) (*Client, *httptest.Server) {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	return NewClientWithHTTP(srv.URL, "client-id-x", "client-secret-y", srv.Client()), srv
}

func TestRefresh_SuccessParsesAllFields(t *testing.T) {
	client, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if got := r.FormValue("grant_type"); got != "refresh_token" {
			t.Errorf("grant_type = %q, want refresh_token", got)
		}
		if got := r.FormValue("refresh_token"); got != "rt-original" {
			t.Errorf("refresh_token = %q, want rt-original", got)
		}
		if got := r.FormValue("client_id"); got != "client-id-x" {
			t.Errorf("client_id = %q, want client-id-x", got)
		}
		if ct := r.Header.Get("Content-Type"); ct != "application/x-www-form-urlencoded" {
			t.Errorf("Content-Type = %q", ct)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"access_token":  "at-new",
			"token_type":    "bearer",
			"expires_in":    3600,
			"refresh_token": "rt-rotated",
			"scope":         "files"
		}`))
	})

	tr, err := client.Refresh(context.Background(), "rt-original")
	if err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	if tr.AccessToken != "at-new" || tr.ExpiresIn != 3600 || tr.RefreshToken != "rt-rotated" {
		t.Errorf("TokenResponse = %+v", tr)
	}
	if !tr.IsRefreshTokenRotated() {
		t.Error("IsRefreshTokenRotated = false, want true")
	}
}

func TestRefresh_SuccessNoRotation(t *testing.T) {
	client, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"access_token":"at","token_type":"bearer","expires_in":14400}`))
	})

	tr, err := client.Refresh(context.Background(), "rt")
	if err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	if tr.IsRefreshTokenRotated() {
		t.Error("IsRefreshTokenRotated = true, want false (no refresh_token in response)")
	}
}

func TestRefresh_InvalidGrantIsPermanent(t *testing.T) {
	client, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"invalid_grant","error_description":"refresh token revoked"}`))
	})

	_, err := client.Refresh(context.Background(), "rt")
	if !errors.Is(err, ErrInvalidGrant) {
		t.Errorf("err = %v, want wrap of ErrInvalidGrant", err)
	}
}

func TestRefresh_InvalidClientIsPermanent(t *testing.T) {
	client, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":"invalid_client"}`))
	})

	_, err := client.Refresh(context.Background(), "rt")
	if !errors.Is(err, ErrInvalidGrant) {
		t.Errorf("err = %v, want wrap of ErrInvalidGrant", err)
	}
}

func TestRefresh_5xxIsTransient(t *testing.T) {
	client, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
	})
	_, err := client.Refresh(context.Background(), "rt")
	if !errors.Is(err, ErrTransient) {
		t.Errorf("err = %v, want wrap of ErrTransient", err)
	}
}

func TestRefresh_UnknownErrorIsTransient(t *testing.T) {
	client, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"new_error_code_we_dont_know"}`))
	})
	_, err := client.Refresh(context.Background(), "rt")
	if !errors.Is(err, ErrTransient) {
		t.Errorf("err = %v, want wrap of ErrTransient (unknown errors default to transient)", err)
	}
}

func TestRefresh_MalformedJSONIsTransient(t *testing.T) {
	client, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`not json`))
	})
	_, err := client.Refresh(context.Background(), "rt")
	if !errors.Is(err, ErrTransient) {
		t.Errorf("err = %v, want wrap of ErrTransient", err)
	}
}

func TestRefresh_SuccessMissingAccessTokenIsTransient(t *testing.T) {
	client, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"token_type":"bearer","expires_in":3600}`))
	})
	_, err := client.Refresh(context.Background(), "rt")
	if !errors.Is(err, ErrTransient) {
		t.Errorf("err = %v, want wrap of ErrTransient", err)
	}
}
