package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"golang.org/x/oauth2"
)

// tokenServerContext returns a context whose oauth2.HTTPClient trusts tokenServer's
// self-signed certificate, so the OAuth2 client-credentials flow can talk to an
// httptest.NewTLSServer over https without a real, publicly-trusted certificate.
func tokenServerContext(tokenServer *httptest.Server) context.Context {
	return context.WithValue(context.Background(), oauth2.HTTPClient, tokenServer.Client())
}

func TestNewServiceAccountConfig(t *testing.T) {
	var tokenRequests int32

	tokenServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&tokenRequests, 1)

		if err := r.ParseForm(); err != nil {
			t.Fatalf("failed to parse token request form: %v", err)
		}

		if got := r.PostFormValue("grant_type"); got != "client_credentials" {
			t.Fatalf("expected grant_type=client_credentials, got %q", got)
		}

		clientID, clientSecret, ok := r.BasicAuth()
		if !ok || clientID != "test-client-id" || clientSecret != "test-client-secret" {
			t.Fatalf("expected client credentials via Basic auth, got id=%q secret=%q ok=%v", clientID, clientSecret, ok)
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token": "test-access-token",
			"token_type":   "Bearer",
			"expires_in":   3600,
		})
	}))
	defer tokenServer.Close()

	var sawAuthHeader string

	apiServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sawAuthHeader = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
	}))
	defer apiServer.Close()

	cfg, err := NewServiceAccountConfig(tokenServerContext(tokenServer), "test-client-id", "test-client-secret", tokenServer.URL)
	if err != nil {
		t.Fatalf("NewServiceAccountConfig failed: %v", err)
	}

	resp, err := cfg.HTTPClient.Get(apiServer.URL)
	if err != nil {
		t.Fatalf("request via service-account-authenticated client failed: %v", err)
	}
	defer resp.Body.Close()

	if want := "Bearer test-access-token"; sawAuthHeader != want {
		t.Fatalf("expected Authorization header %q, got %q", want, sawAuthHeader)
	}

	if got := atomic.LoadInt32(&tokenRequests); got != 1 {
		t.Fatalf("expected exactly 1 token request for a single API call, got %d", got)
	}

	// A second call within the token's lifetime must reuse the cached token, not fetch a new one.
	resp2, err := cfg.HTTPClient.Get(apiServer.URL)
	if err != nil {
		t.Fatalf("second request failed: %v", err)
	}
	defer resp2.Body.Close()

	if got := atomic.LoadInt32(&tokenRequests); got != 1 {
		t.Fatalf("expected token to be cached and reused, but a second token request was made (total: %d)", got)
	}
}

func TestNewServiceAccountConfig_RefreshesExpiredToken(t *testing.T) {
	var tokenRequests int32

	tokenServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt32(&tokenRequests, 1)

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token": fmt.Sprintf("test-access-token-%d", n),
			"token_type":   "Bearer",
			// Already expired by the time it's received, forcing a refetch on
			// the next request instead of reuse. TestNewServiceAccountConfig
			// above covers the "reuse a still-valid token" half of auto
			// refresh; this covers the "fetch a new one once it's stale" half.
			"expires_in": -1,
		})
	}))
	defer tokenServer.Close()

	apiServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer apiServer.Close()

	cfg, err := NewServiceAccountConfig(tokenServerContext(tokenServer), "test-client-id", "test-client-secret", tokenServer.URL)
	if err != nil {
		t.Fatalf("NewServiceAccountConfig failed: %v", err)
	}

	const numRequests = 3
	for i := 0; i < numRequests; i++ {
		resp, err := cfg.HTTPClient.Get(apiServer.URL)
		if err != nil {
			t.Fatalf("request %d failed: %v", i, err)
		}
		resp.Body.Close()
	}

	if got := atomic.LoadInt32(&tokenRequests); got != numRequests {
		t.Fatalf("expected a fresh token fetch per request once each token is already expired, got %d fetches, want %d",
			got, numRequests)
	}
}

func TestNewServiceAccountAPIClient(t *testing.T) {
	tokenServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token": "test-access-token",
			"token_type":   "Bearer",
			"expires_in":   3600,
		})
	}))
	defer tokenServer.Close()

	client, err := NewServiceAccountAPIClient(tokenServerContext(tokenServer), "test-client-id", "test-client-secret", tokenServer.URL)
	if err != nil {
		t.Fatalf("NewServiceAccountAPIClient failed: %v", err)
	}
	if client == nil {
		t.Fatal("expected a non-nil APIClient")
	}
}

func TestNewServiceAccountConfig_TokenURLValidation(t *testing.T) {
	t.Run("empty tokenURL defaults instead of erroring", func(t *testing.T) {
		cfg, err := NewServiceAccountConfig(context.Background(), "id", "secret", "")
		if err != nil {
			t.Fatalf("expected an empty tokenURL to default rather than error, got: %v", err)
		}
		if cfg == nil {
			t.Fatal("expected a non-nil Configuration")
		}
	})

	t.Run("non-https tokenURL is rejected", func(t *testing.T) {
		_, err := NewServiceAccountConfig(context.Background(), "id", "secret", "http://example.com/oauth2/token")
		if err == nil {
			t.Fatal("expected a non-https tokenURL to be rejected")
		}
		if !strings.Contains(err.Error(), "https") {
			t.Fatalf("expected the error to mention the https requirement, got: %v", err)
		}
	})

	t.Run("https tokenURL is accepted", func(t *testing.T) {
		_, err := NewServiceAccountConfig(context.Background(), "id", "secret", "https://example.com/oauth2/token")
		if err != nil {
			t.Fatalf("expected an https tokenURL to be accepted, got: %v", err)
		}
	})
}
