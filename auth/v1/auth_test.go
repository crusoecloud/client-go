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
	"time"

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

	cfg, err := NewServiceAccountConfig(
		tokenServerContext(tokenServer), "test-client-id", "test-client-secret", tokenServer.URL, "")
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

	cfg, err := NewServiceAccountConfig(
		tokenServerContext(tokenServer), "test-client-id", "test-client-secret", tokenServer.URL, "")
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

	client, err := NewServiceAccountAPIClient(
		tokenServerContext(tokenServer), "test-client-id", "test-client-secret", tokenServer.URL, "")
	if err != nil {
		t.Fatalf("NewServiceAccountAPIClient failed: %v", err)
	}
	if client == nil {
		t.Fatal("expected a non-nil APIClient")
	}
}

func TestNewServiceAccountConfig_TokenURLValidation(t *testing.T) {
	t.Run("empty tokenURL defaults instead of erroring", func(t *testing.T) {
		cfg, err := NewServiceAccountConfig(context.Background(), "id", "secret", "", "")
		if err != nil {
			t.Fatalf("expected an empty tokenURL to default rather than error, got: %v", err)
		}
		if cfg == nil {
			t.Fatal("expected a non-nil Configuration")
		}
	})

	t.Run("non-https tokenURL is rejected", func(t *testing.T) {
		_, err := NewServiceAccountConfig(context.Background(), "id", "secret", "http://example.com/oauth2/token", "")
		if err == nil {
			t.Fatal("expected a non-https tokenURL to be rejected")
		}
		if !strings.Contains(err.Error(), "https") {
			t.Fatalf("expected the error to mention the https requirement, got: %v", err)
		}
	})

	t.Run("https tokenURL is accepted", func(t *testing.T) {
		_, err := NewServiceAccountConfig(context.Background(), "id", "secret", "https://example.com/oauth2/token", "")
		if err != nil {
			t.Fatalf("expected an https tokenURL to be accepted, got: %v", err)
		}
	})
}

// TestNewServiceAccountConfig_Audience guards against CCX-6069: Hydra only treats a client's
// registered audience as an allowlist, not something it stamps onto every issued token, so the
// token request itself must carry an explicit "audience" form value or the resulting access
// token's aud claim comes back empty and auth-gateway rejects it.
func TestNewServiceAccountConfig_Audience(t *testing.T) {
	// audienceCapturingTokenServer returns a token server that records the "audience" form
	// value it was sent with on each request, in the sawAudiences slice.
	audienceCapturingTokenServer := func(sawAudiences *[]string) *httptest.Server {
		return httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if err := r.ParseForm(); err != nil {
				t.Fatalf("failed to parse token request form: %v", err)
			}
			*sawAudiences = append(*sawAudiences, r.PostFormValue("audience"))

			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"access_token": "test-access-token",
				"token_type":   "Bearer",
				"expires_in":   3600,
			})
		}))
	}

	t.Run("empty audience defaults to defaultServiceAccountAudience", func(t *testing.T) {
		var sawAudiences []string
		tokenServer := audienceCapturingTokenServer(&sawAudiences)
		defer tokenServer.Close()

		apiServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))
		defer apiServer.Close()

		cfg, err := NewServiceAccountConfig(
			tokenServerContext(tokenServer), "test-client-id", "test-client-secret", tokenServer.URL, "")
		if err != nil {
			t.Fatalf("NewServiceAccountConfig failed: %v", err)
		}

		resp, err := cfg.HTTPClient.Get(apiServer.URL)
		if err != nil {
			t.Fatalf("request via service-account-authenticated client failed: %v", err)
		}
		resp.Body.Close()

		if len(sawAudiences) != 1 || sawAudiences[0] != defaultServiceAccountAudience {
			t.Fatalf("expected token request audience=%q, got %v", defaultServiceAccountAudience, sawAudiences)
		}
	})

	t.Run("explicit audience overrides the default", func(t *testing.T) {
		const wantAudience = "https://api.crusoe.xyz"

		var sawAudiences []string
		tokenServer := audienceCapturingTokenServer(&sawAudiences)
		defer tokenServer.Close()

		apiServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))
		defer apiServer.Close()

		cfg, err := NewServiceAccountConfig(
			tokenServerContext(tokenServer), "test-client-id", "test-client-secret", tokenServer.URL, wantAudience)
		if err != nil {
			t.Fatalf("NewServiceAccountConfig failed: %v", err)
		}

		resp, err := cfg.HTTPClient.Get(apiServer.URL)
		if err != nil {
			t.Fatalf("request via service-account-authenticated client failed: %v", err)
		}
		resp.Body.Close()

		if len(sawAudiences) != 1 || sawAudiences[0] != wantAudience {
			t.Fatalf("expected token request audience=%q, got %v", wantAudience, sawAudiences)
		}
	})

	t.Run("NewServiceAccountAPIClient accepts an explicit audience", func(t *testing.T) {
		// NewServiceAccountAPIClient is a thin passthrough to NewServiceAccountConfig (whose
		// audience-forwarding is fully exercised by the subtests above); swagger.APIClient
		// doesn't expose its wrapped Configuration, so this only confirms the audience is
		// accepted and construction succeeds, mirroring TestNewServiceAccountAPIClient.
		tokenServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"access_token": "test-access-token",
				"token_type":   "Bearer",
				"expires_in":   3600,
			})
		}))
		defer tokenServer.Close()

		client, err := NewServiceAccountAPIClient(
			tokenServerContext(tokenServer), "test-client-id", "test-client-secret", tokenServer.URL, "https://api.crusoe.tech")
		if err != nil {
			t.Fatalf("NewServiceAccountAPIClient failed: %v", err)
		}
		if client == nil {
			t.Fatal("expected a non-nil APIClient")
		}
	})
}

// TestCtxWithDefaultHTTPClient guards against a wedged connection hanging a token fetch forever:
// a caller that builds this client once at startup with context.Background() (true of both
// Terraform and the CLI) has no other way to bound it, since ctx is captured once and a later,
// unrelated per-request context's cancellation never reaches it.
func TestCtxWithDefaultHTTPClient(t *testing.T) {
	t.Run("injects a bounded client when the caller supplied none", func(t *testing.T) {
		got := ctxWithDefaultHTTPClient(context.Background())

		client, ok := got.Value(oauth2.HTTPClient).(*http.Client)
		if !ok {
			t.Fatalf("expected an *http.Client under oauth2.HTTPClient, got %T", got.Value(oauth2.HTTPClient))
		}
		if client.Timeout != defaultServiceAccountHTTPTimeout {
			t.Fatalf("expected Timeout %v, got %v", defaultServiceAccountHTTPTimeout, client.Timeout)
		}
	})

	t.Run("preserves the caller's client instead of overwriting it", func(t *testing.T) {
		want := &http.Client{Timeout: 5 * time.Second}
		ctx := context.WithValue(context.Background(), oauth2.HTTPClient, want)

		got := ctxWithDefaultHTTPClient(ctx)

		if got.Value(oauth2.HTTPClient).(*http.Client) != want {
			t.Fatal("expected the caller's client to be preserved unchanged, got a different one")
		}
	})
}

// TestNewServiceAccountConfig_DefaultHTTPClientTimesOutOnAWedgedConnection is an end-to-end
// regression test for the bug this fix addresses: with no oauth2.HTTPClient supplied and a
// context that never itself expires (context.Background(), exactly what Terraform/the CLI use),
// a token server that never responds must still cause the token fetch to give up on its own,
// rather than hang forever.
//
// newDefaultServiceAccountHTTPClient is substituted (rather than just shrinking
// defaultServiceAccountHTTPTimeout) so the swapped-in client can also trust the test TLS
// certificate - ctxWithDefaultHTTPClient's own "caller supplied none" branch is still exactly
// what runs; only what it injects is swapped for a faster, trusting equivalent.
func TestNewServiceAccountConfig_DefaultHTTPClientTimesOutOnAWedgedConnection(t *testing.T) {
	block := make(chan struct{})

	tokenServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-block // never respond until the test cleans up
	}))
	// Cleanups run LIFO: close(block) must unblock the handler(s) BEFORE Close() waits for their
	// connections to finish, or Close() hangs forever. Registering Close() first, then close(block),
	// gets that order.
	t.Cleanup(tokenServer.Close)
	t.Cleanup(func() { close(block) })

	origNewClient := newDefaultServiceAccountHTTPClient
	newDefaultServiceAccountHTTPClient = func() *http.Client {
		client := *tokenServer.Client() // clone: trusts the test cert, without mutating the shared one
		client.Timeout = 50 * time.Millisecond

		return &client
	}
	t.Cleanup(func() { newDefaultServiceAccountHTTPClient = origNewClient })

	cfg, err := NewServiceAccountConfig(context.Background(), "id", "secret", tokenServer.URL, "")
	if err != nil {
		t.Fatalf("NewServiceAccountConfig failed: %v", err)
	}

	// The target URL doesn't matter - tokenServer.URL is reused only because it's a real,
	// reachable address. The oauth2 Transport always fetches a token before proxying the actual
	// request, so this call fails during that token fetch and never reaches the target at all.
	start := time.Now()
	_, err = cfg.HTTPClient.Get(tokenServer.URL)
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("expected the token fetch to fail once the wedged connection outlasts the timeout")
	}
	if elapsed > 2*time.Second {
		t.Fatalf("token fetch took %v to fail; expected it to give up near the 50ms timeout, not hang", elapsed)
	}
}
