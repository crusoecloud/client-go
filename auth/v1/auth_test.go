package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/crusoecloud/client-go/internal/credentials"
	"golang.org/x/oauth2"
)

// tokenServerContext returns a context whose oauth2.HTTPClient trusts tokenServer's
// self-signed certificate, so the OAuth2 client-credentials flow can talk to an
// httptest.NewTLSServer over https without a real, publicly-trusted certificate.
func tokenServerContext(tokenServer *httptest.Server) context.Context {
	return context.WithValue(context.Background(), oauth2.HTTPClient, tokenServer.Client())
}

func TestNewAuthenticatedConfig_DoesNotMutateDefaultClient(t *testing.T) {
	originalTransport := http.DefaultClient.Transport

	cfg1 := NewAuthenticatedConfig("key-a", "secret-a")

	if http.DefaultClient.Transport != originalTransport {
		t.Fatal("NewAuthenticatedConfig mutated http.DefaultClient.Transport")
	}
	if cfg1.HTTPClient == http.DefaultClient {
		t.Fatal("expected a fresh *http.Client, got http.DefaultClient itself")
	}

	// A second call with different credentials must not affect the first client's.
	cfg2 := NewAuthenticatedConfig("key-b", "secret-b")

	transport1, ok := cfg1.HTTPClient.Transport.(AuthenticatingTransport)
	if !ok {
		t.Fatalf("expected an AuthenticatingTransport, got %T", cfg1.HTTPClient.Transport)
	}
	transport2, ok := cfg2.HTTPClient.Transport.(AuthenticatingTransport)
	if !ok {
		t.Fatalf("expected an AuthenticatingTransport, got %T", cfg2.HTTPClient.Transport)
	}
	if transport1.keyID != "key-a" || transport2.keyID != "key-b" {
		t.Fatalf("expected independent clients to keep their own credentials, got %q and %q",
			transport1.keyID, transport2.keyID)
	}
}

func TestNewClientSecretConfig(t *testing.T) {
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

	cfg, err := NewClientSecretConfig(
		tokenServerContext(tokenServer), "test-client-id", "test-client-secret", tokenServer.URL, "")
	if err != nil {
		t.Fatalf("NewClientSecretConfig failed: %v", err)
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

func TestNewClientSecretConfig_RefreshesExpiredToken(t *testing.T) {
	var tokenRequests int32

	tokenServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt32(&tokenRequests, 1)

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token": fmt.Sprintf("test-access-token-%d", n),
			"token_type":   "Bearer",
			// Already expired by the time it's received, forcing a refetch on
			// the next request instead of reuse. TestNewClientSecretConfig
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

	cfg, err := NewClientSecretConfig(
		tokenServerContext(tokenServer), "test-client-id", "test-client-secret", tokenServer.URL, "")
	if err != nil {
		t.Fatalf("NewClientSecretConfig failed: %v", err)
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

func TestNewClientSecretAPIClient(t *testing.T) {
	tokenServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token": "test-access-token",
			"token_type":   "Bearer",
			"expires_in":   3600,
		})
	}))
	defer tokenServer.Close()

	client, err := NewClientSecretAPIClient(
		tokenServerContext(tokenServer), "test-client-id", "test-client-secret", tokenServer.URL, "")
	if err != nil {
		t.Fatalf("NewClientSecretAPIClient failed: %v", err)
	}
	if client == nil {
		t.Fatal("expected a non-nil APIClient")
	}
}

func TestNewClientSecretConfig_TokenURLValidation(t *testing.T) {
	t.Run("empty tokenURL defaults instead of erroring", func(t *testing.T) {
		cfg, err := NewClientSecretConfig(context.Background(), "id", "secret", "", "")
		if err != nil {
			t.Fatalf("expected an empty tokenURL to default rather than error, got: %v", err)
		}
		if cfg == nil {
			t.Fatal("expected a non-nil Configuration")
		}
	})

	t.Run("non-https tokenURL is rejected", func(t *testing.T) {
		_, err := NewClientSecretConfig(context.Background(), "id", "secret", "http://example.com/oauth2/token", "")
		if err == nil {
			t.Fatal("expected a non-https tokenURL to be rejected")
		}
		if !strings.Contains(err.Error(), "https") {
			t.Fatalf("expected the error to mention the https requirement, got: %v", err)
		}
	})

	t.Run("https tokenURL is accepted", func(t *testing.T) {
		_, err := NewClientSecretConfig(context.Background(), "id", "secret", "https://example.com/oauth2/token", "")
		if err != nil {
			t.Fatalf("expected an https tokenURL to be accepted, got: %v", err)
		}
	})
}

// An omitted audience yields an empty aud claim, which auth-gateway rejects.
func TestNewClientSecretConfig_Audience(t *testing.T) {
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

	t.Run("empty audience defaults to the package default", func(t *testing.T) {
		var sawAudiences []string
		tokenServer := audienceCapturingTokenServer(&sawAudiences)
		defer tokenServer.Close()

		apiServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))
		defer apiServer.Close()

		cfg, err := NewClientSecretConfig(
			tokenServerContext(tokenServer), "test-client-id", "test-client-secret", tokenServer.URL, "")
		if err != nil {
			t.Fatalf("NewClientSecretConfig failed: %v", err)
		}

		resp, err := cfg.HTTPClient.Get(apiServer.URL)
		if err != nil {
			t.Fatalf("request via service-account-authenticated client failed: %v", err)
		}
		resp.Body.Close()

		if len(sawAudiences) != 1 || sawAudiences[0] != credentials.DefaultAudience {
			t.Fatalf("expected token request audience=%q, got %v", credentials.DefaultAudience, sawAudiences)
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

		cfg, err := NewClientSecretConfig(
			tokenServerContext(tokenServer), "test-client-id", "test-client-secret", tokenServer.URL, wantAudience)
		if err != nil {
			t.Fatalf("NewClientSecretConfig failed: %v", err)
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

	t.Run("NewClientSecretAPIClient accepts an explicit audience", func(t *testing.T) {
		// NewClientSecretAPIClient is a thin passthrough to NewClientSecretConfig (whose
		// audience-forwarding is fully exercised by the subtests above); swagger.APIClient
		// doesn't expose its wrapped Configuration, so this only confirms the audience is
		// accepted and construction succeeds, mirroring TestNewClientSecretAPIClient.
		tokenServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"access_token": "test-access-token",
				"token_type":   "Bearer",
				"expires_in":   3600,
			})
		}))
		defer tokenServer.Close()

		client, err := NewClientSecretAPIClient(
			tokenServerContext(tokenServer), "test-client-id", "test-client-secret", tokenServer.URL, "https://api.crusoe.tech")
		if err != nil {
			t.Fatalf("NewClientSecretAPIClient failed: %v", err)
		}
		if client == nil {
			t.Fatal("expected a non-nil APIClient")
		}
	})
}

// A client built once with context.Background() has no other way to bound a wedged connection.
func TestCtxWithDefaultHTTPClient(t *testing.T) {
	t.Run("injects a bounded client when the caller supplied none", func(t *testing.T) {
		got := ctxWithDefaultHTTPClient(context.Background())

		client, ok := got.Value(oauth2.HTTPClient).(*http.Client)
		if !ok {
			t.Fatalf("expected an *http.Client under oauth2.HTTPClient, got %T", got.Value(oauth2.HTTPClient))
		}
		if client.Timeout != defaultTokenFetchHTTPTimeout {
			t.Fatalf("expected Timeout %v, got %v", defaultTokenFetchHTTPTimeout, client.Timeout)
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

// A wedged token server must not hang forever, even with context.Background().
func TestNewClientSecretConfig_DefaultHTTPClientTimesOutOnAWedgedConnection(t *testing.T) {
	block := make(chan struct{})
	var tokenRequests int32

	tokenServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&tokenRequests, 1)
		<-block // never respond until the test cleans up
	}))
	// Cleanups run LIFO: close(block) must unblock the handler(s) BEFORE Close() waits for their
	// connections to finish, or Close() hangs forever. Registering Close() first, then close(block),
	// gets that order.
	t.Cleanup(tokenServer.Close)
	t.Cleanup(func() { close(block) })

	origNewClient := newDefaultTokenFetchHTTPClient
	newDefaultTokenFetchHTTPClient = func() *http.Client {
		client := *tokenServer.Client() // clone: trusts the test cert, without mutating the shared one
		client.Timeout = 50 * time.Millisecond

		return &client
	}
	t.Cleanup(func() { newDefaultTokenFetchHTTPClient = origNewClient })

	cfg, err := NewClientSecretConfig(context.Background(), "id", "secret", tokenServer.URL, "")
	if err != nil {
		t.Fatalf("NewClientSecretConfig failed: %v", err)
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

	if got := atomic.LoadInt32(&tokenRequests); got != 1 {
		t.Fatalf("expected exactly 1 token request (AuthStyle set explicitly), got %d - "+
			"did AuthStyle regress to auto-detecting on every call?", got)
	}
}

var defaultConfigEnvVars = []string{
	"CRUSOE_PROFILE",
	"CRUSOE_ACCESS_KEY_ID",
	"CRUSOE_SECRET_KEY",
	"CRUSOE_CLIENT_ID",
	"CRUSOE_CLIENT_SECRET",
	"CRUSOE_TOKEN_URL",
	"CRUSOE_AUDIENCE",
}

func clearDefaultConfigEnvVars(t *testing.T) string {
	t.Helper()

	for _, name := range defaultConfigEnvVars {
		t.Setenv(name, "")
		os.Unsetenv(name) //nolint:errcheck,usetesting
	}

	return filepath.Join(t.TempDir(), "does-not-exist")
}

func TestNewDefaultConfig_APIKeyFromOptions(t *testing.T) {
	configPath := clearDefaultConfigEnvVars(t)

	cfg, err := NewDefaultConfig(context.Background(),
		WithAPIKey("explicit-key", "explicit-secret"), WithConfigPath(configPath))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	transport, ok := cfg.HTTPClient.Transport.(AuthenticatingTransport)
	if !ok {
		t.Fatalf("expected an AuthenticatingTransport, got %T", cfg.HTTPClient.Transport)
	}
	if transport.keyID != "explicit-key" || transport.secretKey != "explicit-secret" {
		t.Fatalf("expected explicit credentials to be used, got keyID=%q", transport.keyID)
	}
}

func TestNewDefaultConfig_APIKeyFromEnv(t *testing.T) {
	configPath := clearDefaultConfigEnvVars(t)
	t.Setenv("CRUSOE_ACCESS_KEY_ID", "env-key")
	t.Setenv("CRUSOE_SECRET_KEY", "env-secret")

	cfg, err := NewDefaultConfig(context.Background(), WithConfigPath(configPath))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	transport, ok := cfg.HTTPClient.Transport.(AuthenticatingTransport)
	if !ok {
		t.Fatalf("expected an AuthenticatingTransport, got %T", cfg.HTTPClient.Transport)
	}
	if transport.keyID != "env-key" || transport.secretKey != "env-secret" {
		t.Fatalf("expected env credentials to be used, got keyID=%q", transport.keyID)
	}
}

func TestNewDefaultConfig_ServiceAccountFromOptions(t *testing.T) {
	configPath := clearDefaultConfigEnvVars(t)

	tokenServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token": "test-access-token",
			"token_type":   "Bearer",
			"expires_in":   3600,
		})
	}))
	defer tokenServer.Close()

	cfg, err := NewDefaultConfig(tokenServerContext(tokenServer),
		WithClientSecret("test-client-id", "test-client-secret", tokenServer.URL, "test-audience"),
		WithConfigPath(configPath))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	apiServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer apiServer.Close()

	resp, err := cfg.HTTPClient.Get(apiServer.URL)
	if err != nil {
		t.Fatalf("request via resolved client failed: %v", err)
	}
	defer resp.Body.Close()
}

func TestNewDefaultConfig_ServiceAccountFromConfigFile(t *testing.T) {
	clearDefaultConfigEnvVars(t)

	tokenServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token": "test-access-token",
			"token_type":   "Bearer",
			"expires_in":   3600,
		})
	}))
	defer tokenServer.Close()

	configPath := filepath.Join(t.TempDir(), "config")
	configContent := fmt.Sprintf(`
[default]
client_id = "file-client-id"
client_secret = "file-client-secret"
token_url = %q
audience = "test-audience"
`, tokenServer.URL)
	if err := os.WriteFile(configPath, []byte(configContent), 0o600); err != nil {
		t.Fatalf("failed to write temp config: %v", err)
	}

	cfg, err := NewDefaultConfig(tokenServerContext(tokenServer), WithConfigPath(configPath))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg == nil {
		t.Fatal("expected a non-nil Configuration")
	}
}

func TestNewDefaultConfig_ConflictingCredentialsReturnsError(t *testing.T) {
	configPath := clearDefaultConfigEnvVars(t)

	_, err := NewDefaultConfig(context.Background(),
		WithAPIKey("key", "secret"),
		WithClientSecret("client-id", "client-secret", "", ""),
		WithConfigPath(configPath))
	if !errors.Is(err, credentials.ErrConflictingCredentials) {
		t.Fatalf("expected ErrConflictingCredentials, got: %v", err)
	}
}

func TestNewDefaultConfig_MissingCredentialsReturnsError(t *testing.T) {
	configPath := clearDefaultConfigEnvVars(t)

	_, err := NewDefaultConfig(context.Background(), WithConfigPath(configPath))
	if !errors.Is(err, credentials.ErrMissingCredentials) {
		t.Fatalf("expected ErrMissingCredentials, got: %v", err)
	}
}

func TestNewDefaultConfig_ProfileSelection(t *testing.T) {
	clearDefaultConfigEnvVars(t)

	configPath := filepath.Join(t.TempDir(), "config")
	configContent := `
[production]
access_key_id = "prod-key"
secret_key = "prod-secret"

[staging]
access_key_id = "staging-key"
secret_key = "staging-secret"
`
	if err := os.WriteFile(configPath, []byte(configContent), 0o600); err != nil {
		t.Fatalf("failed to write temp config: %v", err)
	}

	cfg, err := NewDefaultConfig(context.Background(), WithConfigPath(configPath), WithProfile("staging"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	transport, ok := cfg.HTTPClient.Transport.(AuthenticatingTransport)
	if !ok {
		t.Fatalf("expected an AuthenticatingTransport, got %T", cfg.HTTPClient.Transport)
	}
	if transport.keyID != "staging-key" || transport.secretKey != "staging-secret" {
		t.Fatalf("expected staging profile credentials, got keyID=%q", transport.keyID)
	}
}
