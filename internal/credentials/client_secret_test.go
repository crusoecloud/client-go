package credentials

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"sync/atomic"
	"testing"

	"golang.org/x/oauth2"
)

// tokenServerContext returns a context whose oauth2.HTTPClient trusts tokenServer's self-signed
// certificate, so the token source can talk to an httptest.NewTLSServer over https without a real,
// publicly-trusted certificate.
func tokenServerContext(tokenServer *httptest.Server) context.Context {
	return context.WithValue(context.Background(), oauth2.HTTPClient, tokenServer.Client())
}

func TestNewClientSecretTokenSource(t *testing.T) {
	tokenServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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

	source, err := NewClientSecretTokenSource(
		tokenServerContext(tokenServer), "test-client-id", "test-client-secret", tokenServer.URL, "")
	if err != nil {
		t.Fatalf("NewClientSecretTokenSource failed: %v", err)
	}

	token, err := source.Token()
	if err != nil {
		t.Fatalf("Token() failed: %v", err)
	}
	if token.AccessToken != "test-access-token" {
		t.Fatalf("expected access token %q, got %q", "test-access-token", token.AccessToken)
	}
}

func TestNewClientSecretTokenSource_Audience(t *testing.T) {
	var sawAudience string

	tokenServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Fatalf("failed to parse token request form: %v", err)
		}
		sawAudience = r.PostFormValue("audience")

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token": "test-access-token",
			"token_type":   "Bearer",
			"expires_in":   3600,
		})
	}))
	defer tokenServer.Close()

	t.Run("empty audience defaults to the package default", func(t *testing.T) {
		source, err := NewClientSecretTokenSource(
			tokenServerContext(tokenServer), "test-client-id", "test-client-secret", tokenServer.URL, "")
		if err != nil {
			t.Fatalf("NewClientSecretTokenSource failed: %v", err)
		}
		if _, err := source.Token(); err != nil {
			t.Fatalf("Token() failed: %v", err)
		}
		if sawAudience != DefaultAudience {
			t.Fatalf("expected default audience %q, got %q", DefaultAudience, sawAudience)
		}
	})

	t.Run("explicit audience overrides the default", func(t *testing.T) {
		source, err := NewClientSecretTokenSource(
			tokenServerContext(tokenServer), "test-client-id", "test-client-secret", tokenServer.URL, "https://api.example.com")
		if err != nil {
			t.Fatalf("NewClientSecretTokenSource failed: %v", err)
		}
		if _, err := source.Token(); err != nil {
			t.Fatalf("Token() failed: %v", err)
		}
		if sawAudience != "https://api.example.com" {
			t.Fatalf("expected explicit audience, got %q", sawAudience)
		}
	})
}

func TestNewClientSecretTokenSource_TokenURLValidation(t *testing.T) {
	t.Run("empty tokenURL defaults instead of erroring", func(t *testing.T) {
		source, err := NewClientSecretTokenSource(context.Background(), "id", "secret", "", "")
		if err != nil {
			t.Fatalf("expected an empty tokenURL to default rather than error, got: %v", err)
		}
		if source == nil {
			t.Fatal("expected a non-nil TokenSource")
		}
	})

	t.Run("non-https tokenURL is rejected", func(t *testing.T) {
		_, err := NewClientSecretTokenSource(context.Background(), "id", "secret", "http://example.com/oauth2/token", "")
		if !errors.Is(err, ErrInsecureTokenURL) {
			t.Fatalf("expected ErrInsecureTokenURL, got: %v", err)
		}
	})

	t.Run("https tokenURL is accepted", func(t *testing.T) {
		_, err := NewClientSecretTokenSource(context.Background(), "id", "secret", "https://example.com/oauth2/token", "")
		if err != nil {
			t.Fatalf("expected an https tokenURL to be accepted, got: %v", err)
		}
	})
}

// countingTokenServer returns a token server plus a counter of how many token requests it served.
func countingTokenServer(t *testing.T) (*httptest.Server, *int32) {
	t.Helper()

	var requests int32

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&requests, 1)

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token": "test-access-token",
			"token_type":   "Bearer",
			"expires_in":   3600,
		})
	}))
	t.Cleanup(server.Close)

	return server, &requests
}

func TestNewClientSecretTokenSource_DiskTokenCacheIsOptIn(t *testing.T) {
	t.Run("no options never touches the disk", func(t *testing.T) {
		tokenServer, requests := countingTokenServer(t)
		dir := t.TempDir()

		for i := 0; i < 2; i++ {
			source, err := NewClientSecretTokenSource(
				tokenServerContext(tokenServer), "test-client-id", "test-client-secret", tokenServer.URL, "")
			if err != nil {
				t.Fatalf("NewClientSecretTokenSource failed: %v", err)
			}
			if _, err := source.Token(); err != nil {
				t.Fatalf("Token() failed: %v", err)
			}
		}

		if got := atomic.LoadInt32(requests); got != 2 {
			t.Fatalf("expected each source to mint its own token without options, got %d requests", got)
		}

		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Fatalf("failed to read the temp dir: %v", err)
		}
		if len(entries) != 0 {
			t.Fatalf("expected no files to be written without WithDiskTokenCache, got %v", entries)
		}
	})

	t.Run("WithDiskTokenCache reuses a token across sources", func(t *testing.T) {
		tokenServer, requests := countingTokenServer(t)
		dir := t.TempDir()

		for i := 0; i < 3; i++ {
			source, err := NewClientSecretTokenSource(
				tokenServerContext(tokenServer), "test-client-id", "test-client-secret", tokenServer.URL, "",
				WithDiskTokenCache(dir))
			if err != nil {
				t.Fatalf("NewClientSecretTokenSource failed: %v", err)
			}

			token, err := source.Token()
			if err != nil {
				t.Fatalf("Token() failed: %v", err)
			}
			if token.AccessToken != "test-access-token" {
				t.Fatalf("expected the cached access token, got %q", token.AccessToken)
			}
		}

		if got := atomic.LoadInt32(requests); got != 1 {
			t.Fatalf("expected exactly one token request across three sources, got %d", got)
		}

		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Fatalf("failed to read the cache dir: %v", err)
		}
		if len(entries) != 1 {
			t.Fatalf("expected exactly one cache file, got %v", entries)
		}
	})

	t.Run("an invalid tokenURL still errors before any cache dir is created", func(t *testing.T) {
		dir := t.TempDir()

		_, err := NewClientSecretTokenSource(context.Background(), "id", "secret", "http://example.com/token", "",
			WithDiskTokenCache(dir))
		if !errors.Is(err, ErrInsecureTokenURL) {
			t.Fatalf("expected ErrInsecureTokenURL, got: %v", err)
		}

		entries, readErr := os.ReadDir(dir)
		if readErr != nil {
			t.Fatalf("failed to read the cache dir: %v", readErr)
		}
		if len(entries) != 0 {
			t.Fatalf("expected no cache files after a validation failure, got %v", entries)
		}
	})
}
