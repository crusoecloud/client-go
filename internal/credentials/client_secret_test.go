package credentials

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
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
		if sawAudience != DefaultServiceAccountAudience {
			t.Fatalf("expected default audience %q, got %q", DefaultServiceAccountAudience, sawAudience)
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
