package auth

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	swagger "github.com/crusoecloud/client-go/swagger/v1alpha5"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/clientcredentials"
)

// AuthenticatingTransport is a struct implementing http.Roundtripper
// that authenticates a request to Crusoe Cloud before sending it out.
type AuthenticatingTransport struct {
	keyID     string
	secretKey string
	http.RoundTripper
}

func NewAuthenticatingTransport(r http.RoundTripper, keyID, secretKey string) AuthenticatingTransport {
	if r == nil {
		r = http.DefaultTransport
	}

	return AuthenticatingTransport{
		RoundTripper: r,
		keyID:        keyID,
		secretKey:    secretKey,
	}
}

func (t AuthenticatingTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if err := AddSignature(r, t.keyID, t.secretKey); err != nil {
		return nil, err
	}

	//nolint:wrapcheck // error should be forwarded here.
	return t.RoundTripper.RoundTrip(r)
}

const (
	timestampHeader = "X-Crusoe-Timestamp"
	authHeader      = "Authorization"
	authVersion     = "1.0"
)

// Verifies if the token signature is valid for a given request.
func AddSignature(req *http.Request, encodedKeyID, encodedKey string) error {
	req.Header.Set(timestampHeader, time.Now().UTC().Format(time.RFC3339))

	message, err := generateMessageV1_0(req)
	if err != nil {
		return err
	}
	signature, err := signMessageV1_0(message, encodedKey)
	if err != nil {
		return err
	}

	req.Header.Set(authHeader,
		"Bearer "+fmt.Sprintf("%s:%s:%s", authVersion, encodedKeyID, base64.RawURLEncoding.EncodeToString(signature)))

	return nil
}

// Generates a sha256/hmac checksum of a given message.
func signMessageV1_0(message []byte, encodedKey string) ([]byte, error) {
	// Key is b64 encoded.
	expectedKey, err := base64.RawURLEncoding.DecodeString(encodedKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decode key: %w", err)
	}

	mac := hmac.New(sha256.New, expectedKey)
	mac.Write(message)

	return mac.Sum(nil), nil
}

// Per RFC, the message consists of:
// --start--
// http_path\n
// canonicalized_request_params\n
// http_verb\n
// timestamp_header_value\n
// --end--.
func generateMessageV1_0(req *http.Request) ([]byte, error) {
	messageString := strings.Builder{}

	// http_path\n
	messageString.WriteString(req.URL.Path + "\n")
	// canonicalized_request_params\n
	canonicalQuery, err := canonicalizeQuery(req.URL.RawQuery)
	if err != nil {
		return nil, err
	}
	messageString.WriteString(canonicalQuery + "\n")
	// http_verb\n
	messageString.WriteString(req.Method + "\n")
	// timestamp_header_value\n
	messageString.WriteString(req.Header.Get(timestampHeader) + "\n")

	return []byte(messageString.String()), nil
}

var errSemicolonSeparator = errors.New("invalid semicolon separator in query")

// Canonicalizes the query into a deterministic string.
// see https://cs.opensource.google/go/go/+/refs/tags/go1.18.8:src/net/url/url.go;l=921
func canonicalizeQuery(query string) (canonicalQuery string, err error) {
	values := make(map[string][]string)
	for query != "" {
		key := query
		if i := strings.IndexAny(key, "&"); i >= 0 {
			key, query = key[:i], key[i+1:]
		} else {
			query = ""
		}
		if strings.Contains(key, ";") {
			err = errSemicolonSeparator

			continue
		}
		if key == "" {
			continue
		}
		var value string
		key, value, _ = strings.Cut(key, "=")
		key, err1 := url.QueryUnescape(key)
		if err1 != nil {
			if err == nil {
				err = err1
			}

			continue
		}
		value, err1 = url.QueryUnescape(value)
		if err1 != nil {
			if err == nil {
				err = err1
			}

			continue
		}
		values[key] = append(values[key], value)
	}

	return encodeQuery(values), err
}

// encodeQuery encodes a key-value map representing the query into a deterministic string.
// see https://cs.opensource.google/go/go/+/refs/tags/go1.17.6:src/net/url/url.go;l=974
func encodeQuery(values map[string][]string) string {
	if values == nil {
		return ""
	}
	var buf strings.Builder
	keys := make([]string, 0, len(values))
	for k := range values {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		vs := values[k]
		keyEscaped := url.QueryEscape(k)
		for _, v := range vs {
			if buf.Len() > 0 {
				buf.WriteByte('&')
			}
			buf.WriteString(keyEscaped)
			buf.WriteByte('=')
			buf.WriteString(url.QueryEscape(v))
		}
	}

	return buf.String()
}

// NewAuthenticatedAPIClient initializes a new Crusoe API client with the given configuration.
func NewAuthenticatedAPIClient(accessKey, secret string) *swagger.APIClient {
	return swagger.NewAPIClient(NewAuthenticatedConfig(accessKey, secret))
}

// NewAuthenticatedConfig initializes a new Crusoe API configuration .
func NewAuthenticatedConfig(accessKey, secret string) *swagger.Configuration {
	cfg := swagger.NewConfiguration()
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = http.DefaultClient
	}

	cfg.HTTPClient.Transport = NewAuthenticatingTransport(cfg.HTTPClient.Transport, accessKey, secret)

	return cfg
}

// defaultServiceAccountTokenURL is used when NewServiceAccountConfig is called with an empty
// tokenURL.
//
//nolint:gosec // G101: URL constant, not a credential
const defaultServiceAccountTokenURL = "https://auth.crusoe.ai/oauth2/token"

// defaultServiceAccountAudience is used when NewServiceAccountConfig is called with an empty
// audience. It matches the audience prod's auth-gateway validates against, i.e. the environment
// defaultServiceAccountTokenURL itself points at.
const defaultServiceAccountAudience = "https://api.crusoe.ai"

// errInsecureTokenURL is returned when a non-empty tokenURL isn't https - sending it would mean
// a client secret goes out over the wire in the clear.
var errInsecureTokenURL = errors.New("tokenURL must be an https:// URL")

// defaultServiceAccountHTTPTimeout bounds a token fetch when the caller hasn't already supplied
// an http.Client via ctx (see ctxWithDefaultHTTPClient).
const defaultServiceAccountHTTPTimeout = 30 * time.Second

// newDefaultServiceAccountHTTPClient builds the client ctxWithDefaultHTTPClient injects when the
// caller hasn't supplied one. A var, not a plain call, so tests can substitute a client that also
// trusts a test TLS certificate instead of waiting out the real timeout.
//
//nolint:gochecknoglobals // deliberate test-injection seam, not shared mutable state
var newDefaultServiceAccountHTTPClient = func() *http.Client {
	return &http.Client{Timeout: defaultServiceAccountHTTPTimeout}
}

// ctxWithDefaultHTTPClient returns ctx unchanged if the caller already set an oauth2.HTTPClient
// value (e.g. a test's TLS-trusting client), otherwise returns ctx with a bounded client injected.
//
// Without this, oauth2.NewClient falls back to http.DefaultClient - which has no timeout - for
// fetching the token. A caller that builds this client once at startup with context.Background()
// (true of both Terraform and the CLI) would then have no way to bound a hang on a wedged
// connection: ctx is captured once at construction time, so cancelling some later, unrelated
// per-request context never reaches it. Per oauth2.NewClient's own doc comment, a context-supplied
// client is used only for token acquisition, so this has no effect on the returned
// *swagger.Configuration's own request timeouts.
func ctxWithDefaultHTTPClient(ctx context.Context) context.Context {
	if ctx.Value(oauth2.HTTPClient) != nil {
		return ctx
	}

	return context.WithValue(ctx, oauth2.HTTPClient, newDefaultServiceAccountHTTPClient())
}

// NewServiceAccountAPIClient initializes a new Crusoe API client authenticated as a service
// account via the OAuth2 client credentials grant. See NewServiceAccountConfig for how ctx
// bounds the token fetch (including its default timeout when ctx carries no oauth2.HTTPClient).
func NewServiceAccountAPIClient(ctx context.Context, clientID, clientSecret, tokenURL, audience string) (
	*swagger.APIClient, error,
) {
	// Delegate to NewServiceAccountConfig for tokenURL/audience validation and defaulting.
	cfg, err := NewServiceAccountConfig(ctx, clientID, clientSecret, tokenURL, audience)
	if err != nil {
		return nil, err
	}

	return swagger.NewAPIClient(cfg), nil
}

// NewServiceAccountConfig initializes a new Crusoe API configuration authenticated as a service
// account via the OAuth2 client credentials grant (clientID/clientSecret against tokenURL). The
// returned Configuration's HTTPClient fetches an access token on first use and refreshes it
// automatically as it nears expiry, for every subsequent request.
//
// tokenURL defaults to defaultServiceAccountTokenURL when empty. A non-empty tokenURL that isn't
// https is rejected, rather than sending the client secret over the wire in the clear.
//
// audience defaults to defaultServiceAccountAudience when empty, and is sent as the token
// request's "audience" form parameter (RFC 8707 resource indicator). Ory Hydra only treats a
// client's registered audience list as an allowlist - it does not stamp it onto every issued
// token - so a request that omits "audience" gets back a token with an empty aud claim, which
// auth-gateway then rejects (CCX-6069). Callers targeting a non-prod environment must pass the
// audience matching that environment's auth-gateway config alongside its tokenURL.
//
// The token fetch itself is bounded by defaultServiceAccountHTTPTimeout unless ctx already
// carries its own oauth2.HTTPClient - see ctxWithDefaultHTTPClient. That same injection point
// would also be the place to add retry/backoff (the parity gap documented where
// terraform-provider-crusoe wraps this client) if that's ever needed; not done here since it's a
// separate, larger design decision.
func NewServiceAccountConfig(ctx context.Context, clientID, clientSecret, tokenURL, audience string) (
	*swagger.Configuration, error,
) {
	// tokenURL defaulting/validation.
	switch {
	case tokenURL == "":
		tokenURL = defaultServiceAccountTokenURL
	case !strings.HasPrefix(tokenURL, "https://"):
		return nil, fmt.Errorf("%w: got %q", errInsecureTokenURL, tokenURL)
	}

	if audience == "" {
		audience = defaultServiceAccountAudience
	}

	cfg := swagger.NewConfiguration()

	cfg.HTTPClient = (&clientcredentials.Config{
		ClientID:       clientID,
		ClientSecret:   clientSecret,
		TokenURL:       tokenURL,
		EndpointParams: url.Values{"audience": {audience}},
		AuthStyle:      oauth2.AuthStyleInHeader,
	}).Client(ctxWithDefaultHTTPClient(ctx))

	return cfg, nil
}
