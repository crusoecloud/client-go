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

	"github.com/crusoecloud/client-go/internal/credentials"
	swagger "github.com/crusoecloud/client-go/swagger/v1alpha5"
	"golang.org/x/oauth2"
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

// NewAuthenticatedConfig initializes a new Crusoe API configuration. Always allocates a fresh
// *http.Client instead of reusing http.DefaultClient, which would mutate that process-wide client
// for every other goroutine using it.
func NewAuthenticatedConfig(accessKey, secret string) *swagger.Configuration {
	cfg := swagger.NewConfiguration()
	cfg.HTTPClient = &http.Client{
		Transport: NewAuthenticatingTransport(http.DefaultTransport, accessKey, secret),
	}

	return cfg
}

// defaultTokenFetchHTTPTimeout bounds a token fetch when the caller hasn't already supplied
// an http.Client via ctx (see ctxWithDefaultHTTPClient).
const defaultTokenFetchHTTPTimeout = 30 * time.Second

// newDefaultTokenFetchHTTPClient builds the client ctxWithDefaultHTTPClient injects when the
// caller hasn't supplied one. A var, not a plain call, so tests can substitute a client that also
// trusts a test TLS certificate instead of waiting out the real timeout.
//
//nolint:gochecknoglobals // deliberate test-injection seam, not shared mutable state
var newDefaultTokenFetchHTTPClient = func() *http.Client {
	return &http.Client{Timeout: defaultTokenFetchHTTPTimeout}
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

	return context.WithValue(ctx, oauth2.HTTPClient, newDefaultTokenFetchHTTPClient())
}

// NewClientSecretAPIClient initializes a new Crusoe API client authenticated as a service
// account via the OAuth2 client credentials grant. See NewClientSecretConfig for how ctx
// bounds the token fetch (including its default timeout when ctx carries no oauth2.HTTPClient).
func NewClientSecretAPIClient(ctx context.Context, clientID, clientSecret, tokenURL, audience string) (
	*swagger.APIClient, error,
) {
	// Delegate to NewClientSecretConfig for tokenURL/audience validation and defaulting.
	cfg, err := NewClientSecretConfig(ctx, clientID, clientSecret, tokenURL, audience)
	if err != nil {
		return nil, err
	}

	return swagger.NewAPIClient(cfg), nil
}

// NewClientSecretConfig initializes a new Crusoe API configuration authenticated as a service
// account via the OAuth2 client credentials grant (clientID/clientSecret against tokenURL). The
// returned Configuration's HTTPClient fetches an access token on first use and refreshes it
// automatically as it nears expiry, for every subsequent request.
//
// tokenURL/audience defaulting and validation, and the underlying oauth2.TokenSource, live in
// credentials.NewClientSecretTokenSource - see its doc comment for the RFC 8707 audience details.
// This wraps that TokenSource with the same ctx (bounded by defaultTokenFetchHTTPTimeout unless
// the caller already supplied an oauth2.HTTPClient - see ctxWithDefaultHTTPClient) via
// oauth2.NewClient to get a request-ready *http.Client. That same injection point would also be the
// place to add retry/backoff (the parity gap documented where terraform-provider-crusoe wraps this
// client) if that's ever needed; not done here since it's a separate, larger design decision.
func NewClientSecretConfig(ctx context.Context, clientID, clientSecret, tokenURL, audience string) (
	*swagger.Configuration, error,
) {
	//nolint:wsl // no blank line needed before this statement
	tokenCtx := ctxWithDefaultHTTPClient(ctx)

	tokenSource, err := credentials.NewClientSecretTokenSource(tokenCtx, clientID, clientSecret, tokenURL, audience)
	if err != nil {
		return nil, fmt.Errorf("constructing client secret token source: %w", err)
	}

	cfg := swagger.NewConfiguration()
	cfg.HTTPClient = oauth2.NewClient(tokenCtx, tokenSource)

	return cfg, nil
}

// options is a private alias for credentials.Options so that internal type doesn't leak into
// this package's exported API / godoc. Option and the With* functions below are the public
// interface; see their own doc comments for behavior.
type options = credentials.Options

// Option configures credential resolution for NewDefaultConfig and NewDefaultAPIClient.
type Option func(*options)

// WithAPIKey sets an explicit access key/secret key pair, taking precedence over
// environment variables and the config file.
func WithAPIKey(accessKey, secret string) Option {
	return func(o *options) {
		o.APIKey = credentials.APIKeyCredentials{AccessKeyID: accessKey, SecretKey: secret}
	}
}

// WithClientSecret sets explicit service account OAuth2 credentials, taking
// precedence over environment variables and the config file. tokenURL and audience may be left
// empty to use their defaults.
func WithClientSecret(clientID, clientSecret, tokenURL, audience string) Option {
	return func(o *options) {
		o.ClientSecret = credentials.ClientSecretCredentials{
			ClientID: clientID, ClientSecret: clientSecret, TokenURL: tokenURL, Audience: audience,
		}
	}
}

// WithProfile selects a named profile from the config file, overriding CRUSOE_PROFILE and the
// config file's own top-level profile key. Also takes precedence over CRUSOE_* environment
// variables for which identity is used, so a profile explicitly selected this way can't be
// overridden by unrelated env vars set elsewhere in the same process.
func WithProfile(name string) Option {
	return func(o *options) {
		o.Profile = name
	}
}

// WithConfigPath overrides the default ~/.crusoe/config path, for processes with no home
// directory or that keep their config file elsewhere. CRUSOE_CONFIG_DIR has the same effect via
// an environment variable instead.
func WithConfigPath(path string) Option {
	return func(o *options) {
		o.ConfigPath = path
	}
}

// NewDefaultConfig resolves credentials in this order: explicit options passed here, then
// CRUSOE_* environment variables, then ~/.crusoe/config, returning an error if neither a
// complete access-key/secret-key pair nor a complete service-account client ID/secret pair is
// found, or if both are found at once.
//
// The resulting *swagger.Configuration is built the same way NewAuthenticatedConfig or
// NewClientSecretConfig would build it; this only adds credential resolution on top.
func NewDefaultConfig(ctx context.Context, opts ...Option) (*swagger.Configuration, error) {
	var resolveOpts options
	for _, opt := range opts {
		opt(&resolveOpts)
	}

	cfg, loadErr := credentials.LoadConfigWithOptions(&resolveOpts)
	// Most load errors are advisory and still let resolution continue; these two are fatal and
	// must be returned directly, not buried as context behind a later ErrMissingCredentials.
	fatalLoadErr := errors.Is(loadErr, credentials.ErrProfileNotFound) ||
		errors.Is(loadErr, credentials.ErrProfileWithExplicitCredentials)
	if fatalLoadErr {
		return nil, fmt.Errorf("resolving default credentials: %w", loadErr)
	}

	method, err := credentials.ResolveAuthMethod(cfg)
	if err != nil {
		if loadErr != nil {
			return nil, fmt.Errorf("resolving default credentials: %w (config load: %s)", err, loadErr.Error())
		}

		return nil, fmt.Errorf("resolving default credentials: %w", err)
	}

	switch method {
	case credentials.AuthMethodClientSecret:
		return NewClientSecretConfig(ctx, cfg.ClientSecret.ClientID, cfg.ClientSecret.ClientSecret,
			cfg.ClientSecret.TokenURL, cfg.ClientSecret.Audience)
	case credentials.AuthMethodAPIKey:
		return NewAuthenticatedConfig(cfg.APIKey.AccessKeyID, cfg.APIKey.SecretKey), nil
	case credentials.AuthMethodUnknown:
		// Unreachable: ResolveAuthMethod only returns AuthMethodUnknown alongside a non-nil error,
		// already handled above.
		return nil, fmt.Errorf("resolving default credentials: %w", credentials.ErrMissingCredentials)
	default:
		// A method ResolveAuthMethod knows how to resolve but this switch has no case for yet -
		// e.g. a new AuthMethod added to authCandidates without a matching case added here. Fail
		// loudly instead of falling through to ErrMissingCredentials, which would misreport
		// credentials that were actually found as missing.
		return nil, fmt.Errorf("resolving default credentials: %w: %v", credentials.ErrUnsupportedAuthMethod, method)
	}
}

// NewDefaultAPIClient is NewDefaultConfig, wrapped in a ready-to-use *swagger.APIClient.
func NewDefaultAPIClient(ctx context.Context, opts ...Option) (*swagger.APIClient, error) {
	cfg, err := NewDefaultConfig(ctx, opts...)
	if err != nil {
		return nil, err
	}

	return swagger.NewAPIClient(cfg), nil
}
