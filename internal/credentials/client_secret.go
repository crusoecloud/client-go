package credentials

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strings"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/clientcredentials"
)

// ErrInsecureTokenURL is returned when a non-empty tokenURL isn't https - sending it would mean a
// client secret goes out over the wire in the clear.
var ErrInsecureTokenURL = errors.New("tokenURL must be an https:// URL")

// clientSecretOptions collects the optional behavior a caller can turn on for the token source
// itself. It is unrelated to Options, which governs which credentials get resolved in the first
// place.
type clientSecretOptions struct {
	diskCacheDir string
}

// ClientSecretOption configures optional behavior of the token source returned by
// NewClientSecretTokenSource.
type ClientSecretOption func(*clientSecretOptions)

// WithDiskTokenCache caches minted access tokens on disk under dir, reused across process
// invocations until near expiry. Off by default.
//
// dir is created 0700 if missing, and must already be privately owned/permissioned if it exists -
// otherwise caching is silently skipped (POSIX-only; Windows only checks it's a directory). Cache
// files are 0600, named by hash only; the client secret is never written. Revocation (unlike
// rotation) isn't caught by the cache key - see InvalidateDiskTokenCache.
func WithDiskTokenCache(dir string) ClientSecretOption {
	return func(o *clientSecretOptions) {
		o.diskCacheDir = dir
	}
}

// defaultTokenURLAndAudience applies the same empty-string substitution NewClientSecretTokenSource
// validates and defaults tokenURL/audience with, so InvalidateDiskTokenCache hashes the same
// effective values a token source built from the same raw inputs would - a caller that constructed
// with "" and invalidates with "" must land on the same cache file, not a different one that was
// never written.
func defaultTokenURLAndAudience(tokenURL, audience string) (resolvedTokenURL, resolvedAudience string) {
	if tokenURL == "" {
		tokenURL = DefaultTokenURL
	}

	if audience == "" {
		audience = DefaultAudience
	}

	return tokenURL, audience
}

// NewClientSecretTokenSource returns an oauth2.TokenSource for the OAuth2 client_credentials grant,
// authenticated via a shared client secret - the decoratable unit a caller wraps with
// oauth2.NewClient (as auth.NewClientSecretConfig does) to get a request-ready *http.Client. ctx is
// used only for the token-minting HTTP calls this source makes - see oauth2.HTTPClient.
//
// tokenURL defaults to DefaultTokenURL when empty; a non-empty tokenURL that isn't
// https is rejected, rather than sending the client secret over the wire in the clear.
//
// audience defaults to DefaultAudience when empty, and is sent as the token request's
// "audience" form parameter (RFC 8707 resource indicator). Ory Hydra only treats a client's
// registered audience list as an allowlist - it does not stamp it onto every issued token - so a
// request that omits "audience" gets back a token with an empty aud claim, which auth-gateway then
// rejects. Callers targeting a non-prod environment must pass the audience matching that
// environment's auth-gateway config alongside its tokenURL.
//
// opts are additive and off by default - see WithDiskTokenCache.
func NewClientSecretTokenSource(
	ctx context.Context, clientID, clientSecret, tokenURL, audience string, opts ...ClientSecretOption,
) (oauth2.TokenSource, error) {
	// A non-empty tokenURL is validated before defaulting - only the empty case is a default.
	if tokenURL != "" && !strings.HasPrefix(tokenURL, "https://") {
		return nil, fmt.Errorf("%w: got %q", ErrInsecureTokenURL, tokenURL)
	}

	tokenURL, audience = defaultTokenURLAndAudience(tokenURL, audience)

	// Applied after defaulting so the cache key below hashes the effective tokenURL/audience.
	var sourceOpts clientSecretOptions
	for _, opt := range opts {
		opt(&sourceOpts)
	}

	source := (&clientcredentials.Config{
		ClientID:       clientID,
		ClientSecret:   clientSecret,
		TokenURL:       tokenURL,
		EndpointParams: url.Values{"audience": {audience}},
		AuthStyle:      oauth2.AuthStyleInHeader,
	}).TokenSource(ctx)

	if sourceOpts.diskCacheDir != "" {
		return newDiskCachingTokenSource(
			source, sourceOpts.diskCacheDir, clientID, clientSecret, tokenURL, audience), nil
	}

	return source, nil
}
