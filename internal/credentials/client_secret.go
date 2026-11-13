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

// WithDiskTokenCache enables caching minted access tokens on disk under dir. It is off by default;
// without it the token source behaves exactly as it always has, keeping a token only in memory for
// the lifetime of the process. With it, a token minted by one process is reused by subsequent
// processes until it nears expiry - the difference that matters for a CLI that runs as a fresh
// process per command and would otherwise pay a token round-trip every time.
//
// dir is created with 0700 permissions if it doesn't exist. Each cache file is named by a SHA-256
// hash of the full credential tuple - never a plaintext client ID or secret - and written with 0600
// permissions. The client secret is never written to disk. dir is also required to already be
// privately owned and permissioned if it exists beforehand (e.g. from a previous run) - a
// pre-existing dir that fails that check is treated as unusable and caching is silently skipped,
// rather than trusting whatever another local user could have placed inside it. These permission
// checks are POSIX-only; on Windows, only that dir is actually a directory is verified.
//
// A rotated client secret is covered by the cache key and always misses. A token invalidated some
// other way - its signing key rotated server-side, or explicitly revoked - is not: the cache has no
// way to know that happened, and keeps serving it until its own recorded expiry. A caller that sees
// a 401 it can't otherwise explain should call InvalidateDiskTokenCache for the same credential
// tuple before retrying once.
func WithDiskTokenCache(dir string) ClientSecretOption {
	return func(o *clientSecretOptions) {
		o.diskCacheDir = dir
	}
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
	// tokenURL defaulting/validation.
	switch {
	case tokenURL == "":
		tokenURL = DefaultTokenURL
	case !strings.HasPrefix(tokenURL, "https://"):
		return nil, fmt.Errorf("%w: got %q", ErrInsecureTokenURL, tokenURL)
	}

	if audience == "" {
		audience = DefaultAudience
	}

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
