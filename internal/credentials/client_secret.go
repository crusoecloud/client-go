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

// NewClientSecretTokenSource returns an oauth2.TokenSource for the OAuth2 client_credentials grant,
// authenticated via a shared client secret - the decoratable unit a caller wraps with
// oauth2.NewClient (as auth.NewClientSecretConfig does) to get a request-ready *http.Client. ctx is
// used only for the token-minting HTTP calls this source makes - see oauth2.HTTPClient.
//
// tokenURL defaults to DefaultServiceAccountTokenURL when empty; a non-empty tokenURL that isn't
// https is rejected, rather than sending the client secret over the wire in the clear.
//
// audience defaults to DefaultServiceAccountAudience when empty, and is sent as the token request's
// "audience" form parameter (RFC 8707 resource indicator). Ory Hydra only treats a client's
// registered audience list as an allowlist - it does not stamp it onto every issued token - so a
// request that omits "audience" gets back a token with an empty aud claim, which auth-gateway then
// rejects. Callers targeting a non-prod environment must pass the audience matching that
// environment's auth-gateway config alongside its tokenURL.
func NewClientSecretTokenSource(ctx context.Context, clientID, clientSecret, tokenURL, audience string) (
	oauth2.TokenSource, error,
) {
	// tokenURL defaulting/validation.
	switch {
	case tokenURL == "":
		tokenURL = DefaultServiceAccountTokenURL
	case !strings.HasPrefix(tokenURL, "https://"):
		return nil, fmt.Errorf("%w: got %q", ErrInsecureTokenURL, tokenURL)
	}

	if audience == "" {
		audience = DefaultServiceAccountAudience
	}

	return (&clientcredentials.Config{
		ClientID:       clientID,
		ClientSecret:   clientSecret,
		TokenURL:       tokenURL,
		EndpointParams: url.Values{"audience": {audience}},
		AuthStyle:      oauth2.AuthStyleInHeader,
	}).TokenSource(ctx), nil
}
