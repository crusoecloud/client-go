package credentials

import "errors"

// AuthMethod identifies which credential pair should be used to authenticate the Crusoe API client.
type AuthMethod int

const (
	// AuthMethodUnknown is the zero value, returned alongside an error when credentials could not
	// be resolved to a single authentication method.
	AuthMethodUnknown AuthMethod = iota
	// AuthMethodAPIKey authenticates via the legacy HMAC AccessKeyID/SecretKey pair.
	AuthMethodAPIKey
	// AuthMethodServiceAccount authenticates via OAuth2 client_credentials using
	// ServiceAccountClientID/ServiceAccountClientSecret.
	AuthMethodServiceAccount
)

var (
	// ErrMissingCredentials is returned when neither credential pair is configured at all.
	ErrMissingCredentials = errors.New("no Crusoe credentials configured")

	// ErrIncompleteAPIKeyCredentials is returned when exactly one of AccessKeyID/SecretKey is set.
	ErrIncompleteAPIKeyCredentials = errors.New("access key ID and secret key must both be set")

	// ErrIncompleteServiceAccountCredentials is returned when exactly one of
	// ServiceAccountClientID/ServiceAccountClientSecret is set.
	ErrIncompleteServiceAccountCredentials = errors.New(
		"service account client ID and client secret must both be set")

	// ErrConflictingCredentials is returned when both a complete API key pair and a complete
	// service account pair are configured simultaneously. Resolution refuses to silently pick
	// one, since that could authenticate as the wrong identity without the caller noticing.
	ErrConflictingCredentials = errors.New(
		"both API key and service account credentials are configured; configure only one authentication method")

	// ErrMismatchedServiceAccountEnvironment is returned when exactly one of
	// ServiceAccountTokenURL/ServiceAccountAudience is overridden from its default. The two
	// default to prod values independently, so overriding only one silently keeps the other
	// pointed at prod, minting a token with the wrong audience for that token endpoint.
	ErrMismatchedServiceAccountEnvironment = errors.New(
		"service account token URL and audience must both be set together when overriding either from its default")
)

type authCandidate struct {
	method        AuthMethod
	complete      func(cfg *Config) bool
	partial       func(cfg *Config) bool
	incompleteErr error
	validate      func(cfg *Config) error
}

//nolint:gochecknoglobals // static method registry, never mutated
var authCandidates = []authCandidate{
	{
		method:        AuthMethodAPIKey,
		complete:      isCompleteAPIKey,
		partial:       isPartialAPIKey,
		incompleteErr: ErrIncompleteAPIKeyCredentials,
	},
	{
		method:        AuthMethodServiceAccount,
		complete:      isCompleteServiceAccount,
		partial:       isPartialServiceAccount,
		incompleteErr: ErrIncompleteServiceAccountCredentials,
		validate:      validateServiceAccountEnvironment,
	},
}

func isCompleteAPIKey(cfg *Config) bool { return cfg.AccessKeyID != "" && cfg.SecretKey != "" }

func isPartialAPIKey(cfg *Config) bool {
	hasAny := cfg.AccessKeyID != "" || cfg.SecretKey != ""

	return hasAny && !isCompleteAPIKey(cfg)
}

func isCompleteServiceAccount(cfg *Config) bool {
	return cfg.ServiceAccountClientID != "" && cfg.ServiceAccountClientSecret != ""
}

func isPartialServiceAccount(cfg *Config) bool {
	hasAny := cfg.ServiceAccountClientID != "" || cfg.ServiceAccountClientSecret != ""

	return hasAny && !isCompleteServiceAccount(cfg)
}

// ResolveAuthMethod inspects a Config and determines which authentication method (if any) should
// be used to construct the Crusoe API client.
//
// Precedence / validation rules:
//   - More than one method fully configured   -> ErrConflictingCredentials (ambiguous; refuse to guess).
//   - Any method partially configured          -> that method's own incomplete-credential error.
//   - Exactly one method fully configured      -> that method, after running its own validate check.
//   - No method configured at all              -> ErrMissingCredentials.
//
// Partial-credential checks intentionally take priority over "nothing configured", so a likely
// typo (e.g. only SecretKey set) is reported precisely instead of being reported as missing - and
// take priority even when a different method is already complete (e.g. a complete API key pair
// plus a stray, partial service-account field is still reported as the incomplete service account,
// not silently accepted as the API key).
func ResolveAuthMethod(cfg *Config) (AuthMethod, error) {
	complete := make([]authCandidate, 0, len(authCandidates))
	for _, c := range authCandidates {
		if c.complete(cfg) {
			complete = append(complete, c)
		}
	}

	if len(complete) > 1 {
		return AuthMethodUnknown, ErrConflictingCredentials
	}

	for _, c := range authCandidates {
		if c.partial != nil && c.partial(cfg) {
			return AuthMethodUnknown, c.incompleteErr
		}
	}

	if len(complete) == 1 {
		c := complete[0]
		if c.validate != nil {
			if err := c.validate(cfg); err != nil {
				return AuthMethodUnknown, err
			}
		}

		return c.method, nil
	}

	return AuthMethodUnknown, ErrMissingCredentials
}

// validateServiceAccountEnvironment ensures TokenURL and Audience are overridden together, not
// independently - see ErrMismatchedServiceAccountEnvironment. An empty field means "not
// configured" rather than "overridden to empty", so it's treated as the default, not a mismatch.
func validateServiceAccountEnvironment(cfg *Config) error {
	hasCustomTokenURL := cfg.ServiceAccountTokenURL != "" && cfg.ServiceAccountTokenURL != DefaultServiceAccountTokenURL
	hasCustomAudience := cfg.ServiceAccountAudience != "" && cfg.ServiceAccountAudience != DefaultServiceAccountAudience

	if hasCustomTokenURL != hasCustomAudience {
		return ErrMismatchedServiceAccountEnvironment
	}

	return nil
}
