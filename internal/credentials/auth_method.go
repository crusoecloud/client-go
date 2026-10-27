package credentials

import (
	"errors"
	"os"
)

// AuthMethod identifies which credential pair should be used to authenticate the Crusoe API client.
type AuthMethod int

const (
	// AuthMethodUnknown is the zero value, returned alongside an error when credentials could not
	// be resolved to a single authentication method.
	AuthMethodUnknown AuthMethod = iota
	// AuthMethodAPIKey authenticates via the legacy HMAC AccessKeyID/SecretKey pair.
	AuthMethodAPIKey
	// AuthMethodClientSecret authenticates via the OAuth2 client_credentials grant using a shared
	// client secret (ClientSecretCredentials).
	AuthMethodClientSecret
)

var (
	// ErrMissingCredentials is returned when neither credential pair is configured at all.
	ErrMissingCredentials = errors.New("no Crusoe credentials configured")

	// ErrIncompleteAPIKeyCredentials is returned when exactly one of AccessKeyID/SecretKey is set.
	ErrIncompleteAPIKeyCredentials = errors.New("access key ID and secret key must both be set")

	// ErrIncompleteClientSecretCredentials is returned when exactly one of
	// ClientSecretCredentials.ClientID/ClientSecret is set.
	ErrIncompleteClientSecretCredentials = errors.New(
		"client ID and client secret must both be set")

	// ErrConflictingCredentials is returned when more than one credential pair is fully configured
	// simultaneously. Resolution refuses to silently pick one, since that could authenticate as
	// the wrong identity without the caller noticing.
	ErrConflictingCredentials = errors.New(
		"multiple credential pairs are fully configured; configure only one authentication method")

	// ErrMismatchedClientSecretEnvironment is returned when exactly one of
	// ClientSecretCredentials.TokenURL/Audience is overridden from its default. The two default to
	// prod values independently, so overriding only one silently keeps the other pointed at prod,
	// minting a token with the wrong audience for that token endpoint.
	ErrMismatchedClientSecretEnvironment = errors.New(
		"token URL and audience must both be set together when overriding either from its default")

	// ErrProfileNotFound is returned when an explicitly requested profile (via Options.Profile or
	// CRUSOE_PROFILE) doesn't exist in the config file. See LoadConfigWithOptions.
	ErrProfileNotFound = errors.New("profile not found in config file")

	// ErrUnsupportedAuthMethod is returned by a caller that constructs a client per AuthMethod
	// (e.g. auth.NewDefaultConfig) when ResolveAuthMethod returns a method it has no constructor
	// for. Should not occur in practice - every AuthMethod in authCandidates should have a
	// matching case at the call site - but failing loudly here is safer than silently falling
	// through to ErrMissingCredentials for credentials that were actually found.
	ErrUnsupportedAuthMethod = errors.New("unsupported authentication method")
)

// authCandidate bundles everything LoadConfigWithOptions and ResolveAuthMethod need to know about
// one credential type, so adding a new type only means adding a new entry here - every function
// that loops over authCandidates (ResolveAuthMethod, isCompleteCredential, hasAnyCredentialField,
// envConfigFromEnviron, optsConfigFromOptions, loadProfile, applyCredential, mergeAncillary) picks
// it up automatically.
type authCandidate struct {
	method        AuthMethod
	complete      func(cfg *Config) bool
	partial       func(cfg *Config) bool
	incompleteErr error
	validate      func(cfg *Config) error

	// fromEnv populates cfg's fields for this credential type from CRUSOE_* environment variables.
	fromEnv func(cfg *Config)
	// fromOptions copies this credential type's explicit-override fields from opts into cfg.
	fromOptions func(cfg *Config, opts *Options)
	// fromProfile populates cfg's fields for this credential type from a decoded TOML profile table.
	fromProfile func(cfg *Config, valMap map[string]interface{})
	// apply copies this credential type's identity fields (not ancillary ones - see mergeAncillary)
	// from source onto cfg.
	apply func(cfg, source *Config)
	// mergeAncillary overwrites cfg's non-identity fields for this type with override's non-empty
	// ones. nil for types with no ancillary fields (e.g. APIKey).
	mergeAncillary func(cfg, override *Config)
}

//nolint:gochecknoglobals // static method registry, never mutated
var authCandidates = []authCandidate{
	{
		method:        AuthMethodAPIKey,
		complete:      isCompleteAPIKey,
		partial:       isPartialAPIKey,
		incompleteErr: ErrIncompleteAPIKeyCredentials,
		fromEnv: func(cfg *Config) {
			cfg.APIKey.AccessKeyID = os.Getenv("CRUSOE_ACCESS_KEY_ID")
			cfg.APIKey.SecretKey = os.Getenv("CRUSOE_SECRET_KEY")
		},
		fromOptions: func(cfg *Config, opts *Options) {
			cfg.APIKey = opts.APIKey
		},
		fromProfile: func(cfg *Config, valMap map[string]interface{}) {
			if v, ok := valMap["access_key_id"].(string); ok {
				cfg.APIKey.AccessKeyID = v
			}
			if v, ok := valMap["secret_key"].(string); ok {
				cfg.APIKey.SecretKey = v
			}
		},
		apply: func(cfg, source *Config) {
			cfg.APIKey = source.APIKey
		},
	},
	{
		method:        AuthMethodClientSecret,
		complete:      isCompleteClientSecret,
		partial:       isPartialClientSecret,
		incompleteErr: ErrIncompleteClientSecretCredentials,
		validate:      validateClientSecretEnvironment,
		fromEnv: func(cfg *Config) {
			cfg.ClientSecret.ClientID = os.Getenv("CRUSOE_CLIENT_ID")
			cfg.ClientSecret.ClientSecret = os.Getenv("CRUSOE_CLIENT_SECRET")
			cfg.ClientSecret.TokenURL = os.Getenv("CRUSOE_TOKEN_URL")
			cfg.ClientSecret.Audience = os.Getenv("CRUSOE_AUDIENCE")
		},
		fromOptions: func(cfg *Config, opts *Options) {
			cfg.ClientSecret = opts.ClientSecret
		},
		fromProfile: func(cfg *Config, valMap map[string]interface{}) {
			if v, ok := valMap["client_id"].(string); ok {
				cfg.ClientSecret.ClientID = v
			}
			if v, ok := valMap["client_secret"].(string); ok {
				cfg.ClientSecret.ClientSecret = v
			}
			if v, ok := valMap["token_url"].(string); ok {
				cfg.ClientSecret.TokenURL = v
			}
			if v, ok := valMap["audience"].(string); ok {
				cfg.ClientSecret.Audience = v
			}
		},
		apply: func(cfg, source *Config) {
			cfg.ClientSecret.ClientID = source.ClientSecret.ClientID
			cfg.ClientSecret.ClientSecret = source.ClientSecret.ClientSecret
		},
		mergeAncillary: func(cfg, override *Config) {
			if override.ClientSecret.TokenURL != "" {
				cfg.ClientSecret.TokenURL = override.ClientSecret.TokenURL
			}
			if override.ClientSecret.Audience != "" {
				cfg.ClientSecret.Audience = override.ClientSecret.Audience
			}
		},
	},
}

func isCompleteAPIKey(cfg *Config) bool {
	return cfg.APIKey.AccessKeyID != "" && cfg.APIKey.SecretKey != ""
}

func isPartialAPIKey(cfg *Config) bool {
	hasAny := cfg.APIKey.AccessKeyID != "" || cfg.APIKey.SecretKey != ""

	return hasAny && !isCompleteAPIKey(cfg)
}

func isCompleteClientSecret(cfg *Config) bool {
	return cfg.ClientSecret.ClientID != "" && cfg.ClientSecret.ClientSecret != ""
}

func isPartialClientSecret(cfg *Config) bool {
	hasAny := cfg.ClientSecret.ClientID != "" || cfg.ClientSecret.ClientSecret != ""

	return hasAny && !isCompleteClientSecret(cfg)
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

// validateClientSecretEnvironment ensures TokenURL and Audience are overridden together, not
// independently - see ErrMismatchedClientSecretEnvironment. An empty field means "not
// configured" rather than "overridden to empty", so it's treated as the default, not a mismatch.
func validateClientSecretEnvironment(cfg *Config) error {
	hasCustomTokenURL := cfg.ClientSecret.TokenURL != "" && cfg.ClientSecret.TokenURL != DefaultTokenURL
	hasCustomAudience := cfg.ClientSecret.Audience != "" && cfg.ClientSecret.Audience != DefaultAudience

	if hasCustomTokenURL != hasCustomAudience {
		return ErrMismatchedClientSecretEnvironment
	}

	return nil
}
