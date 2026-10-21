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

// ResolveAuthMethod inspects a Config and determines which authentication method (if any) should
// be used to construct the Crusoe API client.
//
// Precedence / validation rules:
//   - Both credential pairs fully set               -> ErrConflictingCredentials (ambiguous; refuse to guess).
//   - Exactly one of AccessKeyID/SecretKey set       -> ErrIncompleteAPIKeyCredentials.
//   - Exactly one of the service account fields set  -> ErrIncompleteServiceAccountCredentials.
//   - Service account pair fully set, but only one of TokenURL/Audience is overridden from its
//     default -> ErrMismatchedServiceAccountEnvironment.
//   - Only the service account pair fully set        -> AuthMethodServiceAccount.
//   - Only the API key pair fully set                -> AuthMethodAPIKey.
//   - Neither pair set at all                        -> ErrMissingCredentials.
//
// Partial-credential checks intentionally take priority over "neither set", so a likely typo
// (e.g. only SecretKey set) is reported precisely instead of being reported as "nothing configured".
//
//nolint:cyclop // exhaustive precedence/conflict matrix, ported 1:1 from terraform-provider-crusoe
func ResolveAuthMethod(cfg *Config) (AuthMethod, error) {
	hasAccessKeyID := cfg.AccessKeyID != ""
	hasSecretKey := cfg.SecretKey != ""
	hasClientID := cfg.ServiceAccountClientID != ""
	hasClientSecret := cfg.ServiceAccountClientSecret != ""

	hasCompleteAPIKey := hasAccessKeyID && hasSecretKey
	hasCompleteServiceAccount := hasClientID && hasClientSecret
	hasAnyAPIKey := hasAccessKeyID || hasSecretKey
	hasAnyServiceAccount := hasClientID || hasClientSecret

	switch {
	case hasCompleteAPIKey && hasCompleteServiceAccount:
		return AuthMethodUnknown, ErrConflictingCredentials
	case hasAnyAPIKey && !hasCompleteAPIKey:
		return AuthMethodUnknown, ErrIncompleteAPIKeyCredentials
	case hasAnyServiceAccount && !hasCompleteServiceAccount:
		return AuthMethodUnknown, ErrIncompleteServiceAccountCredentials
	case hasCompleteServiceAccount:
		if err := validateServiceAccountEnvironment(cfg); err != nil {
			return AuthMethodUnknown, err
		}

		return AuthMethodServiceAccount, nil
	case hasCompleteAPIKey:
		return AuthMethodAPIKey, nil
	default:
		return AuthMethodUnknown, ErrMissingCredentials
	}
}

// validateServiceAccountEnvironment ensures TokenURL and Audience are overridden together, not
// independently - see ErrMismatchedServiceAccountEnvironment. An empty field means "not
// configured" rather than "overridden to empty", so it's treated as the default, not a mismatch.
func validateServiceAccountEnvironment(cfg *Config) error {
	hasCustomTokenURL := cfg.ServiceAccountTokenURL != "" && cfg.ServiceAccountTokenURL != defaultServiceAccountTokenURL
	hasCustomAudience := cfg.ServiceAccountAudience != "" && cfg.ServiceAccountAudience != defaultServiceAccountAudience

	if hasCustomTokenURL != hasCustomAudience {
		return ErrMismatchedServiceAccountEnvironment
	}

	return nil
}
