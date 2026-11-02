package auth

import "github.com/crusoecloud/client-go/internal/credentials"

// Reexported so callers can branch on these with errors.Is without importing the internal
// credentials package, which Go itself blocks from outside this module anyway. Each alias is the
// same underlying error value, so errors.Is(err, auth.ErrMissingCredentials) works identically to
// comparing against the internal sentinel directly.
var (
	// ErrMissingCredentials is returned when no credential type is configured at all.
	ErrMissingCredentials = credentials.ErrMissingCredentials

	// ErrIncompleteAPIKeyCredentials is returned when exactly one of the access key ID / secret
	// key pair is set.
	ErrIncompleteAPIKeyCredentials = credentials.ErrIncompleteAPIKeyCredentials

	// ErrIncompleteClientSecretCredentials is returned when exactly one of the client ID / client
	// secret pair is set.
	ErrIncompleteClientSecretCredentials = credentials.ErrIncompleteClientSecretCredentials

	// ErrConflictingCredentials is returned when more than one credential type is fully
	// configured at once.
	ErrConflictingCredentials = credentials.ErrConflictingCredentials

	// ErrMismatchedClientSecretEnvironment is returned when exactly one of the token URL /
	// audience pair is overridden from its default.
	ErrMismatchedClientSecretEnvironment = credentials.ErrMismatchedClientSecretEnvironment

	// ErrProfileNotFound is returned when an explicitly requested profile doesn't exist in the
	// config file.
	ErrProfileNotFound = credentials.ErrProfileNotFound

	// ErrProfileWithExplicitCredentials is returned when WithProfile is combined with an explicit
	// credential override (WithAPIKey or WithClientSecret).
	ErrProfileWithExplicitCredentials = credentials.ErrProfileWithExplicitCredentials

	// ErrUnsupportedAuthMethod indicates an internal gap between the credential types this
	// package can resolve and the ones it can construct a client for. Should not occur.
	ErrUnsupportedAuthMethod = credentials.ErrUnsupportedAuthMethod

	// ErrInsecureTokenURL is returned when a non-empty token URL passed to WithClientSecret, or
	// resolved from the config file or CRUSOE_TOKEN_URL, isn't https.
	ErrInsecureTokenURL = credentials.ErrInsecureTokenURL
)
