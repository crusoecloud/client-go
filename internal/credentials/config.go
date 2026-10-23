// Package credentials resolves Crusoe Cloud credentials from explicit overrides, environment
// variables, and ~/.crusoe/config, mirroring the precedence chain already implemented in
// terraform-provider-crusoe (internal/common/config.go) and customer-cli
// (internal/configs/configs.go), so client-go consumers get the same resolution behavior those
// tools already provide.
package credentials

import (
	"errors"
	"fmt"
	"os"

	"github.com/BurntSushi/toml"
)

const (
	// configFilePath is appended to the resolved config directory to locate the shared Crusoe
	// config file, matching terraform-provider-crusoe and customer-cli.
	configFilePath = "/config"

	// configDirEnvVar lets a caller relocate the config directory away from ~/.crusoe, matching
	// customer-cli's CRUSOE_CONFIG_DIR.
	configDirEnvVar = "CRUSOE_CONFIG_DIR"

	// defaultConfigDir is appended to the user's home directory when neither opts.ConfigPath nor
	// CRUSOE_CONFIG_DIR is set.
	defaultConfigDir = "/.crusoe"

	// DefaultServiceAccountTokenURL is the default OAuth2 token endpoint. Exported for auth.go.
	//nolint:gosec // G101: URL constant, not a credential
	DefaultServiceAccountTokenURL = "https://auth.crusoe.ai/oauth2/token"

	// DefaultServiceAccountAudience is the default token audience. Exported for auth.go.
	DefaultServiceAccountAudience = "https://api.crusoe.ai"

	// defaultProfileName is used when no profile is selected by any precedence tier.
	defaultProfileName = "default"
)

// Config is the fully-resolved set of credential fields, after merging the selected profile from
// the config file with any CRUSOE_* environment variables and explicit overrides.
type Config struct {
	ProfileName string

	AccessKeyID string
	SecretKey   string

	// ServiceAccountClientID and ServiceAccountClientSecret authenticate via OAuth2
	// client_credentials, as an alternative to AccessKeyID/SecretKey. See ResolveAuthMethod.
	ServiceAccountClientID     string
	ServiceAccountClientSecret string

	// ServiceAccountTokenURL is the OAuth2 token endpoint for the client_credentials exchange.
	// Defaults to Crusoe's production Hydra endpoint.
	ServiceAccountTokenURL string

	// ServiceAccountAudience is the "audience" requested on the token request. Defaults to
	// prod's audience; must match the target environment's auth-gateway.
	ServiceAccountAudience string

	// OAuthSessionPath is reserved for a future cached human-OAuth-login credential (see
	// Options.OAuthSessionPath). Not yet populated by LoadConfigWithOptions, and not yet an
	// authCandidates entry in ResolveAuthMethod - there is no reader/refresher for it today.
	OAuthSessionPath string
}

// Options carries explicit overrides (highest precedence) plus profile/config-path selection.
// Empty fields are treated as "not specified" and fall through to the next precedence tier.
type Options struct {
	// Profile selects which profile to load from the config file.
	// Precedence: Profile > CRUSOE_PROFILE env > config file "profile" key > "default".
	Profile string

	// ConfigPath overrides the default ~/.crusoe/config path. Empty uses the default. Pass this
	// for processes with no home directory, or that keep their config file elsewhere.
	ConfigPath string

	// AccessKeyID, SecretKey, and the ServiceAccount* fields below are explicit overrides: when
	// set, they take precedence over both environment variables and the config file.
	AccessKeyID                string
	SecretKey                  string
	ServiceAccountClientID     string
	ServiceAccountClientSecret string
	ServiceAccountTokenURL     string
	ServiceAccountAudience     string

	// OAuthSessionPath is a forward-compatibility placeholder for a future cached human-OAuth-login
	// credential (e.g. a "crusoe auth login" flow writing a token to disk, analogous to gcloud's
	// application-default-credentials file). Intentionally not wired into LoadConfigWithOptions or
	// ResolveAuthMethod yet: the cache file's schema (in particular, whether/how a refresh token is
	// represented) and the token endpoint it refreshes against aren't settled. Wiring it in means:
	// resolving this path (explicit > CRUSOE_OAUTH_SESSION_PATH env > a default location, mirroring
	// ConfigPath's own precedence), adding a passive (non-interactive) reader/refresher, and adding
	// one authCandidates entry whose complete check is "a valid or refreshable session exists at
	// this path" - never anything that opens a browser or blocks on user input; that belongs only
	// in the CLI's own "auth login" command, not in this SDK.
	OAuthSessionPath string
}

// LoadConfigWithOptions resolves a Config in this order (later wins):
//  1. Hardcoded defaults (service-account token URL/audience only; credentials start empty).
//  2. The selected profile's fields from ~/.crusoe/config (or opts.ConfigPath).
//  3. CRUSOE_* environment variables.
//  4. opts' explicit fields.
//
// Profile selection itself follows: opts.Profile > CRUSOE_PROFILE env > config file's top-level
// "profile" key > "default".
//
// The returned Config is always populated, even on error: a non-nil error only means the config
// file couldn't be located or read, and callers should treat it as advisory, not fatal -
// resolution continues using environment variables and explicit options alone.
func LoadConfigWithOptions(opts *Options) (*Config, error) {
	cfg := &Config{
		ServiceAccountTokenURL: DefaultServiceAccountTokenURL,
		ServiceAccountAudience: DefaultServiceAccountAudience,
	}

	rawData, advisoryErr := loadRawConfig(opts)

	profileName := resolveProfileName(rawData, opts)
	cfg.ProfileName = profileName

	profileConfig, _ := loadProfile(rawData, profileName)
	if profileConfig == nil {
		profileConfig = &Config{}
	}

	envConfig := envConfigFromEnviron()
	optsConfig := optsConfigFromOptions(opts)

	// Identity fields come from exactly one tier, picked by pickIdentityTier, so a complete pair
	// never combines field-by-field with a pair from another tier.
	applyIdentity(cfg, pickIdentityTier(identityTierOrder(opts, optsConfig, envConfig, profileConfig)...))

	// Ancillary fields merge independently of identity, lowest precedence to highest.
	mergeAncillary(cfg, profileConfig)
	mergeAncillary(cfg, envConfig)
	mergeAncillary(cfg, optsConfig)

	return cfg, advisoryErr
}

// loadRawConfig reads and decodes the TOML config file. A missing home directory or config file
// is non-fatal: it returns an empty map with an advisory error, since env vars and explicit
// options alone are still a valid way to configure credentials.
func loadRawConfig(opts *Options) (map[string]interface{}, error) {
	configPath := resolveConfigPath(opts)
	if configPath == "" {
		homeDir, err := os.UserHomeDir()
		if err != nil {
			return map[string]interface{}{}, fmt.Errorf("failed to find home dir: %w", err)
		}

		configPath = homeDir + defaultConfigDir + configFilePath
	}

	var rawData map[string]interface{}
	if _, err := toml.DecodeFile(configPath, &rawData); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return map[string]interface{}{}, nil
		}

		return map[string]interface{}{}, fmt.Errorf("error reading config file at %s: %w", configPath, err)
	}

	return rawData, nil
}

// envConfigFromEnviron reads every CRUSOE_* credential env var into a Config.
func envConfigFromEnviron() *Config {
	return &Config{
		AccessKeyID:                os.Getenv("CRUSOE_ACCESS_KEY_ID"),
		SecretKey:                  os.Getenv("CRUSOE_SECRET_KEY"),
		ServiceAccountClientID:     os.Getenv("CRUSOE_SERVICE_ACCOUNT_CLIENT_ID"),
		ServiceAccountClientSecret: os.Getenv("CRUSOE_SERVICE_ACCOUNT_CLIENT_SECRET"),
		ServiceAccountTokenURL:     os.Getenv("CRUSOE_SERVICE_ACCOUNT_TOKEN_URL"),
		ServiceAccountAudience:     os.Getenv("CRUSOE_SERVICE_ACCOUNT_AUDIENCE"),
	}
}

// optsConfigFromOptions copies opts' explicit credential fields into a Config.
func optsConfigFromOptions(opts *Options) *Config {
	return &Config{
		AccessKeyID:                opts.AccessKeyID,
		SecretKey:                  opts.SecretKey,
		ServiceAccountClientID:     opts.ServiceAccountClientID,
		ServiceAccountClientSecret: opts.ServiceAccountClientSecret,
		ServiceAccountTokenURL:     opts.ServiceAccountTokenURL,
		ServiceAccountAudience:     opts.ServiceAccountAudience,
	}
}

// identityTierOrder returns the identity tiers in precedence order: opts > env > profile, except
// when opts.Profile explicitly names a profile. In that case profile is tried before env, so an
// explicitly selected identity can't be overridden by unrelated env vars set elsewhere in the
// same process.
func identityTierOrder(opts *Options, optsConfig, envConfig, profileConfig *Config) []*Config {
	if opts.Profile != "" {
		return []*Config{optsConfig, profileConfig, envConfig}
	}

	return []*Config{optsConfig, envConfig, profileConfig}
}

// resolveConfigPath returns the config file path to read, or "" if the caller should fall back to
// the home-directory default. Precedence: opts.ConfigPath > CRUSOE_CONFIG_DIR env > default.
func resolveConfigPath(opts *Options) string {
	if opts.ConfigPath != "" {
		return opts.ConfigPath
	}

	if dir := os.Getenv(configDirEnvVar); dir != "" {
		return dir + configFilePath
	}

	return ""
}

// resolveProfileName applies the profile-selection precedence: opts.Profile > CRUSOE_PROFILE env
// > config file's top-level "profile" key > "default".
func resolveProfileName(rawData map[string]interface{}, opts *Options) string {
	profileName := defaultProfileName

	if topLevelProfile, ok := rawData["profile"].(string); ok && topLevelProfile != "" {
		profileName = topLevelProfile
	}
	if envProfile := os.Getenv("CRUSOE_PROFILE"); envProfile != "" {
		profileName = envProfile
	}
	if opts.Profile != "" {
		profileName = opts.Profile
	}

	return profileName
}

// loadProfile extracts the named profile table from the decoded TOML data, if present.
func loadProfile(rawData map[string]interface{}, profileName string) (*Config, bool) {
	val, ok := rawData[profileName]
	if !ok {
		return nil, false
	}

	valMap, ok := val.(map[string]interface{})
	if !ok {
		return nil, false
	}

	profileConfig := &Config{}
	if v, ok := valMap["access_key_id"].(string); ok {
		profileConfig.AccessKeyID = v
	}
	if v, ok := valMap["secret_key"].(string); ok {
		profileConfig.SecretKey = v
	}
	if v, ok := valMap["service_account_client_id"].(string); ok {
		profileConfig.ServiceAccountClientID = v
	}
	if v, ok := valMap["service_account_client_secret"].(string); ok {
		profileConfig.ServiceAccountClientSecret = v
	}
	if v, ok := valMap["service_account_token_url"].(string); ok {
		profileConfig.ServiceAccountTokenURL = v
	}
	if v, ok := valMap["service_account_audience"].(string); ok {
		profileConfig.ServiceAccountAudience = v
	}

	return profileConfig, true
}

// isCompleteIdentity reports whether cfg has a complete API-key pair or service-account pair,
// reusing the same per-method checks ResolveAuthMethod's authCandidates table uses.
func isCompleteIdentity(cfg *Config) bool {
	return isCompleteAPIKey(cfg) || isCompleteServiceAccount(cfg)
}

// pickIdentityTier returns the first tier, in the given highest-to-lowest precedence order, that
// carries a complete credential pair, used as-is.
//
// If no tier is complete, falls back to merging identity fields across all tiers, lowest to
// highest, so ResolveAuthMethod still reports a precise incomplete-credential error.
func pickIdentityTier(tiers ...*Config) *Config {
	for _, tier := range tiers {
		if isCompleteIdentity(tier) {
			return tier
		}
	}

	merged := &Config{}
	for i := len(tiers) - 1; i >= 0; i-- {
		mergeIdentity(merged, tiers[i])
	}

	return merged
}

// mergeIdentity overwrites cfg's identity fields with override's non-empty ones. Used only by
// pickIdentityTier's no-complete-tier fallback.
func mergeIdentity(cfg, override *Config) {
	if override.AccessKeyID != "" {
		cfg.AccessKeyID = override.AccessKeyID
	}
	if override.SecretKey != "" {
		cfg.SecretKey = override.SecretKey
	}
	if override.ServiceAccountClientID != "" {
		cfg.ServiceAccountClientID = override.ServiceAccountClientID
	}
	if override.ServiceAccountClientSecret != "" {
		cfg.ServiceAccountClientSecret = override.ServiceAccountClientSecret
	}
}

// applyIdentity copies source's identity fields onto cfg unconditionally.
func applyIdentity(cfg, source *Config) {
	cfg.AccessKeyID = source.AccessKeyID
	cfg.SecretKey = source.SecretKey
	cfg.ServiceAccountClientID = source.ServiceAccountClientID
	cfg.ServiceAccountClientSecret = source.ServiceAccountClientSecret
}

// mergeAncillary overwrites cfg's non-identity fields (ServiceAccountTokenURL/Audience) with
// override's non-empty ones.
func mergeAncillary(cfg, override *Config) {
	if override.ServiceAccountTokenURL != "" {
		cfg.ServiceAccountTokenURL = override.ServiceAccountTokenURL
	}
	if override.ServiceAccountAudience != "" {
		cfg.ServiceAccountAudience = override.ServiceAccountAudience
	}
}
