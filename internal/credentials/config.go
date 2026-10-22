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
	// configFilePath is appended to the user's home directory to locate the shared Crusoe config
	// file, matching terraform-provider-crusoe and customer-cli.
	configFilePath = "/.crusoe/config"

	// defaultServiceAccountTokenURL mirrors the default already used by auth.NewServiceAccountConfig.
	//nolint:gosec // G101: URL constant, not a credential
	defaultServiceAccountTokenURL = "https://auth.crusoe.ai/oauth2/token"

	// defaultServiceAccountAudience mirrors the default already used by auth.NewServiceAccountConfig.
	defaultServiceAccountAudience = "https://api.crusoe.ai"

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
}

// Options carries explicit overrides (highest precedence) plus profile/config-path selection.
// Empty fields are treated as "not specified" and fall through to the next precedence tier.
type Options struct {
	// Profile selects which profile to load from the config file.
	// Precedence: Profile > CRUSOE_PROFILE env > config file "profile" key > "default".
	Profile string

	// ConfigPath overrides the default ~/.crusoe/config path. Empty uses the default. Pass this
	// when the process has no mounted home directory (e.g. a Kubernetes pod reading credentials
	// from a mounted Secret at a fixed path).
	ConfigPath string

	// AccessKeyID, SecretKey, and the ServiceAccount* fields below are explicit overrides: when
	// set, they take precedence over both environment variables and the config file.
	AccessKeyID                string
	SecretKey                  string
	ServiceAccountClientID     string
	ServiceAccountClientSecret string
	ServiceAccountTokenURL     string
	ServiceAccountAudience     string
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
		ServiceAccountTokenURL: defaultServiceAccountTokenURL,
		ServiceAccountAudience: defaultServiceAccountAudience,
	}

	// A home-dir lookup failure falls through like a missing config file - env vars and explicit
	// options alone are a valid way to configure credentials. advisoryErr is still returned so the
	// caller can surface it, but resolution proceeds.
	var advisoryErr error
	configPath := opts.ConfigPath
	if configPath == "" {
		homeDir, err := os.UserHomeDir()
		if err != nil {
			advisoryErr = fmt.Errorf("failed to find home dir: %w", err)
		} else {
			configPath = homeDir + configFilePath
		}
	}

	var rawData map[string]interface{}
	if advisoryErr != nil {
		rawData = make(map[string]interface{})
	} else if _, err := toml.DecodeFile(configPath, &rawData); err != nil {
		// Missing/invalid config file is non-fatal - credentials can come from env vars or
		// explicit options alone.
		if !errors.Is(err, os.ErrNotExist) {
			advisoryErr = fmt.Errorf("error reading config file at %s: %w", configPath, err)
		}
		rawData = make(map[string]interface{})
	}

	profileName := resolveProfileName(rawData, opts)
	cfg.ProfileName = profileName

	if profileConfig, ok := loadProfile(rawData, profileName); ok {
		mergeNonEmpty(cfg, profileConfig)
	}

	mergeNonEmpty(cfg, &Config{
		AccessKeyID:                os.Getenv("CRUSOE_ACCESS_KEY_ID"),
		SecretKey:                  os.Getenv("CRUSOE_SECRET_KEY"),
		ServiceAccountClientID:     os.Getenv("CRUSOE_SERVICE_ACCOUNT_CLIENT_ID"),
		ServiceAccountClientSecret: os.Getenv("CRUSOE_SERVICE_ACCOUNT_CLIENT_SECRET"),
		ServiceAccountTokenURL:     os.Getenv("CRUSOE_SERVICE_ACCOUNT_TOKEN_URL"),
		ServiceAccountAudience:     os.Getenv("CRUSOE_SERVICE_ACCOUNT_AUDIENCE"),
	})

	mergeNonEmpty(cfg, &Config{
		AccessKeyID:                opts.AccessKeyID,
		SecretKey:                  opts.SecretKey,
		ServiceAccountClientID:     opts.ServiceAccountClientID,
		ServiceAccountClientSecret: opts.ServiceAccountClientSecret,
		ServiceAccountTokenURL:     opts.ServiceAccountTokenURL,
		ServiceAccountAudience:     opts.ServiceAccountAudience,
	})

	return cfg, advisoryErr
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

// mergeNonEmpty overwrites each non-empty field of override onto cfg, leaving existing fields
// untouched where override's corresponding field is empty ("not specified").
func mergeNonEmpty(cfg, override *Config) {
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
	if override.ServiceAccountTokenURL != "" {
		cfg.ServiceAccountTokenURL = override.ServiceAccountTokenURL
	}
	if override.ServiceAccountAudience != "" {
		cfg.ServiceAccountAudience = override.ServiceAccountAudience
	}
}
