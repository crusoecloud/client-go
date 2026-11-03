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
	"path/filepath"

	"github.com/BurntSushi/toml"
)

const (
	// configFileName is the shared Crusoe config file's name within its resolved directory,
	// matching terraform-provider-crusoe and customer-cli.
	configFileName = "config"

	// configDirEnvVar lets a caller relocate the config directory away from ~/.crusoe, matching
	// customer-cli's CRUSOE_CONFIG_DIR.
	configDirEnvVar = "CRUSOE_CONFIG_DIR"

	// profileEnvVar selects a profile by name, overriding the config file's own default.
	profileEnvVar = "CRUSOE_PROFILE"

	// defaultConfigDir is appended to the user's home directory when neither opts.ConfigPath nor
	// CRUSOE_CONFIG_DIR is set.
	defaultConfigDir = ".crusoe"

	// DefaultTokenURL is the default OAuth2 token endpoint. Exported so callers (and tests)
	// outside this package can reference it instead of duplicating the literal.
	//nolint:gosec // G101: URL constant, not a credential
	DefaultTokenURL = "https://auth.crusoe.ai/oauth2/token"

	// DefaultAudience is the default token audience. Exported so callers (and tests) outside
	// this package can reference it instead of duplicating the literal.
	DefaultAudience = "https://api.crusoe.ai"

	// defaultProfileName is used when no profile is selected by any precedence tier.
	defaultProfileName = "default"
)

// Config is the fully-resolved set of credential fields, after merging the selected profile from
// the config file with any CRUSOE_* environment variables and explicit overrides.
type Config struct {
	ProfileName string

	APIKey       APIKeyCredentials
	ClientSecret ClientSecretCredentials

	// CredentialSource names the winning precedence tier (e.g. "explicit options", "profile").
	// CredentialSourceComplete reports whether that tier was a full pair. Both are empty/false
	// when no tier had any field set. Informational only - not used by resolution itself.
	CredentialSource         string
	CredentialSourceComplete bool
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

	// APIKey and ClientSecret are explicit overrides: when a field is set, it takes precedence over
	// both environment variables and the config file.
	APIKey       APIKeyCredentials
	ClientSecret ClientSecretCredentials
}

// LoadConfigWithOptions resolves a Config in this order (later wins):
//  1. Hardcoded defaults (ClientSecret's TokenURL/Audience only; credentials start empty).
//  2. The selected profile's fields from ~/.crusoe/config (or opts.ConfigPath).
//  3. CRUSOE_* environment variables.
//  4. opts' explicit fields.
//
// Profile selection itself follows: opts.Profile > CRUSOE_PROFILE env > config file's top-level
// "profile" key > "default". opts.Profile cannot be combined with opts.APIKey or
// opts.ClientSecret - both select an identity, so combining them returns
// ErrProfileWithExplicitCredentials.
//
// The returned Config is always populated, even on error: a non-nil error from a missing or
// unreadable config file is advisory, not fatal - resolution continues using environment
// variables and explicit options alone. The one exception is an explicitly requested profile
// (via Options.Profile, CRUSOE_PROFILE, or the config file's own top-level "profile" key) that
// doesn't exist: that is always a hard error, since silently falling through could authenticate as
// the wrong identity without the caller noticing. An implicit "default" profile that doesn't exist
// is not an error, since many callers configure credentials entirely via env vars and never
// create a config file at all.
func LoadConfigWithOptions(opts *Options) (*Config, error) {
	cfg := &Config{
		ClientSecret: ClientSecretCredentials{
			TokenURL: DefaultTokenURL,
			Audience: DefaultAudience,
		},
	}

	optsConfig := optsConfigFromOptions(opts)
	if opts.Profile != "" && hasAnyCredentialField(optsConfig) {
		return cfg, ErrProfileWithExplicitCredentials
	}

	rawData, advisoryErr := loadRawConfig(opts)

	profileName := resolveProfileName(rawData, opts)
	cfg.ProfileName = profileName

	profileConfig, found := loadProfile(rawData, profileName)
	if !found {
		if profileWasExplicitlyRequested(rawData, opts) {
			if advisoryErr != nil {
				return cfg, fmt.Errorf("%w: %q (config file error: %v)", ErrProfileNotFound, profileName, advisoryErr)
			}

			return cfg, fmt.Errorf("%w: %q", ErrProfileNotFound, profileName)
		}

		profileConfig = &Config{}
	}

	envConfig := envConfigFromEnviron()

	// The winning tier supplies both the credential pair and its own ancillary fields
	// (TokenURL/Audience) together - never mixed with a different tier's, so one identity's
	// secret is never silently paired with a different tier's token endpoint or audience.
	winner, outcome := pickCredentialTier(credentialTierOrder(opts, optsConfig, envConfig, profileConfig)...)
	applyCredential(cfg, winner)
	mergeAncillary(cfg, winner)
	cfg.CredentialSource = outcome.tier
	cfg.CredentialSourceComplete = outcome.complete

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

		configPath = filepath.Join(homeDir, defaultConfigDir, configFileName)
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

// envConfigFromEnviron reads every CRUSOE_* credential env var into a Config, via the same
// authCandidates table ResolveAuthMethod uses - so a new method added there doesn't require a
// matching edit here.
func envConfigFromEnviron() *Config {
	cfg := &Config{}
	for _, c := range authCandidates {
		c.fromEnv(cfg)
	}

	return cfg
}

// optsConfigFromOptions copies opts' explicit credential fields into a Config, via the same
// authCandidates table ResolveAuthMethod uses - so a new method added there doesn't require a
// matching edit here.
func optsConfigFromOptions(opts *Options) *Config {
	cfg := &Config{}
	for _, c := range authCandidates {
		c.fromOptions(cfg, opts)
	}

	return cfg
}

// namedTier pairs a precedence-ordered Config with the human-readable name pickCredentialTier
// reports back as Config.CredentialSource when that tier wins.
type namedTier struct {
	name   string
	config *Config
}

// credentialTierOrder returns the credential tiers in precedence order: opts > env > profile.
// When opts.Profile names a profile, env is excluded entirely - an incomplete named profile must
// report its own incompleteness, not fall through to unrelated env vars.
func credentialTierOrder(opts *Options, optsConfig, envConfig, profileConfig *Config) []namedTier {
	if opts.Profile != "" {
		// optsConfig is guaranteed empty here: LoadConfigWithOptions already returns
		// ErrProfileWithExplicitCredentials before reaching this call if opts.Profile and any
		// explicit credential field are both set, so there is no "explicit options" tier left to
		// consider.
		return []namedTier{
			{"profile", profileConfig},
		}
	}

	return []namedTier{
		{"explicit options", optsConfig},
		{"environment variables", envConfig},
		{"profile", profileConfig},
	}
}

// resolveConfigPath returns the config file path to read, or "" if the caller should fall back to
// the home-directory default. Precedence: opts.ConfigPath > CRUSOE_CONFIG_DIR env > default.
func resolveConfigPath(opts *Options) string {
	if opts.ConfigPath != "" {
		return opts.ConfigPath
	}

	if dir := os.Getenv(configDirEnvVar); dir != "" {
		return filepath.Join(dir, configFileName)
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
	if envProfile := os.Getenv(profileEnvVar); envProfile != "" {
		profileName = envProfile
	}
	if opts.Profile != "" {
		profileName = opts.Profile
	}

	return profileName
}

// profileWasExplicitlyRequested reports whether the caller named a specific profile - via
// opts.Profile, CRUSOE_PROFILE, or the config file's own top-level "profile" key - as opposed to
// falling back to the implicit "default". See LoadConfigWithOptions for why this determines
// whether a missing profile is a hard error.
func profileWasExplicitlyRequested(rawData map[string]interface{}, opts *Options) bool {
	if opts.Profile != "" || os.Getenv(profileEnvVar) != "" {
		return true
	}

	topLevelProfile, ok := rawData["profile"].(string)

	return ok && topLevelProfile != ""
}

// loadProfile extracts the named profile table from the decoded TOML data, if present, via the
// same authCandidates table ResolveAuthMethod uses - so a new method added there doesn't require a
// matching edit here.
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
	for _, c := range authCandidates {
		c.fromProfile(profileConfig, valMap)
	}

	return profileConfig, true
}

// isCompleteCredential reports whether cfg has a complete credential pair for any known method,
// via the same authCandidates table ResolveAuthMethod uses - so a new method added there doesn't
// require a matching edit here.
func isCompleteCredential(cfg *Config) bool {
	for _, c := range authCandidates {
		if c.complete(cfg) {
			return true
		}
	}

	return false
}

// tierOutcome records which precedence tier pickCredentialTier chose and whether it was complete,
// for Config.CredentialSource/CredentialSourceComplete.
type tierOutcome struct {
	tier     string
	complete bool
}

// pickCredentialTier returns the first tier, in the given highest-to-lowest precedence order, that
// carries a complete credential pair, used as-is.
//
// If no tier is complete, returns the first tier (still highest-to-lowest) that has any credential
// field set at all, again used as-is - never combined with another tier's fields. Stitching
// together e.g. an AccessKeyID from one tier and a SecretKey from a different tier could silently
// assemble a "complete" pair out of two unrelated tiers (the exact cross-tier contamination this
// whole tier-based resolution exists to prevent), so ResolveAuthMethod's incomplete-credential
// error must reflect one real tier's actual state, not a composite of several.
func pickCredentialTier(tiers ...namedTier) (*Config, tierOutcome) {
	for _, t := range tiers {
		if isCompleteCredential(t.config) {
			return t.config, tierOutcome{tier: t.name, complete: true}
		}
	}

	for _, t := range tiers {
		if hasAnyCredentialField(t.config) {
			return t.config, tierOutcome{tier: t.name, complete: false}
		}
	}

	return &Config{}, tierOutcome{}
}

// hasAnyCredentialField reports whether cfg has any credential field set, complete or not, via the
// same authCandidates table isCompleteCredential uses - so a new method added there doesn't
// require a matching edit here. Used only by pickCredentialTier's no-complete-tier fallback.
func hasAnyCredentialField(cfg *Config) bool {
	for _, c := range authCandidates {
		if c.complete(cfg) || (c.partial != nil && c.partial(cfg)) {
			return true
		}
	}

	return false
}

// applyCredential copies source's identity fields onto cfg unconditionally, via the same
// authCandidates table ResolveAuthMethod uses - so a new method added there doesn't require a
// matching edit here. ClientSecret.TokenURL/Audience are deliberately left untouched here even
// though they live on the same struct - callers apply those via mergeAncillary instead, which
// falls back to a default rather than copying blindly.
func applyCredential(cfg, source *Config) {
	for _, c := range authCandidates {
		c.apply(cfg, source)
	}
}

// mergeAncillary overwrites cfg's non-identity fields (e.g. ClientSecret.TokenURL/Audience) with
// override's non-empty ones, via the same authCandidates table ResolveAuthMethod uses - so a new
// method added there doesn't require a matching edit here, unless it has no ancillary fields at
// all (e.g. APIKey), in which case it simply has no mergeAncillary to run.
func mergeAncillary(cfg, override *Config) {
	for _, c := range authCandidates {
		if c.mergeAncillary != nil {
			c.mergeAncillary(cfg, override)
		}
	}
}
