package credentials

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// crusoeEnvVars lists every CRUSOE_* variable LoadConfigWithOptions reads directly.
var crusoeEnvVars = []string{
	"CRUSOE_PROFILE",
	"CRUSOE_ACCESS_KEY_ID",
	"CRUSOE_SECRET_KEY",
	"CRUSOE_CLIENT_ID",
	"CRUSOE_CLIENT_SECRET",
	"CRUSOE_TOKEN_URL",
	"CRUSOE_AUDIENCE",
}

func clearCrusoeEnvVars(t *testing.T) {
	t.Helper()

	for _, name := range crusoeEnvVars {
		t.Setenv(name, "")
		os.Unsetenv(name) //nolint:errcheck,usetesting
	}
}

// writeTempConfig writes content to a temp file and returns its path.
func writeTempConfig(t *testing.T, content string) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "config")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("failed to write temp config: %v", err)
	}

	return path
}

func TestProfilePrecedence_FullChain(t *testing.T) {
	clearCrusoeEnvVars(t)

	configContent := `
profile = "from-file"

[from-file]
access_key_id = "file-key"
secret_key = "file-secret"

[from-env]
access_key_id = "env-profile-key"
secret_key = "env-profile-secret"

[from-opts]
access_key_id = "opts-profile-key"
secret_key = "opts-profile-secret"
`
	configPath := writeTempConfig(t, configContent)

	t.Run("falls back to top-level profile key in config file", func(t *testing.T) {
		cfg, err := LoadConfigWithOptions(&Options{ConfigPath: configPath})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if cfg.ProfileName != "from-file" || cfg.APIKey.AccessKeyID != "file-key" {
			t.Fatalf("expected profile from-file/file-key, got %+v", cfg)
		}
	})

	t.Run("CRUSOE_PROFILE env overrides config file profile key", func(t *testing.T) {
		os.Setenv("CRUSOE_PROFILE", "from-env") //nolint:usetesting // explicit var for the test's own env-precedence assertion
		defer os.Unsetenv("CRUSOE_PROFILE")     //nolint:errcheck,usetesting // cleanup after subtest

		cfg, err := LoadConfigWithOptions(&Options{ConfigPath: configPath})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if cfg.ProfileName != "from-env" || cfg.APIKey.AccessKeyID != "env-profile-key" {
			t.Fatalf("expected profile from-env/env-profile-key, got %+v", cfg)
		}
	})

	t.Run("opts.Profile overrides both env and config file", func(t *testing.T) {
		os.Setenv("CRUSOE_PROFILE", "from-env") //nolint:usetesting // explicit var for the test's own env-precedence assertion
		defer os.Unsetenv("CRUSOE_PROFILE")     //nolint:errcheck,usetesting // cleanup after subtest

		cfg, err := LoadConfigWithOptions(&Options{ConfigPath: configPath, Profile: "from-opts"})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if cfg.ProfileName != "from-opts" || cfg.APIKey.AccessKeyID != "opts-profile-key" {
			t.Fatalf("expected profile from-opts/opts-profile-key, got %+v", cfg)
		}
	})

	t.Run("defaults to \"default\" when nothing selects a profile", func(t *testing.T) {
		cfg, err := LoadConfigWithOptions(&Options{ConfigPath: writeTempConfig(t, "")})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if cfg.ProfileName != "default" {
			t.Fatalf("expected profile \"default\", got %q", cfg.ProfileName)
		}
	})
}

func TestCredentialEnvOverridesProfile(t *testing.T) {
	clearCrusoeEnvVars(t)

	configPath := writeTempConfig(t, `
[default]
access_key_id = "file-key"
secret_key = "file-secret"
`)

	t.Run("env vars override profile entirely", func(t *testing.T) {
		os.Setenv("CRUSOE_ACCESS_KEY_ID", "env-key") //nolint:usetesting // explicit var for the test's own env-precedence assertion
		os.Setenv("CRUSOE_SECRET_KEY", "env-secret") //nolint:usetesting // explicit var for the test's own env-precedence assertion
		defer os.Unsetenv("CRUSOE_ACCESS_KEY_ID")    //nolint:errcheck,usetesting // cleanup after subtest
		defer os.Unsetenv("CRUSOE_SECRET_KEY")       //nolint:errcheck,usetesting // cleanup after subtest

		cfg, err := LoadConfigWithOptions(&Options{ConfigPath: configPath})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if cfg.APIKey.AccessKeyID != "env-key" || cfg.APIKey.SecretKey != "env-secret" {
			t.Fatalf("expected env credentials to win, got %+v", cfg)
		}
	})

	t.Run("profile alone is used when no env override is set", func(t *testing.T) {
		cfg, err := LoadConfigWithOptions(&Options{ConfigPath: configPath})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if cfg.APIKey.AccessKeyID != "file-key" || cfg.APIKey.SecretKey != "file-secret" {
			t.Fatalf("expected profile credentials, got %+v", cfg)
		}
	})

	t.Run("incomplete env override doesn't combine with profile - profile wins whole", func(t *testing.T) {
		os.Setenv("CRUSOE_ACCESS_KEY_ID", "env-key") //nolint:usetesting // explicit var for the test's own env-precedence assertion
		defer os.Unsetenv("CRUSOE_ACCESS_KEY_ID")    //nolint:errcheck,usetesting // cleanup after subtest

		cfg, err := LoadConfigWithOptions(&Options{ConfigPath: configPath})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if cfg.APIKey.AccessKeyID != "file-key" || cfg.APIKey.SecretKey != "file-secret" {
			t.Fatalf("expected the profile's complete pair to win whole, got %+v", cfg)
		}
	})
}

func TestExplicitOptionsOverrideEverything(t *testing.T) {
	clearCrusoeEnvVars(t)

	os.Setenv("CRUSOE_ACCESS_KEY_ID", "env-key") //nolint:usetesting // explicit var for the test's own precedence assertion
	os.Setenv("CRUSOE_SECRET_KEY", "env-secret") //nolint:usetesting // explicit var for the test's own precedence assertion
	defer os.Unsetenv("CRUSOE_ACCESS_KEY_ID")    //nolint:errcheck,usetesting // cleanup
	defer os.Unsetenv("CRUSOE_SECRET_KEY")       //nolint:errcheck,usetesting // cleanup

	configPath := writeTempConfig(t, `
[default]
access_key_id = "file-key"
secret_key = "file-secret"
`)

	cfg, err := LoadConfigWithOptions(&Options{
		ConfigPath: configPath,
		APIKey:     APIKeyCredentials{AccessKeyID: "explicit-key", SecretKey: "explicit-secret"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.APIKey.AccessKeyID != "explicit-key" || cfg.APIKey.SecretKey != "explicit-secret" {
		t.Fatalf("expected explicit options to win over env and file, got %+v", cfg)
	}
}

func TestMissingConfigFile(t *testing.T) {
	clearCrusoeEnvVars(t)
	os.Setenv("CRUSOE_ACCESS_KEY_ID", "env-key") //nolint:usetesting // explicit var for this test's assertion
	os.Setenv("CRUSOE_SECRET_KEY", "env-secret") //nolint:usetesting // explicit var for this test's assertion
	defer os.Unsetenv("CRUSOE_ACCESS_KEY_ID")    //nolint:errcheck,usetesting // cleanup
	defer os.Unsetenv("CRUSOE_SECRET_KEY")       //nolint:errcheck,usetesting // cleanup

	nonexistentPath := filepath.Join(t.TempDir(), "does-not-exist")

	cfg, err := LoadConfigWithOptions(&Options{ConfigPath: nonexistentPath})
	if err != nil {
		t.Fatalf("expected a missing config file to be non-fatal, got error: %v", err)
	}
	if cfg.APIKey.AccessKeyID != "env-key" || cfg.APIKey.SecretKey != "env-secret" {
		t.Fatalf("expected env credentials to still resolve, got %+v", cfg)
	}
}

func TestConfigDirEnvVar(t *testing.T) {
	clearCrusoeEnvVars(t)

	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "config"), []byte(`
[default]
access_key_id = "dir-env-key"
secret_key = "dir-env-secret"
`), 0o600); err != nil {
		t.Fatalf("failed to write temp config: %v", err)
	}

	t.Run("CRUSOE_CONFIG_DIR is used when opts.ConfigPath is empty", func(t *testing.T) {
		os.Setenv("CRUSOE_CONFIG_DIR", dir)    //nolint:usetesting // explicit var for this test's assertion
		defer os.Unsetenv("CRUSOE_CONFIG_DIR") //nolint:errcheck,usetesting // cleanup

		cfg, err := LoadConfigWithOptions(&Options{})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if cfg.APIKey.AccessKeyID != "dir-env-key" || cfg.APIKey.SecretKey != "dir-env-secret" {
			t.Fatalf("expected credentials from CRUSOE_CONFIG_DIR's config file, got %+v", cfg)
		}
	})

	t.Run("opts.ConfigPath overrides CRUSOE_CONFIG_DIR", func(t *testing.T) {
		os.Setenv("CRUSOE_CONFIG_DIR", dir)    //nolint:usetesting // explicit var for this test's assertion
		defer os.Unsetenv("CRUSOE_CONFIG_DIR") //nolint:errcheck,usetesting // cleanup

		explicitPath := writeTempConfig(t, `
[default]
access_key_id = "explicit-path-key"
secret_key = "explicit-path-secret"
`)

		cfg, err := LoadConfigWithOptions(&Options{ConfigPath: explicitPath})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if cfg.APIKey.AccessKeyID != "explicit-path-key" || cfg.APIKey.SecretKey != "explicit-path-secret" {
			t.Fatalf("expected opts.ConfigPath to win over CRUSOE_CONFIG_DIR, got %+v", cfg)
		}
	})
}

func TestInvalidConfigFile(t *testing.T) {
	clearCrusoeEnvVars(t)
	os.Setenv("CRUSOE_ACCESS_KEY_ID", "env-key") //nolint:usetesting // explicit var for this test's assertion
	os.Setenv("CRUSOE_SECRET_KEY", "env-secret") //nolint:usetesting // explicit var for this test's assertion
	defer os.Unsetenv("CRUSOE_ACCESS_KEY_ID")    //nolint:errcheck,usetesting // cleanup
	defer os.Unsetenv("CRUSOE_SECRET_KEY")       //nolint:errcheck,usetesting // cleanup

	configPath := writeTempConfig(t, "this is not valid toml {{{{")

	cfg, err := LoadConfigWithOptions(&Options{ConfigPath: configPath})
	if err == nil {
		t.Fatal("expected an advisory error for malformed TOML")
	}
	if cfg.APIKey.AccessKeyID != "env-key" || cfg.APIKey.SecretKey != "env-secret" {
		t.Fatalf("expected env vars to still populate despite the malformed file, got %+v", cfg)
	}
}

func TestProfileNotFoundInConfig_ExplicitlyRequested(t *testing.T) {
	clearCrusoeEnvVars(t)

	configPath := writeTempConfig(t, `
[default]
access_key_id = "file-key"
secret_key = "file-secret"
`)

	_, err := LoadConfigWithOptions(&Options{ConfigPath: configPath, Profile: "does-not-exist"})
	if err == nil {
		t.Fatal("expected an error for an explicitly requested profile absent from the file")
	}
}

func TestProfileNotFoundInConfig_ExplicitlyRequestedViaEnv(t *testing.T) {
	clearCrusoeEnvVars(t)

	configPath := writeTempConfig(t, `
[default]
access_key_id = "file-key"
secret_key = "file-secret"
`)

	t.Setenv("CRUSOE_PROFILE", "does-not-exist")

	_, err := LoadConfigWithOptions(&Options{ConfigPath: configPath})
	if err == nil {
		t.Fatal("expected an error for a CRUSOE_PROFILE-requested profile absent from the file")
	}
}

func TestProfileNotFoundInConfig_MalformedFileWithExplicitProfile(t *testing.T) {
	clearCrusoeEnvVars(t)

	configPath := writeTempConfig(t, "this is not valid toml {{{{")

	_, err := LoadConfigWithOptions(&Options{ConfigPath: configPath, Profile: "does-not-exist"})
	if err == nil {
		t.Fatal("expected an error for an explicitly requested profile when the config file itself is malformed")
	}
	if !strings.Contains(err.Error(), "config file error") {
		t.Fatalf("expected the malformed-file error to be surfaced alongside the profile error, got: %v", err)
	}
}

func TestProfileNotFoundInConfig_ImplicitDefault(t *testing.T) {
	clearCrusoeEnvVars(t)

	configPath := writeTempConfig(t, `
[other]
access_key_id = "file-key"
secret_key = "file-secret"
`)

	cfg, err := LoadConfigWithOptions(&Options{ConfigPath: configPath})
	if err != nil {
		t.Fatalf("expected no error when the implicit default profile is absent, got: %v", err)
	}
	if cfg.ProfileName != "default" {
		t.Fatalf("expected ProfileName %q, got %q", "default", cfg.ProfileName)
	}
	if cfg.APIKey.AccessKeyID != "" || cfg.APIKey.SecretKey != "" {
		t.Fatalf("expected empty credentials for an absent implicit default profile, got %+v", cfg)
	}
}

func TestMultipleProfiles(t *testing.T) {
	clearCrusoeEnvVars(t)

	configPath := writeTempConfig(t, `
[production]
access_key_id = "prod-key"
secret_key = "prod-secret"

[staging]
access_key_id = "staging-key"
secret_key = "staging-secret"
`)

	prodCfg, err := LoadConfigWithOptions(&Options{ConfigPath: configPath, Profile: "production"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if prodCfg.APIKey.AccessKeyID != "prod-key" || prodCfg.APIKey.SecretKey != "prod-secret" {
		t.Fatalf("expected production profile credentials, got %+v", prodCfg)
	}

	stagingCfg, err := LoadConfigWithOptions(&Options{ConfigPath: configPath, Profile: "staging"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if stagingCfg.APIKey.AccessKeyID != "staging-key" || stagingCfg.APIKey.SecretKey != "staging-secret" {
		t.Fatalf("expected staging profile credentials, got %+v", stagingCfg)
	}
}

func TestServiceAccountConfig_FromProfile(t *testing.T) {
	clearCrusoeEnvVars(t)

	configPath := writeTempConfig(t, `
[default]
client_id = "profile-client-id"
client_secret = "profile-client-secret"
`)

	cfg, err := LoadConfigWithOptions(&Options{ConfigPath: configPath})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.ClientSecret.ClientID != "profile-client-id" || cfg.ClientSecret.ClientSecret != "profile-client-secret" {
		t.Fatalf("expected profile service account credentials, got %+v", cfg)
	}
	if cfg.ClientSecret.TokenURL != DefaultTokenURL {
		t.Fatalf("expected default token URL to be preserved, got %q", cfg.ClientSecret.TokenURL)
	}
	if cfg.ClientSecret.Audience != DefaultAudience {
		t.Fatalf("expected default audience to be preserved, got %q", cfg.ClientSecret.Audience)
	}
}

func TestServiceAccountConfig_EnvOverridesProfile(t *testing.T) {
	clearCrusoeEnvVars(t)

	configPath := writeTempConfig(t, `
[default]
client_id = "profile-client-id"
client_secret = "profile-client-secret"
`)

	os.Setenv("CRUSOE_CLIENT_ID", "env-client-id")                         //nolint:usetesting // explicit var for this test's assertion
	os.Setenv("CRUSOE_CLIENT_SECRET", "env-client-secret")                 //nolint:usetesting // explicit var for this test's assertion
	os.Setenv("CRUSOE_TOKEN_URL", "https://auth.example.com/oauth2/token") //nolint:usetesting // explicit var for this test's assertion
	os.Setenv("CRUSOE_AUDIENCE", "https://api.example.com")                //nolint:usetesting // explicit var for this test's assertion
	defer os.Unsetenv("CRUSOE_CLIENT_ID")                                  //nolint:errcheck,usetesting // cleanup
	defer os.Unsetenv("CRUSOE_CLIENT_SECRET")                              //nolint:errcheck,usetesting // cleanup
	defer os.Unsetenv("CRUSOE_TOKEN_URL")                                  //nolint:errcheck,usetesting // cleanup
	defer os.Unsetenv("CRUSOE_AUDIENCE")                                   //nolint:errcheck,usetesting // cleanup

	cfg, err := LoadConfigWithOptions(&Options{ConfigPath: configPath})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.ClientSecret.ClientID != "env-client-id" || cfg.ClientSecret.ClientSecret != "env-client-secret" {
		t.Fatalf("expected env service account credentials, got %+v", cfg)
	}
	if cfg.ClientSecret.TokenURL != "https://auth.example.com/oauth2/token" {
		t.Fatalf("expected env token URL, got %q", cfg.ClientSecret.TokenURL)
	}
	if cfg.ClientSecret.Audience != "https://api.example.com" {
		t.Fatalf("expected env audience, got %q", cfg.ClientSecret.Audience)
	}
}

func TestCrossTypeCredentialsDoNotCombine(t *testing.T) {
	clearCrusoeEnvVars(t)

	configPath := writeTempConfig(t, `
[default]
client_id = "profile-client-id"
client_secret = "profile-client-secret"
`)

	os.Setenv("CRUSOE_ACCESS_KEY_ID", "stray-env-key") //nolint:usetesting // explicit var for this test's assertion
	defer os.Unsetenv("CRUSOE_ACCESS_KEY_ID")          //nolint:errcheck,usetesting // cleanup

	cfg, err := LoadConfigWithOptions(&Options{ConfigPath: configPath})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.ClientSecret.ClientID != "profile-client-id" || cfg.ClientSecret.ClientSecret != "profile-client-secret" {
		t.Fatalf("expected the profile's complete service account pair, got %+v", cfg)
	}
	if cfg.APIKey.AccessKeyID != "" || cfg.APIKey.SecretKey != "" {
		t.Fatalf("expected the stray env access key to be ignored entirely, got %+v", cfg)
	}

	method, err := ResolveAuthMethod(cfg)
	if err != nil {
		t.Fatalf("expected a clean resolution, got error: %v", err)
	}
	if method != AuthMethodClientSecret {
		t.Fatalf("expected AuthMethodClientSecret, got %v", method)
	}
}

func TestProfileIsolatedFromProcessWideEnvVars(t *testing.T) {
	clearCrusoeEnvVars(t)

	configPath := writeTempConfig(t, `
[projectA]
client_id = "projectA-client-id"
client_secret = "projectA-client-secret"
`)

	os.Setenv("CRUSOE_ACCESS_KEY_ID", "process-wide-key") //nolint:usetesting // simulates another credential's env vars
	os.Setenv("CRUSOE_SECRET_KEY", "process-wide-secret") //nolint:usetesting // simulates another credential's env vars
	defer os.Unsetenv("CRUSOE_ACCESS_KEY_ID")             //nolint:errcheck,usetesting // cleanup
	defer os.Unsetenv("CRUSOE_SECRET_KEY")                //nolint:errcheck,usetesting // cleanup

	cfg, err := LoadConfigWithOptions(&Options{ConfigPath: configPath, Profile: "projectA"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.ClientSecret.ClientID != "projectA-client-id" || cfg.ClientSecret.ClientSecret != "projectA-client-secret" {
		t.Fatalf("expected projectA's service account pair, got %+v", cfg)
	}
	if cfg.APIKey.AccessKeyID != "" || cfg.APIKey.SecretKey != "" {
		t.Fatalf("expected process-wide env vars to be fully excluded from this profile's credential pair, got %+v", cfg)
	}

	method, err := ResolveAuthMethod(cfg)
	if err != nil {
		t.Fatalf("expected WithProfile to isolate this credential pair cleanly, got error: %v", err)
	}
	if method != AuthMethodClientSecret {
		t.Fatalf("expected AuthMethodClientSecret, got %v", method)
	}
}

// Guards against stitching fields from two different tiers into a false-complete pair.
func TestIncompleteTiersDoNotAssembleIntoACompletePair(t *testing.T) {
	clearCrusoeEnvVars(t)
	t.Setenv("CRUSOE_SECRET_KEY", "env-secret-key")

	_, err := LoadConfigWithOptions(&Options{
		ConfigPath: filepath.Join(t.TempDir(), "does-not-exist"),
		APIKey:     APIKeyCredentials{AccessKeyID: "opts-access-key"}, // incomplete alone: no SecretKey
	})
	if !errors.Is(err, ErrIncompleteAPIKeyCredentials) {
		t.Fatalf("expected ErrIncompleteAPIKeyCredentials instead of stitching opts' AccessKeyID with env's SecretKey, got: %v", err)
	}
}

func TestProfileWithExplicitAPIKeyIsError(t *testing.T) {
	clearCrusoeEnvVars(t)

	_, err := LoadConfigWithOptions(&Options{
		Profile: "myprofile",
		APIKey:  APIKeyCredentials{AccessKeyID: "k", SecretKey: "s"},
	})
	if !errors.Is(err, ErrProfileWithExplicitCredentials) {
		t.Fatalf("expected ErrProfileWithExplicitCredentials, got: %v", err)
	}
}

func TestProfileWithExplicitClientSecretIsError(t *testing.T) {
	clearCrusoeEnvVars(t)

	_, err := LoadConfigWithOptions(&Options{
		Profile:      "myprofile",
		ClientSecret: ClientSecretCredentials{ClientID: "id", ClientSecret: "secret"},
	})
	if !errors.Is(err, ErrProfileWithExplicitCredentials) {
		t.Fatalf("expected ErrProfileWithExplicitCredentials, got: %v", err)
	}
}

func TestIncompleteExplicitProfileDoesNotFallThroughToEnv(t *testing.T) {
	clearCrusoeEnvVars(t)

	configPath := writeTempConfig(t, `
[incomplete]
client_id = "profile-client-id"
`)
	t.Setenv("CRUSOE_ACCESS_KEY_ID", "env-key")
	t.Setenv("CRUSOE_SECRET_KEY", "env-secret")

	cfg, err := LoadConfigWithOptions(&Options{ConfigPath: configPath, Profile: "incomplete"})
	if err != nil {
		t.Fatalf("unexpected error loading config: %v", err)
	}

	_, err = ResolveAuthMethod(cfg)
	if !errors.Is(err, ErrIncompleteClientSecretCredentials) {
		t.Fatalf("expected the profile's own incompleteness, not env credentials, got: %v (cfg %+v)", err, cfg)
	}
}

func TestProfileNotFoundInConfig_ExplicitlyRequestedViaTopLevelKey(t *testing.T) {
	clearCrusoeEnvVars(t)

	configPath := writeTempConfig(t, `profile = "does-not-exist"`)

	_, err := LoadConfigWithOptions(&Options{ConfigPath: configPath})
	if !errors.Is(err, ErrProfileNotFound) {
		t.Fatalf("expected ErrProfileNotFound for a top-level profile key naming a missing table, got: %v", err)
	}
}

func TestCredentialSource(t *testing.T) {
	clearCrusoeEnvVars(t)

	configPath := writeTempConfig(t, `
[default]
access_key_id = "file-key"
secret_key = "file-secret"
`)

	t.Run("explicit options", func(t *testing.T) {
		cfg, err := LoadConfigWithOptions(&Options{
			ConfigPath: configPath,
			APIKey:     APIKeyCredentials{AccessKeyID: "k", SecretKey: "s"},
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if cfg.CredentialSource != "explicit options" || !cfg.CredentialSourceComplete {
			t.Fatalf("expected complete explicit options, got source=%q complete=%v", cfg.CredentialSource, cfg.CredentialSourceComplete)
		}
	})

	t.Run("environment variables", func(t *testing.T) {
		t.Setenv("CRUSOE_ACCESS_KEY_ID", "env-key")
		t.Setenv("CRUSOE_SECRET_KEY", "env-secret")

		cfg, err := LoadConfigWithOptions(&Options{ConfigPath: configPath})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if cfg.CredentialSource != "environment variables" || !cfg.CredentialSourceComplete {
			t.Fatalf("expected complete environment variables, got source=%q complete=%v", cfg.CredentialSource, cfg.CredentialSourceComplete)
		}
	})

	t.Run("profile", func(t *testing.T) {
		cfg, err := LoadConfigWithOptions(&Options{ConfigPath: configPath})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if cfg.CredentialSource != "profile" || !cfg.CredentialSourceComplete {
			t.Fatalf("expected complete profile, got source=%q complete=%v", cfg.CredentialSource, cfg.CredentialSourceComplete)
		}
	})

	t.Run("named profile via WithProfile", func(t *testing.T) {
		cfg, err := LoadConfigWithOptions(&Options{ConfigPath: configPath, Profile: "default"})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if cfg.CredentialSource != "profile" || !cfg.CredentialSourceComplete {
			t.Fatalf("expected complete profile, got source=%q complete=%v", cfg.CredentialSource, cfg.CredentialSourceComplete)
		}
	})

	t.Run("incomplete fallback", func(t *testing.T) {
		t.Setenv("CRUSOE_ACCESS_KEY_ID", "only-key-no-secret")

		cfg, err := LoadConfigWithOptions(&Options{ConfigPath: writeTempConfig(t, "")})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if cfg.CredentialSource != "environment variables" || cfg.CredentialSourceComplete {
			t.Fatalf("expected incomplete environment variables, got source=%q complete=%v", cfg.CredentialSource, cfg.CredentialSourceComplete)
		}
	})

	t.Run("nothing configured", func(t *testing.T) {
		cfg, err := LoadConfigWithOptions(&Options{ConfigPath: writeTempConfig(t, "")})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if cfg.CredentialSource != "" || cfg.CredentialSourceComplete {
			t.Fatalf("expected no source, got source=%q complete=%v", cfg.CredentialSource, cfg.CredentialSourceComplete)
		}
	})
}

// Guards against TokenURL/Audience leaking in from a tier other than the one that won.
func TestAncillaryFieldsStayWithTheWinningCredentialTier(t *testing.T) {
	clearCrusoeEnvVars(t)

	configPath := writeTempConfig(t, `
[projectA]
client_id = "projectA-client-id"
client_secret = "projectA-client-secret"
`)

	t.Setenv("CRUSOE_TOKEN_URL", "https://auth.staging.example.com/oauth2/token")
	t.Setenv("CRUSOE_AUDIENCE", "https://api.staging.example.com")

	cfg, err := LoadConfigWithOptions(&Options{ConfigPath: configPath, Profile: "projectA"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.ClientSecret.TokenURL != DefaultTokenURL {
		t.Fatalf("expected projectA's winning tier to fall back to the default token URL, not a stray env override, got %+v",
			cfg.ClientSecret)
	}
	if cfg.ClientSecret.Audience != DefaultAudience {
		t.Fatalf("expected projectA's winning tier to fall back to the default audience, not a stray env override, got %+v",
			cfg.ClientSecret)
	}
}

func TestAncillaryFieldsFromExplicitOptionsSurviveEnvSuppliedIdentity(t *testing.T) {
	clearCrusoeEnvVars(t)

	t.Setenv("CRUSOE_CLIENT_ID", "env-client-id")
	t.Setenv("CRUSOE_CLIENT_SECRET", "env-client-secret")

	cfg, err := LoadConfigWithOptions(&Options{
		ConfigPath: filepath.Join(t.TempDir(), "does-not-exist"),
		ClientSecret: ClientSecretCredentials{
			TokenURL: "https://auth.staging.example.com/oauth2/token",
			Audience: "https://api.staging.example.com",
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.ClientSecret.ClientID != "env-client-id" || cfg.ClientSecret.ClientSecret != "env-client-secret" {
		t.Fatalf("expected env identity to still win, got %+v", cfg.ClientSecret)
	}
	if cfg.ClientSecret.TokenURL != "https://auth.staging.example.com/oauth2/token" {
		t.Fatalf("expected the explicit options' TokenURL override to survive, got %q", cfg.ClientSecret.TokenURL)
	}
	if cfg.ClientSecret.Audience != "https://api.staging.example.com" {
		t.Fatalf("expected the explicit options' Audience override to survive, got %q", cfg.ClientSecret.Audience)
	}
}

func TestExplicitPartialAPIKeyDoesNotFallThroughToEnv(t *testing.T) {
	clearCrusoeEnvVars(t)

	t.Setenv("CRUSOE_ACCESS_KEY_ID", "env-key")
	t.Setenv("CRUSOE_SECRET_KEY", "env-secret")

	cfg, err := LoadConfigWithOptions(&Options{
		ConfigPath: filepath.Join(t.TempDir(), "does-not-exist"),
		APIKey:     APIKeyCredentials{AccessKeyID: "explicit-key"},
	})
	if !errors.Is(err, ErrIncompleteAPIKeyCredentials) {
		t.Fatalf("expected ErrIncompleteAPIKeyCredentials for an explicit partial override, got err=%v cfg=%+v", err, cfg)
	}
}

func TestExplicitPartialClientSecretDoesNotFallThroughToEnv(t *testing.T) {
	clearCrusoeEnvVars(t)

	t.Setenv("CRUSOE_CLIENT_ID", "env-client-id")
	t.Setenv("CRUSOE_CLIENT_SECRET", "env-client-secret")

	cfg, err := LoadConfigWithOptions(&Options{
		ConfigPath:   filepath.Join(t.TempDir(), "does-not-exist"),
		ClientSecret: ClientSecretCredentials{ClientID: "explicit-client-id"},
	})
	if !errors.Is(err, ErrIncompleteClientSecretCredentials) {
		t.Fatalf("expected ErrIncompleteClientSecretCredentials for an explicit partial override, got err=%v cfg=%+v", err, cfg)
	}
}

// tierState is one tier's credential signal. Each state sets at most one method's fields - a tier
// carrying both methods at once is covered separately by TestSameTierCredentialConflicts.
type tierState int

const (
	stNone tierState = iota
	stAPIKeyComplete
	stAPIKeyPartialAccessOnly
	stAPIKeyPartialSecretOnly
	stCSComplete
	stCSPartialIDOnly
	stCSPartialSecretOnly
)

var allTierStates = []tierState{
	stNone, stAPIKeyComplete, stAPIKeyPartialAccessOnly, stAPIKeyPartialSecretOnly,
	stCSComplete, stCSPartialIDOnly, stCSPartialSecretOnly,
}

func (s tierState) String() string {
	switch s {
	case stNone:
		return "none"
	case stAPIKeyComplete:
		return "apikey-complete"
	case stAPIKeyPartialAccessOnly:
		return "apikey-partial-access"
	case stAPIKeyPartialSecretOnly:
		return "apikey-partial-secret"
	case stCSComplete:
		return "cs-complete"
	case stCSPartialIDOnly:
		return "cs-partial-id"
	case stCSPartialSecretOnly:
		return "cs-partial-secret"
	default:
		return "unknown"
	}
}

func (s tierState) apiKey(tag string) APIKeyCredentials {
	switch s {
	case stAPIKeyComplete:
		return APIKeyCredentials{AccessKeyID: tag + "-ak", SecretKey: tag + "-sk"}
	case stAPIKeyPartialAccessOnly:
		return APIKeyCredentials{AccessKeyID: tag + "-ak"}
	case stAPIKeyPartialSecretOnly:
		return APIKeyCredentials{SecretKey: tag + "-sk"}
	default:
		return APIKeyCredentials{}
	}
}

func (s tierState) clientSecret(tag string) ClientSecretCredentials {
	switch s {
	case stCSComplete:
		return ClientSecretCredentials{ClientID: tag + "-id", ClientSecret: tag + "-secret"}
	case stCSPartialIDOnly:
		return ClientSecretCredentials{ClientID: tag + "-id"}
	case stCSPartialSecretOnly:
		return ClientSecretCredentials{ClientSecret: tag + "-secret"}
	default:
		return ClientSecretCredentials{}
	}
}

func (s tierState) isAPIKeyPartial() bool {
	return s == stAPIKeyPartialAccessOnly || s == stAPIKeyPartialSecretOnly
}

func (s tierState) isCSPartial() bool {
	return s == stCSPartialIDOnly || s == stCSPartialSecretOnly
}

func (s tierState) isComplete() bool {
	return s == stAPIKeyComplete || s == stCSComplete
}

func (s tierState) isAnySignal() bool {
	return s != stNone
}

func TestExhaustiveIdentityPrecedence(t *testing.T) {
	tiers := []struct {
		name string
		tag  string
	}{
		{"opts", "opts"},
		{"env", "env"},
		{"profile", "profile"},
	}

	total := 0
	for _, optsSt := range allTierStates {
		for _, envSt := range allTierStates {
			for _, profileSt := range allTierStates {
				states := [3]tierState{optsSt, envSt, profileSt}
				name := fmt.Sprintf("opts=%s/env=%s/profile=%s", optsSt, envSt, profileSt)
				t.Run(name, func(t *testing.T) {
					total++
					runIdentityCombination(t, tiers, states)
				})
			}
		}
	}
	t.Logf("ran %d combinations", total)
}

func runIdentityCombination(t *testing.T, tiers []struct {
	name string
	tag  string
}, states [3]tierState,
) {
	t.Helper()
	clearCrusoeEnvVars(t)

	opts := &Options{}
	opts.APIKey = states[0].apiKey("opts")
	opts.ClientSecret = states[0].clientSecret("opts")

	if states[1].apiKey("env").AccessKeyID != "" {
		t.Setenv("CRUSOE_ACCESS_KEY_ID", states[1].apiKey("env").AccessKeyID)
	}
	if states[1].apiKey("env").SecretKey != "" {
		t.Setenv("CRUSOE_SECRET_KEY", states[1].apiKey("env").SecretKey)
	}
	if states[1].clientSecret("env").ClientID != "" {
		t.Setenv("CRUSOE_CLIENT_ID", states[1].clientSecret("env").ClientID)
	}
	if states[1].clientSecret("env").ClientSecret != "" {
		t.Setenv("CRUSOE_CLIENT_SECRET", states[1].clientSecret("env").ClientSecret)
	}

	profileAK := states[2].apiKey("profile")
	profileCS := states[2].clientSecret("profile")
	var toml string
	toml += "[default]\n"
	if profileAK.AccessKeyID != "" {
		toml += fmt.Sprintf("access_key_id = %q\n", profileAK.AccessKeyID)
	}
	if profileAK.SecretKey != "" {
		toml += fmt.Sprintf("secret_key = %q\n", profileAK.SecretKey)
	}
	if profileCS.ClientID != "" {
		toml += fmt.Sprintf("client_id = %q\n", profileCS.ClientID)
	}
	if profileCS.ClientSecret != "" {
		toml += fmt.Sprintf("client_secret = %q\n", profileCS.ClientSecret)
	}
	opts.ConfigPath = writeTempConfig(t, toml)

	cfg, loadErr := LoadConfigWithOptions(opts)

	// Model, step 1: an explicit-options partial signal must fail fast (Fix B), regardless of
	// what env/profile contain.
	if states[0].isAPIKeyPartial() {
		if !errors.Is(loadErr, ErrIncompleteAPIKeyCredentials) {
			t.Fatalf("expected ErrIncompleteAPIKeyCredentials from opts partial APIKey, got: %v (cfg=%+v)", loadErr, cfg)
		}
		return
	}
	if states[0].isCSPartial() {
		if !errors.Is(loadErr, ErrIncompleteClientSecretCredentials) {
			t.Fatalf("expected ErrIncompleteClientSecretCredentials from opts partial ClientSecret, got: %v (cfg=%+v)", loadErr, cfg)
		}
		return
	}
	if loadErr != nil {
		t.Fatalf("unexpected LoadConfigWithOptions error: %v", loadErr)
	}

	// Model, step 2: whole-tier winner - first COMPLETE tier in [opts, env, profile] order; else
	// first tier with ANY signal; else no winner. This mirrors pickCredentialTier's pre-existing,
	// deliberately-tested "never stitch across tiers" semantics (see
	// TestCrossTypeCredentialsDoNotCombine) - only the opts fail-fast behavior above is new.
	winnerIdx := -1
	for i, s := range states {
		if s.isComplete() {
			winnerIdx = i
			break
		}
	}
	if winnerIdx == -1 {
		for i, s := range states {
			if s.isAnySignal() {
				winnerIdx = i
				break
			}
		}
	}

	if winnerIdx == -1 {
		if cfg.APIKey != (APIKeyCredentials{}) || cfg.ClientSecret.ClientID != "" || cfg.ClientSecret.ClientSecret != "" {
			t.Fatalf("expected empty identity fields when no tier has any signal, got %+v / %+v", cfg.APIKey, cfg.ClientSecret)
		}

		method, resolveErr := ResolveAuthMethod(cfg)
		if !errors.Is(resolveErr, ErrMissingCredentials) {
			t.Fatalf("expected ErrMissingCredentials, got method=%v err=%v", method, resolveErr)
		}

		return
	}

	winnerState := states[winnerIdx]
	winnerTag := tiers[winnerIdx].tag

	wantAPIKey := APIKeyCredentials{}
	wantCS := ClientSecretCredentials{}
	if winnerState == stAPIKeyComplete || winnerState.isAPIKeyPartial() {
		wantAPIKey = winnerState.apiKey(winnerTag)
	}
	if winnerState == stCSComplete || winnerState.isCSPartial() {
		wantCS.ClientID = winnerState.clientSecret(winnerTag).ClientID
		wantCS.ClientSecret = winnerState.clientSecret(winnerTag).ClientSecret
	}

	if cfg.APIKey != wantAPIKey {
		t.Fatalf("APIKey mismatch: want %+v, got %+v (winner=%s/%s)", wantAPIKey, cfg.APIKey, tiers[winnerIdx].name, winnerState)
	}
	if cfg.ClientSecret.ClientID != wantCS.ClientID || cfg.ClientSecret.ClientSecret != wantCS.ClientSecret {
		t.Fatalf("ClientSecret identity mismatch: want %+v, got id=%q secret=%q (winner=%s/%s)",
			wantCS, cfg.ClientSecret.ClientID, cfg.ClientSecret.ClientSecret, tiers[winnerIdx].name, winnerState)
	}

	method, resolveErr := ResolveAuthMethod(cfg)

	switch {
	case winnerState == stAPIKeyComplete:
		if resolveErr != nil || method != AuthMethodAPIKey {
			t.Fatalf("expected clean AuthMethodAPIKey, got method=%v err=%v cfg=%+v", method, resolveErr, cfg)
		}
	case winnerState == stCSComplete:
		if resolveErr != nil || method != AuthMethodClientSecret {
			t.Fatalf("expected clean AuthMethodClientSecret, got method=%v err=%v cfg=%+v", method, resolveErr, cfg)
		}
	case winnerState.isAPIKeyPartial():
		if !errors.Is(resolveErr, ErrIncompleteAPIKeyCredentials) {
			t.Fatalf("expected ErrIncompleteAPIKeyCredentials (fallback partial winner), got method=%v err=%v cfg=%+v", method, resolveErr, cfg)
		}
	case winnerState.isCSPartial():
		if !errors.Is(resolveErr, ErrIncompleteClientSecretCredentials) {
			t.Fatalf("expected ErrIncompleteClientSecretCredentials (fallback partial winner), got method=%v err=%v cfg=%+v", method, resolveErr, cfg)
		}
	default:
		t.Fatalf("unreachable winner state %v", winnerState)
	}
}

// ancillaryState describes one tier's TokenURL/Audience signal.
type ancillaryState int

const (
	ancNone ancillaryState = iota
	ancTokenURLOnly
	ancAudienceOnly
	ancBoth
)

var allAncillaryStates = []ancillaryState{ancNone, ancTokenURLOnly, ancAudienceOnly, ancBoth}

func (a ancillaryState) String() string {
	switch a {
	case ancNone:
		return "none"
	case ancTokenURLOnly:
		return "tokenurl-only"
	case ancAudienceOnly:
		return "audience-only"
	case ancBoth:
		return "both"
	default:
		return "unknown"
	}
}

func (a ancillaryState) tokenURL(tag string) string {
	if a == ancTokenURLOnly || a == ancBoth {
		return "https://auth." + tag + ".example.com/oauth2/token"
	}
	return ""
}

func (a ancillaryState) audience(tag string) string {
	if a == ancAudienceOnly || a == ancBoth {
		return "https://api." + tag + ".example.com"
	}
	return ""
}

func TestExhaustiveAncillaryCascade(t *testing.T) {
	identityTierNames := []string{"opts", "env", "profile"}

	for _, identityTier := range identityTierNames {
		for _, optsAnc := range allAncillaryStates {
			for _, envAnc := range allAncillaryStates {
				for _, profileAnc := range allAncillaryStates {
					anc := [3]ancillaryState{optsAnc, envAnc, profileAnc}
					name := fmt.Sprintf("identity=%s/opts=%s/env=%s/profile=%s", identityTier, optsAnc, envAnc, profileAnc)
					t.Run(name, func(t *testing.T) {
						runAncillaryCombination(t, identityTier, anc)
					})
				}
			}
		}
	}
}

func runAncillaryCombination(t *testing.T, identityTier string, anc [3]ancillaryState) {
	t.Helper()
	clearCrusoeEnvVars(t)

	opts := &Options{}
	tags := []string{"opts", "env", "profile"}

	switch identityTier {
	case "opts":
		opts.ClientSecret.ClientID = "opts-id"
		opts.ClientSecret.ClientSecret = "opts-secret"
	case "env":
		t.Setenv("CRUSOE_CLIENT_ID", "env-id")
		t.Setenv("CRUSOE_CLIENT_SECRET", "env-secret")
	case "profile":
		// written into the profile TOML below
	}

	opts.ClientSecret.TokenURL = anc[0].tokenURL(tags[0])
	opts.ClientSecret.Audience = anc[0].audience(tags[0])

	if url := anc[1].tokenURL(tags[1]); url != "" {
		t.Setenv("CRUSOE_TOKEN_URL", url)
	}
	if aud := anc[1].audience(tags[1]); aud != "" {
		t.Setenv("CRUSOE_AUDIENCE", aud)
	}

	toml := "[default]\n"
	if identityTier == "profile" {
		toml += `client_id = "profile-id"` + "\n"
		toml += `client_secret = "profile-secret"` + "\n"
	}
	if url := anc[2].tokenURL(tags[2]); url != "" {
		toml += fmt.Sprintf("token_url = %q\n", url)
	}
	if aud := anc[2].audience(tags[2]); aud != "" {
		toml += fmt.Sprintf("audience = %q\n", aud)
	}
	opts.ConfigPath = writeTempConfig(t, toml)

	cfg, err := LoadConfigWithOptions(opts)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	wantTokenURL := DefaultTokenURL
	for i, a := range anc {
		if url := a.tokenURL(tags[i]); url != "" {
			wantTokenURL = url
			break
		}
	}
	wantAudience := DefaultAudience
	for i, a := range anc {
		if aud := a.audience(tags[i]); aud != "" {
			wantAudience = aud
			break
		}
	}

	if cfg.ClientSecret.TokenURL != wantTokenURL {
		t.Fatalf("TokenURL: want %q, got %q (identity=%s, anc=%v)", wantTokenURL, cfg.ClientSecret.TokenURL, identityTier, anc)
	}
	if cfg.ClientSecret.Audience != wantAudience {
		t.Fatalf("Audience: want %q, got %q (identity=%s, anc=%v)", wantAudience, cfg.ClientSecret.Audience, identityTier, anc)
	}
}

func TestSameTierCredentialConflicts(t *testing.T) {
	t.Run("opts carries both", func(t *testing.T) {
		clearCrusoeEnvVars(t)
		cfg, err := LoadConfigWithOptions(&Options{
			ConfigPath: filepath.Join(t.TempDir(), "does-not-exist"),
			APIKey:     APIKeyCredentials{AccessKeyID: "ak", SecretKey: "sk"},
			ClientSecret: ClientSecretCredentials{
				ClientID: "id", ClientSecret: "secret",
			},
		})
		if err != nil {
			t.Fatalf("unexpected LoadConfigWithOptions error: %v", err)
		}
		method, resolveErr := ResolveAuthMethod(cfg)
		if !errors.Is(resolveErr, ErrConflictingCredentials) {
			t.Fatalf("expected ErrConflictingCredentials, got method=%v err=%v", method, resolveErr)
		}
	})

	t.Run("env carries both, opts empty", func(t *testing.T) {
		clearCrusoeEnvVars(t)
		t.Setenv("CRUSOE_ACCESS_KEY_ID", "ak")
		t.Setenv("CRUSOE_SECRET_KEY", "sk")
		t.Setenv("CRUSOE_CLIENT_ID", "id")
		t.Setenv("CRUSOE_CLIENT_SECRET", "secret")

		cfg, err := LoadConfigWithOptions(&Options{ConfigPath: filepath.Join(t.TempDir(), "does-not-exist")})
		if err != nil {
			t.Fatalf("unexpected LoadConfigWithOptions error: %v", err)
		}
		method, resolveErr := ResolveAuthMethod(cfg)
		if !errors.Is(resolveErr, ErrConflictingCredentials) {
			t.Fatalf("expected ErrConflictingCredentials, got method=%v err=%v", method, resolveErr)
		}
	})

	t.Run("opts has complete APIKey only, env has complete ClientSecret only - opts wins whole, env's method silently dropped", func(t *testing.T) {
		clearCrusoeEnvVars(t)
		t.Setenv("CRUSOE_CLIENT_ID", "env-id")
		t.Setenv("CRUSOE_CLIENT_SECRET", "env-secret")

		cfg, err := LoadConfigWithOptions(&Options{
			ConfigPath: filepath.Join(t.TempDir(), "does-not-exist"),
			APIKey:     APIKeyCredentials{AccessKeyID: "opts-ak", SecretKey: "opts-sk"},
		})
		if err != nil {
			t.Fatalf("unexpected LoadConfigWithOptions error: %v", err)
		}
		if cfg.ClientSecret.ClientID != "" || cfg.ClientSecret.ClientSecret != "" {
			t.Fatalf("expected env's ClientSecret to be fully discarded when opts wins whole, got %+v", cfg.ClientSecret)
		}
		method, resolveErr := ResolveAuthMethod(cfg)
		if resolveErr != nil || method != AuthMethodAPIKey {
			t.Fatalf("expected clean AuthMethodAPIKey (no conflict detected across tiers by design), got method=%v err=%v", method, resolveErr)
		}
	})
}
