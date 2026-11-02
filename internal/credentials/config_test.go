package credentials

import (
	"errors"
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

	cfg, err := LoadConfigWithOptions(&Options{
		ConfigPath: filepath.Join(t.TempDir(), "does-not-exist"),
		APIKey:     APIKeyCredentials{AccessKeyID: "opts-access-key"}, // incomplete alone: no SecretKey
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	method, err := ResolveAuthMethod(cfg)
	if err == nil {
		t.Fatalf("expected an incomplete-credential error, got a resolved method %v with cfg %+v", method, cfg.APIKey)
	}
	if !errors.Is(err, ErrIncompleteAPIKeyCredentials) {
		t.Fatalf("expected ErrIncompleteAPIKeyCredentials, got: %v", err)
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
		if cfg.CredentialSource != "profile default" || !cfg.CredentialSourceComplete {
			t.Fatalf("expected complete profile default, got source=%q complete=%v", cfg.CredentialSource, cfg.CredentialSourceComplete)
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
