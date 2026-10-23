package credentials

import (
	"os"
	"path/filepath"
	"testing"
)

// crusoeEnvVars lists every CRUSOE_* variable LoadConfigWithOptions reads directly.
var crusoeEnvVars = []string{
	"CRUSOE_PROFILE",
	"CRUSOE_ACCESS_KEY_ID",
	"CRUSOE_SECRET_KEY",
	"CRUSOE_SERVICE_ACCOUNT_CLIENT_ID",
	"CRUSOE_SERVICE_ACCOUNT_CLIENT_SECRET",
	"CRUSOE_SERVICE_ACCOUNT_TOKEN_URL",
	"CRUSOE_SERVICE_ACCOUNT_AUDIENCE",
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
		if cfg.ProfileName != "from-file" || cfg.AccessKeyID != "file-key" {
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
		if cfg.ProfileName != "from-env" || cfg.AccessKeyID != "env-profile-key" {
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
		if cfg.ProfileName != "from-opts" || cfg.AccessKeyID != "opts-profile-key" {
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
		if cfg.AccessKeyID != "env-key" || cfg.SecretKey != "env-secret" {
			t.Fatalf("expected env credentials to win, got %+v", cfg)
		}
	})

	t.Run("profile alone is used when no env override is set", func(t *testing.T) {
		cfg, err := LoadConfigWithOptions(&Options{ConfigPath: configPath})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if cfg.AccessKeyID != "file-key" || cfg.SecretKey != "file-secret" {
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
		if cfg.AccessKeyID != "file-key" || cfg.SecretKey != "file-secret" {
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
		ConfigPath:  configPath,
		AccessKeyID: "explicit-key",
		SecretKey:   "explicit-secret",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.AccessKeyID != "explicit-key" || cfg.SecretKey != "explicit-secret" {
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
	if cfg.AccessKeyID != "env-key" || cfg.SecretKey != "env-secret" {
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
		if cfg.AccessKeyID != "dir-env-key" || cfg.SecretKey != "dir-env-secret" {
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
		if cfg.AccessKeyID != "explicit-path-key" || cfg.SecretKey != "explicit-path-secret" {
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
	if cfg.AccessKeyID != "env-key" || cfg.SecretKey != "env-secret" {
		t.Fatalf("expected env vars to still populate despite the malformed file, got %+v", cfg)
	}
}

func TestProfileNotFoundInConfig(t *testing.T) {
	clearCrusoeEnvVars(t)

	configPath := writeTempConfig(t, `
[default]
access_key_id = "file-key"
secret_key = "file-secret"
`)

	cfg, err := LoadConfigWithOptions(&Options{ConfigPath: configPath, Profile: "does-not-exist"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.ProfileName != "does-not-exist" {
		t.Fatalf("expected ProfileName to record the requested name, got %q", cfg.ProfileName)
	}
	if cfg.AccessKeyID != "" || cfg.SecretKey != "" {
		t.Fatalf("expected empty credentials for a profile absent from the file, got %+v", cfg)
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
	if prodCfg.AccessKeyID != "prod-key" || prodCfg.SecretKey != "prod-secret" {
		t.Fatalf("expected production profile credentials, got %+v", prodCfg)
	}

	stagingCfg, err := LoadConfigWithOptions(&Options{ConfigPath: configPath, Profile: "staging"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if stagingCfg.AccessKeyID != "staging-key" || stagingCfg.SecretKey != "staging-secret" {
		t.Fatalf("expected staging profile credentials, got %+v", stagingCfg)
	}
}

func TestServiceAccountConfig_FromProfile(t *testing.T) {
	clearCrusoeEnvVars(t)

	configPath := writeTempConfig(t, `
[default]
service_account_client_id = "profile-client-id"
service_account_client_secret = "profile-client-secret"
`)

	cfg, err := LoadConfigWithOptions(&Options{ConfigPath: configPath})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.ServiceAccountClientID != "profile-client-id" || cfg.ServiceAccountClientSecret != "profile-client-secret" {
		t.Fatalf("expected profile service account credentials, got %+v", cfg)
	}
	if cfg.ServiceAccountTokenURL != DefaultServiceAccountTokenURL {
		t.Fatalf("expected default token URL to be preserved, got %q", cfg.ServiceAccountTokenURL)
	}
	if cfg.ServiceAccountAudience != DefaultServiceAccountAudience {
		t.Fatalf("expected default audience to be preserved, got %q", cfg.ServiceAccountAudience)
	}
}

func TestServiceAccountConfig_EnvOverridesProfile(t *testing.T) {
	clearCrusoeEnvVars(t)

	configPath := writeTempConfig(t, `
[default]
service_account_client_id = "profile-client-id"
service_account_client_secret = "profile-client-secret"
`)

	os.Setenv("CRUSOE_SERVICE_ACCOUNT_CLIENT_ID", "env-client-id")                         //nolint:usetesting // explicit var for this test's assertion
	os.Setenv("CRUSOE_SERVICE_ACCOUNT_CLIENT_SECRET", "env-client-secret")                 //nolint:usetesting // explicit var for this test's assertion
	os.Setenv("CRUSOE_SERVICE_ACCOUNT_TOKEN_URL", "https://auth.example.com/oauth2/token") //nolint:usetesting // explicit var for this test's assertion
	os.Setenv("CRUSOE_SERVICE_ACCOUNT_AUDIENCE", "https://api.example.com")                //nolint:usetesting // explicit var for this test's assertion
	defer os.Unsetenv("CRUSOE_SERVICE_ACCOUNT_CLIENT_ID")                                  //nolint:errcheck,usetesting // cleanup
	defer os.Unsetenv("CRUSOE_SERVICE_ACCOUNT_CLIENT_SECRET")                              //nolint:errcheck,usetesting // cleanup
	defer os.Unsetenv("CRUSOE_SERVICE_ACCOUNT_TOKEN_URL")                                  //nolint:errcheck,usetesting // cleanup
	defer os.Unsetenv("CRUSOE_SERVICE_ACCOUNT_AUDIENCE")                                   //nolint:errcheck,usetesting // cleanup

	cfg, err := LoadConfigWithOptions(&Options{ConfigPath: configPath})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.ServiceAccountClientID != "env-client-id" || cfg.ServiceAccountClientSecret != "env-client-secret" {
		t.Fatalf("expected env service account credentials, got %+v", cfg)
	}
	if cfg.ServiceAccountTokenURL != "https://auth.example.com/oauth2/token" {
		t.Fatalf("expected env token URL, got %q", cfg.ServiceAccountTokenURL)
	}
	if cfg.ServiceAccountAudience != "https://api.example.com" {
		t.Fatalf("expected env audience, got %q", cfg.ServiceAccountAudience)
	}
}

func TestCrossTypeCredentialsDoNotCombine(t *testing.T) {
	clearCrusoeEnvVars(t)

	configPath := writeTempConfig(t, `
[default]
service_account_client_id = "profile-client-id"
service_account_client_secret = "profile-client-secret"
`)

	os.Setenv("CRUSOE_ACCESS_KEY_ID", "stray-env-key") //nolint:usetesting // explicit var for this test's assertion
	defer os.Unsetenv("CRUSOE_ACCESS_KEY_ID")          //nolint:errcheck,usetesting // cleanup

	cfg, err := LoadConfigWithOptions(&Options{ConfigPath: configPath})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.ServiceAccountClientID != "profile-client-id" || cfg.ServiceAccountClientSecret != "profile-client-secret" {
		t.Fatalf("expected the profile's complete service account pair, got %+v", cfg)
	}
	if cfg.AccessKeyID != "" || cfg.SecretKey != "" {
		t.Fatalf("expected the stray env access key to be ignored entirely, got %+v", cfg)
	}

	method, err := ResolveAuthMethod(cfg)
	if err != nil {
		t.Fatalf("expected a clean resolution, got error: %v", err)
	}
	if method != AuthMethodServiceAccount {
		t.Fatalf("expected AuthMethodServiceAccount, got %v", method)
	}
}

func TestProfileIsolatedFromProcessWideEnvVars(t *testing.T) {
	clearCrusoeEnvVars(t)

	configPath := writeTempConfig(t, `
[projectA]
service_account_client_id = "projectA-client-id"
service_account_client_secret = "projectA-client-secret"
`)

	os.Setenv("CRUSOE_ACCESS_KEY_ID", "process-wide-key") //nolint:usetesting // simulates another identity's env vars
	os.Setenv("CRUSOE_SECRET_KEY", "process-wide-secret") //nolint:usetesting // simulates another identity's env vars
	defer os.Unsetenv("CRUSOE_ACCESS_KEY_ID")             //nolint:errcheck,usetesting // cleanup
	defer os.Unsetenv("CRUSOE_SECRET_KEY")                //nolint:errcheck,usetesting // cleanup

	cfg, err := LoadConfigWithOptions(&Options{ConfigPath: configPath, Profile: "projectA"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.ServiceAccountClientID != "projectA-client-id" || cfg.ServiceAccountClientSecret != "projectA-client-secret" {
		t.Fatalf("expected projectA's service account pair, got %+v", cfg)
	}
	if cfg.AccessKeyID != "" || cfg.SecretKey != "" {
		t.Fatalf("expected process-wide env vars to be fully excluded from this profile's identity, got %+v", cfg)
	}

	method, err := ResolveAuthMethod(cfg)
	if err != nil {
		t.Fatalf("expected WithProfile to isolate this identity cleanly, got error: %v", err)
	}
	if method != AuthMethodServiceAccount {
		t.Fatalf("expected AuthMethodServiceAccount, got %v", method)
	}
}
