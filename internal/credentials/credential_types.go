package credentials

// APIKeyCredentials holds the static HMAC access key / secret key pair used by AuthMethodAPIKey.
type APIKeyCredentials struct {
	AccessKeyID string
	SecretKey   string
}

// ClientSecretCredentials holds the OAuth2 client_credentials grant fields authenticated via a
// shared client secret (AuthMethodClientSecret). TokenURL and Audience default to
// DefaultServiceAccountTokenURL/DefaultServiceAccountAudience when empty - see
// validateClientSecretEnvironment. The CRUSOE_SERVICE_ACCOUNT_* env vars and the config file's
// service_account_* TOML keys are unchanged; only this Go field path changed.
type ClientSecretCredentials struct {
	ClientID     string
	ClientSecret string
	TokenURL     string
	Audience     string
}
