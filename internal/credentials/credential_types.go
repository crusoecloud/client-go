package credentials

// APIKeyCredentials holds the static HMAC access key / secret key pair used by AuthMethodAPIKey.
type APIKeyCredentials struct {
	AccessKeyID string
	SecretKey   string
}

// ClientSecretCredentials holds the OAuth2 client_credentials grant fields authenticated via a
// shared client secret (AuthMethodClientSecret). TokenURL and Audience default to
// DefaultTokenURL/DefaultAudience when empty - see validateClientSecretEnvironment.
type ClientSecretCredentials struct {
	ClientID     string
	ClientSecret string
	TokenURL     string
	Audience     string
}
