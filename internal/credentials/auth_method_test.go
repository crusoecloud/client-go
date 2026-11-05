package credentials

import (
	"errors"
	"testing"
)

func TestAuthCandidatesInvariants(t *testing.T) {
	seen := make(map[AuthMethod]bool)
	for _, c := range authCandidates {
		if c.complete == nil {
			t.Fatalf("authCandidate for method %v has a nil complete check", c.method)
		}
		if c.partial != nil && c.incompleteErr == nil {
			t.Fatalf("authCandidate for method %v has a partial check but no incompleteErr; "+
				"ResolveAuthMethod would return (AuthMethodUnknown, nil) for a partial match", c.method)
		}
		if seen[c.method] {
			t.Fatalf("authCandidates has more than one entry for method %v", c.method)
		}
		seen[c.method] = true
	}
}

func TestResolveAuthMethod(t *testing.T) {
	tests := []struct {
		name    string
		cfg     Config
		want    AuthMethod
		wantErr error
	}{
		{
			name:    "API key only",
			cfg:     Config{APIKey: APIKeyCredentials{AccessKeyID: "key", SecretKey: "secret"}},
			want:    AuthMethodAPIKey,
			wantErr: nil,
		},
		{
			name: "service account only",
			cfg: Config{
				ClientSecret: ClientSecretCredentials{
					ClientID:     "id",
					ClientSecret: "secret",
					TokenURL:     DefaultTokenURL,
					Audience:     DefaultAudience,
				},
			},
			want:    AuthMethodClientSecret,
			wantErr: nil,
		},
		{
			name:    "nothing configured",
			cfg:     Config{},
			want:    AuthMethodUnknown,
			wantErr: ErrMissingCredentials,
		},
		{
			name: "both fully configured",
			cfg: Config{
				APIKey: APIKeyCredentials{AccessKeyID: "key", SecretKey: "secret"},
				ClientSecret: ClientSecretCredentials{
					ClientID:     "id",
					ClientSecret: "secret",
					TokenURL:     DefaultTokenURL,
					Audience:     DefaultAudience,
				},
			},
			want:    AuthMethodUnknown,
			wantErr: ErrConflictingCredentials,
		},
		{
			name:    "only access key ID set",
			cfg:     Config{APIKey: APIKeyCredentials{AccessKeyID: "key"}},
			want:    AuthMethodUnknown,
			wantErr: ErrIncompleteAPIKeyCredentials,
		},
		{
			name:    "only secret key set",
			cfg:     Config{APIKey: APIKeyCredentials{SecretKey: "secret"}},
			want:    AuthMethodUnknown,
			wantErr: ErrIncompleteAPIKeyCredentials,
		},
		{
			name:    "only service account client ID set",
			cfg:     Config{ClientSecret: ClientSecretCredentials{ClientID: "id"}},
			want:    AuthMethodUnknown,
			wantErr: ErrIncompleteClientSecretCredentials,
		},
		{
			name:    "only service account client secret set",
			cfg:     Config{ClientSecret: ClientSecretCredentials{ClientSecret: "secret"}},
			want:    AuthMethodUnknown,
			wantErr: ErrIncompleteClientSecretCredentials,
		},
		{
			name: "partial API key and partial service account: API key check wins",
			cfg: Config{
				APIKey:       APIKeyCredentials{AccessKeyID: "key"},
				ClientSecret: ClientSecretCredentials{ClientID: "id"},
			},
			want:    AuthMethodUnknown,
			wantErr: ErrIncompleteAPIKeyCredentials,
		},
		{
			name: "complete API key and partial service account",
			cfg: Config{
				APIKey:       APIKeyCredentials{AccessKeyID: "key", SecretKey: "secret"},
				ClientSecret: ClientSecretCredentials{ClientID: "id"},
			},
			want:    AuthMethodUnknown,
			wantErr: ErrIncompleteClientSecretCredentials,
		},
		{
			name: "complete service account and partial API key",
			cfg: Config{
				APIKey: APIKeyCredentials{AccessKeyID: "key"},
				ClientSecret: ClientSecretCredentials{
					ClientID:     "id",
					ClientSecret: "secret",
					TokenURL:     DefaultTokenURL,
					Audience:     DefaultAudience,
				},
			},
			want:    AuthMethodUnknown,
			wantErr: ErrIncompleteAPIKeyCredentials,
		},
		{
			name: "only token URL overridden",
			cfg: Config{
				ClientSecret: ClientSecretCredentials{
					ClientID:     "id",
					ClientSecret: "secret",
					TokenURL:     "https://auth.example.com/oauth2/token",
					Audience:     DefaultAudience,
				},
			},
			want:    AuthMethodUnknown,
			wantErr: ErrMismatchedClientSecretEnvironment,
		},
		{
			name: "only audience overridden",
			cfg: Config{
				ClientSecret: ClientSecretCredentials{
					ClientID:     "id",
					ClientSecret: "secret",
					TokenURL:     DefaultTokenURL,
					Audience:     "https://api.example.com",
				},
			},
			want:    AuthMethodUnknown,
			wantErr: ErrMismatchedClientSecretEnvironment,
		},
		{
			name: "both token URL and audience overridden together",
			cfg: Config{
				ClientSecret: ClientSecretCredentials{
					ClientID:     "id",
					ClientSecret: "secret",
					TokenURL:     "https://auth.example.com/oauth2/token",
					Audience:     "https://api.example.com",
				},
			},
			want:    AuthMethodClientSecret,
			wantErr: nil,
		},
		{
			name: "both token URL and audience left unset",
			cfg: Config{
				ClientSecret: ClientSecretCredentials{ClientID: "id", ClientSecret: "secret"},
			},
			want:    AuthMethodClientSecret,
			wantErr: nil,
		},
		{
			name: "both explicitly set to their own defaults",
			cfg: Config{
				ClientSecret: ClientSecretCredentials{
					ClientID:     "id",
					ClientSecret: "secret",
					TokenURL:     DefaultTokenURL,
					Audience:     DefaultAudience,
				},
			},
			want:    AuthMethodClientSecret,
			wantErr: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ResolveAuthMethod(&tt.cfg)

			if tt.wantErr == nil {
				if err != nil {
					t.Fatalf("expected no error, got: %v", err)
				}
			} else if !errors.Is(err, tt.wantErr) {
				t.Fatalf("expected error %v, got: %v", tt.wantErr, err)
			}

			if got != tt.want {
				t.Fatalf("expected AuthMethod %v, got %v", tt.want, got)
			}

			if tt.wantErr != nil && got != AuthMethodUnknown {
				t.Fatalf("expected AuthMethodUnknown alongside an error, got %v", got)
			}
		})
	}
}
