package credentials

import (
	"errors"
	"testing"
)

func TestResolveAuthMethod(t *testing.T) {
	tests := []struct {
		name    string
		cfg     Config
		want    AuthMethod
		wantErr error
	}{
		{
			name:    "API key only",
			cfg:     Config{AccessKeyID: "key", SecretKey: "secret"},
			want:    AuthMethodAPIKey,
			wantErr: nil,
		},
		{
			name: "service account only",
			cfg: Config{
				ServiceAccountClientID:     "id",
				ServiceAccountClientSecret: "secret",
				ServiceAccountTokenURL:     defaultServiceAccountTokenURL,
				ServiceAccountAudience:     defaultServiceAccountAudience,
			},
			want:    AuthMethodServiceAccount,
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
				AccessKeyID: "key", SecretKey: "secret",
				ServiceAccountClientID:     "id",
				ServiceAccountClientSecret: "secret",
				ServiceAccountTokenURL:     defaultServiceAccountTokenURL,
				ServiceAccountAudience:     defaultServiceAccountAudience,
			},
			want:    AuthMethodUnknown,
			wantErr: ErrConflictingCredentials,
		},
		{
			name:    "only access key ID set",
			cfg:     Config{AccessKeyID: "key"},
			want:    AuthMethodUnknown,
			wantErr: ErrIncompleteAPIKeyCredentials,
		},
		{
			name:    "only secret key set",
			cfg:     Config{SecretKey: "secret"},
			want:    AuthMethodUnknown,
			wantErr: ErrIncompleteAPIKeyCredentials,
		},
		{
			name:    "only service account client ID set",
			cfg:     Config{ServiceAccountClientID: "id"},
			want:    AuthMethodUnknown,
			wantErr: ErrIncompleteServiceAccountCredentials,
		},
		{
			name:    "only service account client secret set",
			cfg:     Config{ServiceAccountClientSecret: "secret"},
			want:    AuthMethodUnknown,
			wantErr: ErrIncompleteServiceAccountCredentials,
		},
		{
			name: "partial API key and partial service account: API key check wins",
			cfg: Config{
				AccessKeyID:            "key",
				ServiceAccountClientID: "id",
			},
			want:    AuthMethodUnknown,
			wantErr: ErrIncompleteAPIKeyCredentials,
		},
		{
			name: "complete API key and partial service account",
			cfg: Config{
				AccessKeyID: "key", SecretKey: "secret",
				ServiceAccountClientID: "id",
			},
			want:    AuthMethodUnknown,
			wantErr: ErrIncompleteServiceAccountCredentials,
		},
		{
			name: "complete service account and partial API key",
			cfg: Config{
				AccessKeyID:                "key",
				ServiceAccountClientID:     "id",
				ServiceAccountClientSecret: "secret",
				ServiceAccountTokenURL:     defaultServiceAccountTokenURL,
				ServiceAccountAudience:     defaultServiceAccountAudience,
			},
			want:    AuthMethodUnknown,
			wantErr: ErrIncompleteAPIKeyCredentials,
		},
		{
			name: "only token URL overridden",
			cfg: Config{
				ServiceAccountClientID:     "id",
				ServiceAccountClientSecret: "secret",
				ServiceAccountTokenURL:     "https://auth.example.com/oauth2/token",
				ServiceAccountAudience:     defaultServiceAccountAudience,
			},
			want:    AuthMethodUnknown,
			wantErr: ErrMismatchedServiceAccountEnvironment,
		},
		{
			name: "only audience overridden",
			cfg: Config{
				ServiceAccountClientID:     "id",
				ServiceAccountClientSecret: "secret",
				ServiceAccountTokenURL:     defaultServiceAccountTokenURL,
				ServiceAccountAudience:     "https://api.example.com",
			},
			want:    AuthMethodUnknown,
			wantErr: ErrMismatchedServiceAccountEnvironment,
		},
		{
			name: "both token URL and audience overridden together",
			cfg: Config{
				ServiceAccountClientID:     "id",
				ServiceAccountClientSecret: "secret",
				ServiceAccountTokenURL:     "https://auth.example.com/oauth2/token",
				ServiceAccountAudience:     "https://api.example.com",
			},
			want:    AuthMethodServiceAccount,
			wantErr: nil,
		},
		{
			name: "both token URL and audience left unset",
			cfg: Config{
				ServiceAccountClientID:     "id",
				ServiceAccountClientSecret: "secret",
			},
			want:    AuthMethodServiceAccount,
			wantErr: nil,
		},
		{
			name: "both explicitly set to their own defaults",
			cfg: Config{
				ServiceAccountClientID:     "id",
				ServiceAccountClientSecret: "secret",
				ServiceAccountTokenURL:     defaultServiceAccountTokenURL,
				ServiceAccountAudience:     defaultServiceAccountAudience,
			},
			want:    AuthMethodServiceAccount,
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
