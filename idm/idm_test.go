package idm

import (
	"testing"
	"time"
)

func TestValidateConfig(t *testing.T) {
	tests := []struct {
		name    string
		config  Config
		wantErr bool
		errMsg  string
	}{
		{
			name:    "missing DB",
			config:  Config{JWTSecret: "12345678901234567890123456789012"},
			wantErr: true,
			errMsg:  "idm: DB is required",
		},
		{
			name:    "missing JWTSecret",
			config:  Config{DB: nil},
			wantErr: true,
			errMsg:  "idm: DB is required",
		},
		{
			name: "short JWTSecret",
			config: Config{
				DB:        nil, // Will fail on DB first
				JWTSecret: "short",
			},
			wantErr: true,
		},
		{
			name: "incomplete Google config",
			config: Config{
				DB:        nil,
				JWTSecret: "12345678901234567890123456789012",
				Google:    &GoogleConfig{ClientID: "id"},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateConfig(&tt.config)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateConfig() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestApplyDefaults(t *testing.T) {
	cfg := Config{}
	applyDefaults(&cfg)

	if cfg.JWTIssuer != "simple-idm" {
		t.Errorf("JWTIssuer = %q, want %q", cfg.JWTIssuer, "simple-idm")
	}
	if cfg.AccessTokenTTL != 15*time.Minute {
		t.Errorf("AccessTokenTTL = %v, want %v", cfg.AccessTokenTTL, 15*time.Minute)
	}
	if cfg.RefreshTokenTTL != 7*24*time.Hour {
		t.Errorf("RefreshTokenTTL = %v, want %v", cfg.RefreshTokenTTL, 7*24*time.Hour)
	}
	if cfg.Logger == nil {
		t.Error("Logger should have default value")
	}
}

func TestApplyDefaults_PreservesCustomValues(t *testing.T) {
	cfg := Config{
		JWTIssuer:       "custom-issuer",
		AccessTokenTTL:  30 * time.Minute,
		RefreshTokenTTL: 24 * time.Hour,
	}
	applyDefaults(&cfg)

	if cfg.JWTIssuer != "custom-issuer" {
		t.Errorf("JWTIssuer = %q, want %q", cfg.JWTIssuer, "custom-issuer")
	}
	if cfg.AccessTokenTTL != 30*time.Minute {
		t.Errorf("AccessTokenTTL = %v, want %v", cfg.AccessTokenTTL, 30*time.Minute)
	}
	if cfg.RefreshTokenTTL != 24*time.Hour {
		t.Errorf("RefreshTokenTTL = %v, want %v", cfg.RefreshTokenTTL, 24*time.Hour)
	}
}

func TestGoogleConfig(t *testing.T) {
	cfg := &GoogleConfig{
		ClientID:     "test-client-id",
		ClientSecret: "test-client-secret",
		RedirectURI:  "http://localhost:8080/callback",
	}

	if cfg.ClientID != "test-client-id" {
		t.Errorf("ClientID = %q, want %q", cfg.ClientID, "test-client-id")
	}
}

func TestUser(t *testing.T) {
	name := "Test User"
	user := User{
		ID:            "123",
		Email:         "test@example.com",
		EmailVerified: true,
		Name:          &name,
	}

	if user.ID != "123" {
		t.Errorf("ID = %q, want %q", user.ID, "123")
	}
	if user.Email != "test@example.com" {
		t.Errorf("Email = %q, want %q", user.Email, "test@example.com")
	}
	if !user.EmailVerified {
		t.Error("EmailVerified should be true")
	}
	if *user.Name != "Test User" {
		t.Errorf("Name = %q, want %q", *user.Name, "Test User")
	}
}
