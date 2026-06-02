package idm

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/lib/pq"
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

func TestValidateSchemaUsesCurrentSearchPath(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()
	schema := "idm_schema_test"

	execTestSQL(t, db, `DROP SCHEMA IF EXISTS `+pq.QuoteIdentifier(schema)+` CASCADE`)
	t.Cleanup(func() {
		execTestSQL(t, db, `DROP SCHEMA IF EXISTS `+pq.QuoteIdentifier(schema)+` CASCADE`)
	})

	execTestSQL(t, db, `CREATE SCHEMA `+pq.QuoteIdentifier(schema))
	execTestSQL(t, db, `CREATE TABLE `+pq.QuoteIdentifier(schema)+`.users (id uuid PRIMARY KEY)`)
	execTestSQL(t, db, `CREATE TABLE `+pq.QuoteIdentifier(schema)+`.user_password (user_id uuid PRIMARY KEY)`)
	execTestSQL(t, db, `CREATE TABLE `+pq.QuoteIdentifier(schema)+`.user_identities (id uuid PRIMARY KEY)`)
	execTestSQL(t, db, `CREATE TABLE `+pq.QuoteIdentifier(schema)+`.sessions (id uuid PRIMARY KEY)`)
	execTestSQL(t, db, `SET search_path TO `+pq.QuoteIdentifier(schema)+`, public`)

	var currentSchema string
	if err := db.QueryRowContext(ctx, `SELECT current_schema()`).Scan(&currentSchema); err != nil {
		t.Fatalf("current_schema: %v", err)
	}
	if currentSchema != schema {
		t.Fatalf("expected current schema %q, got %q", schema, currentSchema)
	}

	if err := validateSchema(db); err != nil {
		t.Fatalf("validateSchema() error = %v", err)
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

func openTestDB(t *testing.T) *sql.DB {
	t.Helper()

	dsn := "postgres://xchangeai:pwd@localhost:5432/xchangeai?sslmode=disable"
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() {
		_ = db.Close()
	})

	if err := db.Ping(); err != nil {
		t.Skipf("skipping postgres integration test: %v", err)
	}

	return db
}

func execTestSQL(t *testing.T, db *sql.DB, query string) {
	t.Helper()

	if _, err := db.Exec(query); err != nil {
		t.Fatalf("exec %q: %v", query, err)
	}
}
