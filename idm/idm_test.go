package idm

import (
	"context"
	"database/sql"
	"reflect"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"
	"github.com/tendant/simple-idm-slim/pkg/domain"
	"github.com/tendant/simple-idm-slim/pkg/repository"
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
	execTestSQL(t, db, `CREATE TABLE `+pq.QuoteIdentifier(schema)+`.roles (id uuid PRIMARY KEY)`)
	execTestSQL(t, db, `CREATE TABLE `+pq.QuoteIdentifier(schema)+`.user_roles (user_id uuid NOT NULL, role_id uuid NOT NULL)`)
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

func TestIDMRoleFacade(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()
	setupIDMRoleSchema(t, db)

	auth, err := New(Config{
		DB:        db,
		JWTSecret: "test-secret-key-32-characters-lo",
	})
	if err != nil {
		t.Fatalf("new idm: %v", err)
	}

	adminRole, err := auth.EnsureRole(ctx, "admin")
	if err != nil {
		t.Fatalf("ensure admin role: %v", err)
	}
	if adminRole.Name != "admin" {
		t.Fatalf("expected admin role, got %#v", adminRole)
	}
	if _, err := auth.EnsureRole(ctx, "creator"); err != nil {
		t.Fatalf("ensure creator role: %v", err)
	}

	roles, err := auth.ListRoles(ctx)
	if err != nil {
		t.Fatalf("list roles: %v", err)
	}
	if !reflect.DeepEqual(idmRoleNames(roles), []string{"admin", "creator"}) {
		t.Fatalf("unexpected role list: %#v", roles)
	}

	userID := insertIDMRoleTestUser(t, db, "facade-role@example.com")
	if err := auth.AssignRole(ctx, userID, "creator"); err != nil {
		t.Fatalf("assign creator role: %v", err)
	}
	names, err := auth.GetUserRoles(ctx, userID)
	if err != nil {
		t.Fatalf("get user roles: %v", err)
	}
	if !reflect.DeepEqual(names, []string{"creator"}) {
		t.Fatalf("expected creator role, got %#v", names)
	}

	if err := auth.SetUserRoles(ctx, userID, []string{"admin"}); err != nil {
		t.Fatalf("set user roles: %v", err)
	}
	names, err = auth.GetUserRoles(ctx, userID)
	if err != nil {
		t.Fatalf("get user roles after set: %v", err)
	}
	if !reflect.DeepEqual(names, []string{"admin"}) {
		t.Fatalf("expected admin role, got %#v", names)
	}

	if err := auth.RemoveRole(ctx, userID, "admin"); err != nil {
		t.Fatalf("remove admin role: %v", err)
	}
	names, err = auth.GetUserRoles(ctx, userID)
	if err != nil {
		t.Fatalf("get user roles after remove: %v", err)
	}
	if len(names) != 0 {
		t.Fatalf("expected no roles after remove, got %#v", names)
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

func setupIDMRoleSchema(t *testing.T, db *sql.DB) {
	t.Helper()

	schema := "idm_role_test_" + uuid.NewString()
	execTestSQL(t, db, `CREATE SCHEMA `+pq.QuoteIdentifier(schema))
	t.Cleanup(func() {
		execTestSQL(t, db, `DROP SCHEMA IF EXISTS `+pq.QuoteIdentifier(schema)+` CASCADE`)
	})
	execTestSQL(t, db, `SET search_path TO `+pq.QuoteIdentifier(schema)+`, public`)
	execTestSQL(t, db, `
		CREATE TABLE users (
			id UUID PRIMARY KEY,
			email TEXT NOT NULL UNIQUE,
			username TEXT UNIQUE,
			email_verified BOOLEAN NOT NULL DEFAULT FALSE,
			name TEXT,
			failed_login_attempts INTEGER NOT NULL DEFAULT 0,
			locked_until TIMESTAMPTZ,
			mfa_enabled BOOLEAN NOT NULL DEFAULT FALSE,
			created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			deleted_at TIMESTAMPTZ
		)
	`)
	execTestSQL(t, db, `CREATE TABLE user_password (user_id UUID PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE, password_hash TEXT NOT NULL, password_updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW())`)
	execTestSQL(t, db, `CREATE TABLE user_identities (id UUID PRIMARY KEY, user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE, provider TEXT NOT NULL, provider_subject TEXT NOT NULL, email TEXT, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW())`)
	execTestSQL(t, db, `CREATE TABLE sessions (id UUID PRIMARY KEY, user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE, token_hash TEXT NOT NULL, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), expires_at TIMESTAMPTZ NOT NULL, revoked_at TIMESTAMPTZ, last_seen_at TIMESTAMPTZ, metadata JSONB)`)
	execTestSQL(t, db, `CREATE TABLE roles (id UUID PRIMARY KEY DEFAULT gen_random_uuid(), name TEXT NOT NULL UNIQUE, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW())`)
	execTestSQL(t, db, `CREATE TABLE user_roles (user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE, role_id UUID NOT NULL REFERENCES roles(id) ON DELETE CASCADE, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), PRIMARY KEY (user_id, role_id))`)
}

func insertIDMRoleTestUser(t *testing.T, db *sql.DB, email string) uuid.UUID {
	t.Helper()

	usersRepo := repository.NewUsersRepository(db)
	now := time.Now()
	user := &domain.User{
		ID:            uuid.New(),
		Email:         email,
		EmailVerified: true,
		CreatedAt:     now,
		UpdatedAt:     now,
	}
	if err := usersRepo.Create(context.Background(), user); err != nil {
		t.Fatalf("create test user: %v", err)
	}
	return user.ID
}

func idmRoleNames(roles []*domain.Role) []string {
	names := make([]string, 0, len(roles))
	for _, role := range roles {
		names = append(names, role.Name)
	}
	return names
}
