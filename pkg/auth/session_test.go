package auth

import (
	"context"
	"database/sql"
	"reflect"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/lib/pq"
	"github.com/tendant/simple-idm-slim/pkg/domain"
	"github.com/tendant/simple-idm-slim/pkg/repository"
)

func TestSessionService_ValidateAccessToken(t *testing.T) {
	secret := []byte("test-secret-key-32-characters-lo")
	service := &SessionService{
		config: SessionConfig{
			JWTSecret:      secret,
			Issuer:         "test-issuer",
			AccessTokenTTL: 15 * time.Minute,
		},
	}

	userID := uuid.New()
	sessionID := uuid.New()
	now := time.Now()

	// Create a valid token
	claims := AccessTokenClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   userID.String(),
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(15 * time.Minute)),
			Issuer:    "test-issuer",
			ID:        sessionID.String(),
		},
		Email:         "test@example.com",
		EmailVerified: true,
		Name:          "Test User",
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(secret)
	if err != nil {
		t.Fatalf("Failed to sign token: %v", err)
	}

	// Validate the token
	validatedClaims, err := service.ValidateAccessToken(tokenString)
	if err != nil {
		t.Fatalf("ValidateAccessToken failed: %v", err)
	}

	if validatedClaims.Subject != userID.String() {
		t.Errorf("Subject mismatch: got %s, want %s", validatedClaims.Subject, userID.String())
	}
	if validatedClaims.Email != "test@example.com" {
		t.Errorf("Email mismatch: got %s, want %s", validatedClaims.Email, "test@example.com")
	}
}

func TestSessionService_ValidateAccessToken_Expired(t *testing.T) {
	secret := []byte("test-secret-key-32-characters-lo")
	service := &SessionService{
		config: SessionConfig{
			JWTSecret: secret,
			Issuer:    "test-issuer",
		},
	}

	// Create an expired token
	claims := AccessTokenClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   uuid.New().String(),
			IssuedAt:  jwt.NewNumericDate(time.Now().Add(-1 * time.Hour)),
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(-30 * time.Minute)), // Expired
			Issuer:    "test-issuer",
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, _ := token.SignedString(secret)

	_, err := service.ValidateAccessToken(tokenString)
	if err == nil {
		t.Error("ValidateAccessToken should fail for expired token")
	}
}

func TestSessionService_ValidateAccessToken_WrongSecret(t *testing.T) {
	service := &SessionService{
		config: SessionConfig{
			JWTSecret: []byte("correct-secret-key-32-characters"),
			Issuer:    "test-issuer",
		},
	}

	// Create a token with different secret
	claims := AccessTokenClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   uuid.New().String(),
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(15 * time.Minute)),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, _ := token.SignedString([]byte("wrong-secret-key-32-characters!!"))

	_, err := service.ValidateAccessToken(tokenString)
	if err == nil {
		t.Error("ValidateAccessToken should fail for wrong secret")
	}
}

func TestSessionService_ValidateAccessToken_InvalidFormat(t *testing.T) {
	service := &SessionService{
		config: SessionConfig{
			JWTSecret: []byte("test-secret"),
		},
	}

	invalidTokens := []string{
		"",
		"invalid",
		"not.a.jwt",
		"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.invalid.signature",
	}

	for _, token := range invalidTokens {
		_, err := service.ValidateAccessToken(token)
		if err == nil {
			t.Errorf("ValidateAccessToken should fail for invalid token: %s", token)
		}
	}
}

func TestSessionService_GetUserIDFromToken(t *testing.T) {
	secret := []byte("test-secret-key-32-characters-lo")
	service := &SessionService{
		config: SessionConfig{
			JWTSecret: secret,
		},
	}

	userID := uuid.New()

	claims := AccessTokenClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   userID.String(),
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(15 * time.Minute)),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, _ := token.SignedString(secret)

	extractedID, err := service.GetUserIDFromToken(tokenString)
	if err != nil {
		t.Fatalf("GetUserIDFromToken failed: %v", err)
	}

	if extractedID != userID {
		t.Errorf("User ID mismatch: got %s, want %s", extractedID, userID)
	}
}

func TestNewSessionService_Defaults(t *testing.T) {
	service := NewSessionService(SessionConfig{
		JWTSecret: []byte("test"),
	}, nil, nil)

	if service.config.AccessTokenTTL != DefaultAccessTokenTTL {
		t.Errorf("AccessTokenTTL should default to %v, got %v", DefaultAccessTokenTTL, service.config.AccessTokenTTL)
	}

	if service.config.RefreshTokenTTL != DefaultRefreshTokenTTL {
		t.Errorf("RefreshTokenTTL should default to %v, got %v", DefaultRefreshTokenTTL, service.config.RefreshTokenTTL)
	}
}

func TestNewSessionService_CustomTTL(t *testing.T) {
	customAccess := 30 * time.Minute
	customRefresh := 24 * time.Hour

	service := NewSessionService(SessionConfig{
		JWTSecret:       []byte("test"),
		AccessTokenTTL:  customAccess,
		RefreshTokenTTL: customRefresh,
	}, nil, nil)

	if service.config.AccessTokenTTL != customAccess {
		t.Errorf("AccessTokenTTL should be %v, got %v", customAccess, service.config.AccessTokenTTL)
	}

	if service.config.RefreshTokenTTL != customRefresh {
		t.Errorf("RefreshTokenTTL should be %v, got %v", customRefresh, service.config.RefreshTokenTTL)
	}
}

func TestSessionService_IssueAndRefreshIncludeRoleClaims(t *testing.T) {
	db := openSessionTestDB(t)
	ctx := context.Background()
	setupSessionRoleSchema(t, db)

	usersRepo := repository.NewUsersRepository(db)
	sessionsRepo := repository.NewSessionsRepository(db)
	rolesRepo := repository.NewRolesRepository(db)
	user := insertSessionTestUser(t, usersRepo, "role-session@example.com")
	adminRole, err := rolesRepo.Ensure(ctx, "admin")
	if err != nil {
		t.Fatalf("ensure admin role: %v", err)
	}
	creatorRole, err := rolesRepo.Ensure(ctx, "creator")
	if err != nil {
		t.Fatalf("ensure creator role: %v", err)
	}
	if err := rolesRepo.AssignToUser(ctx, user.ID, creatorRole.ID); err != nil {
		t.Fatalf("assign creator role: %v", err)
	}

	service := NewSessionServiceWithRoles(SessionConfig{
		JWTSecret: []byte("test-secret-key-32-characters-lo"),
		Issuer:    "test-issuer",
	}, sessionsRepo, usersRepo, rolesRepo)

	tokenPair, err := service.IssueSession(ctx, user.ID, IssueSessionOpts{})
	if err != nil {
		t.Fatalf("issue session: %v", err)
	}
	claims, err := service.ValidateAccessToken(tokenPair.AccessToken)
	if err != nil {
		t.Fatalf("validate issued access token: %v", err)
	}
	if !reflect.DeepEqual(claims.Roles, []string{"creator"}) {
		t.Fatalf("issued roles mismatch: got %#v", claims.Roles)
	}

	if err := rolesRepo.AssignToUser(ctx, user.ID, adminRole.ID); err != nil {
		t.Fatalf("assign admin role: %v", err)
	}
	refreshed, err := service.RefreshSession(ctx, tokenPair.RefreshToken, IssueSessionOpts{})
	if err != nil {
		t.Fatalf("refresh session: %v", err)
	}
	refreshedClaims, err := service.ValidateAccessToken(refreshed.AccessToken)
	if err != nil {
		t.Fatalf("validate refreshed access token: %v", err)
	}
	if !reflect.DeepEqual(refreshedClaims.Roles, []string{"admin", "creator"}) {
		t.Fatalf("refreshed roles mismatch: got %#v", refreshedClaims.Roles)
	}
}

func TestSessionService_CustomIssuerReceivesRoles(t *testing.T) {
	db := openSessionTestDB(t)
	ctx := context.Background()
	setupSessionRoleSchema(t, db)

	usersRepo := repository.NewUsersRepository(db)
	sessionsRepo := repository.NewSessionsRepository(db)
	rolesRepo := repository.NewRolesRepository(db)
	user := insertSessionTestUser(t, usersRepo, "custom-issuer@example.com")
	role, err := rolesRepo.Ensure(ctx, "agent")
	if err != nil {
		t.Fatalf("ensure agent role: %v", err)
	}
	if err := rolesRepo.AssignToUser(ctx, user.ID, role.ID); err != nil {
		t.Fatalf("assign agent role: %v", err)
	}

	issuer := &capturingAccessTokenIssuer{returnToken: "custom-token"}
	service := NewSessionServiceWithRoles(SessionConfig{
		JWTSecret:         []byte("test-secret-key-32-characters-lo"),
		Issuer:            "test-issuer",
		AccessTokenIssuer: issuer,
	}, sessionsRepo, usersRepo, rolesRepo)

	tokenPair, err := service.IssueSession(ctx, user.ID, IssueSessionOpts{})
	if err != nil {
		t.Fatalf("issue session: %v", err)
	}
	if tokenPair.AccessToken != "custom-token" {
		t.Fatalf("expected custom issuer token, got %q", tokenPair.AccessToken)
	}
	if !reflect.DeepEqual(issuer.input.Roles, []string{"agent"}) {
		t.Fatalf("custom issuer roles mismatch: got %#v", issuer.input.Roles)
	}
}

type capturingAccessTokenIssuer struct {
	returnToken string
	input       AccessTokenIssueInput
}

func (i *capturingAccessTokenIssuer) IssueAccessToken(_ context.Context, input AccessTokenIssueInput) (string, error) {
	i.input = input
	return i.returnToken, nil
}

func openSessionTestDB(t *testing.T) *sql.DB {
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

func setupSessionRoleSchema(t *testing.T, db *sql.DB) {
	t.Helper()

	schema := "session_role_test_" + uuid.NewString()
	execSessionTestSQL(t, db, `CREATE SCHEMA `+pq.QuoteIdentifier(schema))
	t.Cleanup(func() {
		execSessionTestSQL(t, db, `DROP SCHEMA IF EXISTS `+pq.QuoteIdentifier(schema)+` CASCADE`)
	})
	execSessionTestSQL(t, db, `SET search_path TO `+pq.QuoteIdentifier(schema)+`, public`)
	execSessionTestSQL(t, db, `
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
	execSessionTestSQL(t, db, `
		CREATE TABLE sessions (
			id UUID PRIMARY KEY,
			user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
			token_hash TEXT NOT NULL,
			created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			expires_at TIMESTAMPTZ NOT NULL,
			revoked_at TIMESTAMPTZ,
			last_seen_at TIMESTAMPTZ,
			metadata JSONB
		)
	`)
	execSessionTestSQL(t, db, `
		CREATE TABLE roles (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			name TEXT NOT NULL UNIQUE,
			created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
		)
	`)
	execSessionTestSQL(t, db, `
		CREATE TABLE user_roles (
			user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
			role_id UUID NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
			created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			PRIMARY KEY (user_id, role_id)
		)
	`)
}

func insertSessionTestUser(t *testing.T, repo *repository.UsersRepository, email string) *domain.User {
	t.Helper()

	now := time.Now()
	user := &domain.User{
		ID:            uuid.New(),
		Email:         email,
		EmailVerified: true,
		CreatedAt:     now,
		UpdatedAt:     now,
	}
	if err := repo.Create(context.Background(), user); err != nil {
		t.Fatalf("create test user: %v", err)
	}
	return user
}

func execSessionTestSQL(t *testing.T, db *sql.DB, query string) {
	t.Helper()

	if _, err := db.Exec(query); err != nil {
		t.Fatalf("exec %q: %v", query, err)
	}
}
