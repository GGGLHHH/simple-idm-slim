package auth

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/tendant/simple-idm-slim/pkg/domain"
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

func TestNewSessionService_BackwardCompatibleNilRoles(t *testing.T) {
	// Legacy constructor must behave as roles=nil and not panic.
	svc := NewSessionService(SessionConfig{JWTSecret: []byte("secret")}, nil, nil)
	if svc == nil {
		t.Fatal("expected non-nil service")
	}
	if svc.roles != nil {
		t.Fatal("expected roles to be nil for legacy constructor")
	}
	// With nil roles, getUserRoleNames returns (nil, nil).
	names, err := svc.getUserRoleNames(context.Background(), uuid.New())
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if names != nil {
		t.Fatalf("expected nil names, got %#v", names)
	}
}

func TestIssueAccessToken_RolesClaim(t *testing.T) {
	svc := NewSessionService(SessionConfig{JWTSecret: []byte("test-secret-test-secret-test-secret")}, nil, nil)
	user := &domain.User{ID: uuid.New(), Email: "u@example.com"}
	now := time.Now()

	// With roles -> claim present and correct.
	tok, err := svc.issueAccessToken(context.Background(), user, []string{"admin", "creator"}, uuid.New(), now, now.Add(time.Hour), IssueSessionOpts{})
	if err != nil {
		t.Fatalf("issue with roles: %v", err)
	}
	claims, err := svc.ValidateAccessToken(tok)
	if err != nil {
		t.Fatalf("validate: %v", err)
	}
	if !reflect.DeepEqual(claims.Roles, []string{"admin", "creator"}) {
		t.Fatalf("roles claim mismatch: %#v", claims.Roles)
	}

	// Nil roles -> "roles" key omitted from the token payload (omitempty).
	tok2, err := svc.issueAccessToken(context.Background(), user, nil, uuid.New(), now, now.Add(time.Hour), IssueSessionOpts{})
	if err != nil {
		t.Fatalf("issue nil roles: %v", err)
	}
	if tokenPayloadHasKey(t, tok2, "roles") {
		t.Fatal("expected no 'roles' key in token payload when roles is nil")
	}
}

func tokenPayloadHasKey(t *testing.T, token, key string) bool {
	t.Helper()
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("malformed token: %d segments", len(parts))
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("unmarshal payload: %v", err)
	}
	_, ok := m[key]
	return ok
}
