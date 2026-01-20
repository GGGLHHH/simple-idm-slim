package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/tendant/simple-idm-slim/internal/auth"
)

func createTestSessionService(secret []byte) *auth.SessionService {
	return auth.NewSessionService(auth.SessionConfig{
		JWTSecret:      secret,
		Issuer:         "test",
		AccessTokenTTL: 15 * time.Minute,
	}, nil, nil)
}

func createTestToken(secret []byte, userID uuid.UUID, expiry time.Time) string {
	claims := auth.AccessTokenClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   userID.String(),
			ExpiresAt: jwt.NewNumericDate(expiry),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
		Email: "test@example.com",
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, _ := token.SignedString(secret)
	return tokenString
}

func TestAuth_ValidToken(t *testing.T) {
	secret := []byte("test-secret-key-32-characters-lo")
	sessionService := createTestSessionService(secret)
	userID := uuid.New()
	token := createTestToken(secret, userID, time.Now().Add(15*time.Minute))

	handler := Auth(sessionService)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		extractedID, ok := GetUserID(r.Context())
		if !ok {
			t.Error("User ID should be in context")
		}
		if extractedID != userID {
			t.Errorf("User ID mismatch: got %s, want %s", extractedID, userID)
		}
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("Status code = %d, want %d", rec.Code, http.StatusOK)
	}
}

func TestAuth_MissingHeader(t *testing.T) {
	secret := []byte("test-secret-key-32-characters-lo")
	sessionService := createTestSessionService(secret)

	handler := Auth(sessionService)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("Handler should not be called")
	}))

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("Status code = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
}

func TestAuth_InvalidHeaderFormat(t *testing.T) {
	secret := []byte("test-secret-key-32-characters-lo")
	sessionService := createTestSessionService(secret)

	handler := Auth(sessionService)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("Handler should not be called")
	}))

	invalidHeaders := []string{
		"InvalidFormat",
		"Basic token",
		"Bearer",
		"bearer token extra",
	}

	for _, header := range invalidHeaders {
		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		req.Header.Set("Authorization", header)
		rec := httptest.NewRecorder()

		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusUnauthorized {
			t.Errorf("Header %q: Status code = %d, want %d", header, rec.Code, http.StatusUnauthorized)
		}
	}
}

func TestAuth_ExpiredToken(t *testing.T) {
	secret := []byte("test-secret-key-32-characters-lo")
	sessionService := createTestSessionService(secret)
	userID := uuid.New()
	token := createTestToken(secret, userID, time.Now().Add(-1*time.Hour)) // Expired

	handler := Auth(sessionService)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("Handler should not be called")
	}))

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("Status code = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
}

func TestAuth_WrongSecret(t *testing.T) {
	secret := []byte("test-secret-key-32-characters-lo")
	wrongSecret := []byte("wrong-secret-key-32-characters!!")
	sessionService := createTestSessionService(secret)
	userID := uuid.New()
	token := createTestToken(wrongSecret, userID, time.Now().Add(15*time.Minute))

	handler := Auth(sessionService)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("Handler should not be called")
	}))

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("Status code = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
}

func TestAuth_BearerCaseInsensitive(t *testing.T) {
	secret := []byte("test-secret-key-32-characters-lo")
	sessionService := createTestSessionService(secret)
	userID := uuid.New()
	token := createTestToken(secret, userID, time.Now().Add(15*time.Minute))

	handler := Auth(sessionService)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// Test different cases of "Bearer"
	cases := []string{"Bearer", "bearer", "BEARER", "BeArEr"}

	for _, prefix := range cases {
		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		req.Header.Set("Authorization", prefix+" "+token)
		rec := httptest.NewRecorder()

		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Errorf("Prefix %q: Status code = %d, want %d", prefix, rec.Code, http.StatusOK)
		}
	}
}

func TestGetUserID(t *testing.T) {
	userID := uuid.New()

	// With user ID in context
	ctx := context.WithValue(context.Background(), UserIDKey, userID)
	extractedID, ok := GetUserID(ctx)
	if !ok {
		t.Error("GetUserID should return true when user ID is in context")
	}
	if extractedID != userID {
		t.Errorf("User ID mismatch: got %s, want %s", extractedID, userID)
	}

	// Without user ID in context
	_, ok = GetUserID(context.Background())
	if ok {
		t.Error("GetUserID should return false when user ID is not in context")
	}
}

func TestGetClaims(t *testing.T) {
	claims := &auth.AccessTokenClaims{
		Email: "test@example.com",
	}

	// With claims in context
	ctx := context.WithValue(context.Background(), ClaimsKey, claims)
	extractedClaims, ok := GetClaims(ctx)
	if !ok {
		t.Error("GetClaims should return true when claims are in context")
	}
	if extractedClaims.Email != claims.Email {
		t.Errorf("Email mismatch: got %s, want %s", extractedClaims.Email, claims.Email)
	}

	// Without claims in context
	_, ok = GetClaims(context.Background())
	if ok {
		t.Error("GetClaims should return false when claims are not in context")
	}
}
