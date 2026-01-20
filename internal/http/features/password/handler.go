package password

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/tendant/simple-idm-slim/internal/auth"
	"github.com/tendant/simple-idm-slim/internal/domain"
	"github.com/tendant/simple-idm-slim/internal/httputil"
)

// Handler handles password authentication endpoints.
type Handler struct {
	passwordService *auth.PasswordService
	sessionService  *auth.SessionService
}

// NewHandler creates a new password handler.
func NewHandler(passwordService *auth.PasswordService, sessionService *auth.SessionService) *Handler {
	return &Handler{
		passwordService: passwordService,
		sessionService:  sessionService,
	}
}

// RegisterRequest represents a registration request.
type RegisterRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
	Name     string `json:"name"`
}

// LoginRequest represents a login request.
type LoginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

// TokenResponse represents a token response.
type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
}

// Register handles user registration.
// POST /v1/auth/password/register
func (h *Handler) Register(w http.ResponseWriter, r *http.Request) {
	var req RegisterRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httputil.Error(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.Email == "" || req.Password == "" {
		httputil.Error(w, http.StatusBadRequest, "email and password are required")
		return
	}

	// Basic password validation (in production, add more checks)
	if len(req.Password) < 8 {
		httputil.Error(w, http.StatusBadRequest, "password must be at least 8 characters")
		return
	}

	user, err := h.passwordService.Register(r.Context(), req.Email, req.Password, req.Name)
	if err != nil {
		if errors.Is(err, domain.ErrUserAlreadyExists) {
			httputil.Error(w, http.StatusConflict, "user already exists")
			return
		}
		httputil.Error(w, http.StatusInternalServerError, "registration failed")
		return
	}

	// Issue session for the new user
	opts := auth.IssueSessionOpts{
		IP:        r.RemoteAddr,
		UserAgent: r.UserAgent(),
	}
	tokens, err := h.sessionService.IssueSession(r.Context(), user.ID, opts)
	if err != nil {
		httputil.Error(w, http.StatusInternalServerError, "failed to issue session")
		return
	}

	httputil.JSON(w, http.StatusCreated, TokenResponse{
		AccessToken:  tokens.AccessToken,
		RefreshToken: tokens.RefreshToken,
		TokenType:    tokens.TokenType,
		ExpiresIn:    tokens.ExpiresIn,
	})
}

// Login handles user login.
// POST /v1/auth/password/login
func (h *Handler) Login(w http.ResponseWriter, r *http.Request) {
	var req LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httputil.Error(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.Email == "" || req.Password == "" {
		httputil.Error(w, http.StatusBadRequest, "email and password are required")
		return
	}

	userID, err := h.passwordService.Authenticate(r.Context(), req.Email, req.Password)
	if err != nil {
		if errors.Is(err, domain.ErrInvalidCredentials) {
			httputil.Error(w, http.StatusUnauthorized, "invalid email or password")
			return
		}
		httputil.Error(w, http.StatusInternalServerError, "authentication failed")
		return
	}

	// Issue session
	opts := auth.IssueSessionOpts{
		IP:        r.RemoteAddr,
		UserAgent: r.UserAgent(),
	}
	tokens, err := h.sessionService.IssueSession(r.Context(), userID, opts)
	if err != nil {
		httputil.Error(w, http.StatusInternalServerError, "failed to issue session")
		return
	}

	httputil.JSON(w, http.StatusOK, TokenResponse{
		AccessToken:  tokens.AccessToken,
		RefreshToken: tokens.RefreshToken,
		TokenType:    tokens.TokenType,
		ExpiresIn:    tokens.ExpiresIn,
	})
}
