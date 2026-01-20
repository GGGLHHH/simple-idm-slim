package session

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/tendant/simple-idm-slim/internal/auth"
	"github.com/tendant/simple-idm-slim/internal/domain"
	"github.com/tendant/simple-idm-slim/internal/http/middleware"
	"github.com/tendant/simple-idm-slim/internal/httputil"
)

// Handler handles session endpoints.
type Handler struct {
	sessionService *auth.SessionService
}

// NewHandler creates a new session handler.
func NewHandler(sessionService *auth.SessionService) *Handler {
	return &Handler{
		sessionService: sessionService,
	}
}

// RefreshRequest represents a token refresh request.
type RefreshRequest struct {
	RefreshToken string `json:"refresh_token"`
}

// TokenResponse represents a token response.
type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
}

// LogoutRequest represents a logout request.
type LogoutRequest struct {
	RefreshToken string `json:"refresh_token"`
}

// Refresh refreshes an access token.
// POST /v1/auth/refresh
func (h *Handler) Refresh(w http.ResponseWriter, r *http.Request) {
	var req RefreshRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httputil.Error(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.RefreshToken == "" {
		httputil.Error(w, http.StatusBadRequest, "refresh_token is required")
		return
	}

	opts := auth.IssueSessionOpts{
		IP:        r.RemoteAddr,
		UserAgent: r.UserAgent(),
	}

	tokens, err := h.sessionService.RefreshSession(r.Context(), req.RefreshToken, opts)
	if err != nil {
		if errors.Is(err, domain.ErrSessionNotFound) ||
			errors.Is(err, domain.ErrSessionExpired) ||
			errors.Is(err, domain.ErrSessionRevoked) {
			httputil.Error(w, http.StatusUnauthorized, "invalid or expired refresh token")
			return
		}
		httputil.Error(w, http.StatusInternalServerError, "failed to refresh token")
		return
	}

	httputil.JSON(w, http.StatusOK, TokenResponse{
		AccessToken:  tokens.AccessToken,
		RefreshToken: tokens.RefreshToken,
		TokenType:    tokens.TokenType,
		ExpiresIn:    tokens.ExpiresIn,
	})
}

// Logout revokes a session.
// POST /v1/auth/logout
func (h *Handler) Logout(w http.ResponseWriter, r *http.Request) {
	var req LogoutRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httputil.Error(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.RefreshToken == "" {
		httputil.Error(w, http.StatusBadRequest, "refresh_token is required")
		return
	}

	if err := h.sessionService.RevokeSession(r.Context(), req.RefreshToken); err != nil {
		// Don't reveal if token was not found - still return success
		// This prevents enumeration attacks
	}

	w.WriteHeader(http.StatusNoContent)
}

// LogoutAll revokes all sessions for the current user.
// POST /v1/auth/logout/all
// Requires authentication
func (h *Handler) LogoutAll(w http.ResponseWriter, r *http.Request) {
	userID, ok := middleware.GetUserID(r.Context())
	if !ok {
		httputil.Error(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	if err := h.sessionService.RevokeAllSessions(r.Context(), userID); err != nil {
		httputil.Error(w, http.StatusInternalServerError, "failed to logout all sessions")
		return
	}

	w.WriteHeader(http.StatusNoContent)
}
