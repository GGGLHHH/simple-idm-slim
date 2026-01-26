package me

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/tendant/simple-idm-slim/pkg/domain"
	"github.com/tendant/simple-idm-slim/internal/http/middleware"
	"github.com/tendant/simple-idm-slim/internal/httputil"
)

// DeleteMe deletes the current user's account.
// DELETE /v1/me
// Requires password confirmation for security.
func (h *Handler) DeleteMe(w http.ResponseWriter, r *http.Request) {
	userID, ok := middleware.GetUserID(r.Context())
	if !ok {
		httputil.Error(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	var req DeleteAccountRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httputil.Error(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.Password == "" {
		httputil.Error(w, http.StatusBadRequest, "password is required to delete account")
		return
	}

	// Get user
	user, err := h.users.GetByID(r.Context(), userID)
	if err != nil {
		httputil.Error(w, http.StatusNotFound, "user not found")
		return
	}

	// Verify password for security
	if h.passwordService != nil {
		_, err := h.passwordService.Authenticate(r.Context(), user.Email, req.Password)
		if err != nil {
			if errors.Is(err, domain.ErrInvalidCredentials) {
				httputil.Error(w, http.StatusUnauthorized, "invalid password")
				return
			}
			h.logger.Error("failed to verify password for account deletion", "error", err, "user_id", userID)
			httputil.Error(w, http.StatusInternalServerError, "failed to verify password")
			return
		}
	}

	// Revoke all sessions
	if h.sessionService != nil {
		if err := h.sessionService.RevokeAllSessions(r.Context(), userID); err != nil {
			h.logger.Error("failed to revoke sessions during account deletion", "error", err, "user_id", userID)
			// Continue with deletion even if session revocation fails
		}
	}

	// Delete user (cascades to credentials, identities, sessions, verification tokens via DB constraints)
	if err := h.users.Delete(r.Context(), userID); err != nil {
		if err == domain.ErrUserNotFound {
			httputil.Error(w, http.StatusNotFound, "user not found")
			return
		}
		h.logger.Error("failed to delete user", "error", err, "user_id", userID)
		httputil.Error(w, http.StatusInternalServerError, "failed to delete account")
		return
	}

	h.logger.Info("account deleted", "user_id", userID, "email", user.Email)

	// Clear cookies if web client
	if !httputil.IsMobileClient(r) {
		httputil.ClearAuthCookies(w, httputil.DefaultCookieConfig())
	}

	w.WriteHeader(http.StatusNoContent)
}
