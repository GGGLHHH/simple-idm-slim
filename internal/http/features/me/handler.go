package me

import (
	"encoding/json"
	"net/http"

	"github.com/tendant/simple-idm-slim/internal/domain"
	"github.com/tendant/simple-idm-slim/internal/http/middleware"
	"github.com/tendant/simple-idm-slim/internal/httputil"
	"github.com/tendant/simple-idm-slim/internal/repository"
)

// Handler handles user profile endpoints.
type Handler struct {
	users *repository.UsersRepository
}

// NewHandler creates a new me handler.
func NewHandler(users *repository.UsersRepository) *Handler {
	return &Handler{users: users}
}

// UserResponse represents the user profile response.
type UserResponse struct {
	ID            string  `json:"id"`
	Email         string  `json:"email"`
	EmailVerified bool    `json:"email_verified"`
	Name          *string `json:"name,omitempty"`
}

// UpdateRequest represents a profile update request.
type UpdateRequest struct {
	Name *string `json:"name,omitempty"`
}

// GetMe returns the current user's profile.
// GET /v1/me
func (h *Handler) GetMe(w http.ResponseWriter, r *http.Request) {
	userID, ok := middleware.GetUserID(r.Context())
	if !ok {
		httputil.Error(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	user, err := h.users.GetByID(r.Context(), userID)
	if err != nil {
		httputil.Error(w, http.StatusNotFound, "user not found")
		return
	}

	httputil.JSON(w, http.StatusOK, UserResponse{
		ID:            user.ID.String(),
		Email:         user.Email,
		EmailVerified: user.EmailVerified,
		Name:          user.Name,
	})
}

// UpdateMe updates the current user's profile.
// PATCH /v1/me
func (h *Handler) UpdateMe(w http.ResponseWriter, r *http.Request) {
	userID, ok := middleware.GetUserID(r.Context())
	if !ok {
		httputil.Error(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	var req UpdateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httputil.Error(w, http.StatusBadRequest, "invalid request body")
		return
	}

	user, err := h.users.GetByID(r.Context(), userID)
	if err != nil {
		httputil.Error(w, http.StatusNotFound, "user not found")
		return
	}

	// Update fields if provided
	if req.Name != nil {
		user.Name = req.Name
	}

	if err := h.users.Update(r.Context(), user); err != nil {
		if err == domain.ErrUserNotFound {
			httputil.Error(w, http.StatusNotFound, "user not found")
			return
		}
		httputil.Error(w, http.StatusInternalServerError, "failed to update profile")
		return
	}

	httputil.JSON(w, http.StatusOK, UserResponse{
		ID:            user.ID.String(),
		Email:         user.Email,
		EmailVerified: user.EmailVerified,
		Name:          user.Name,
	})
}
