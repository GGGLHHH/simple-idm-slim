package session

import (
	"net/http"

	"github.com/tendant/simple-idm-slim/internal/auth"
	"github.com/tendant/simple-idm-slim/internal/http/middleware"
)

// RegisterRoutes registers session routes.
func (h *Handler) RegisterRoutes(mux *http.ServeMux, sessionService *auth.SessionService) {
	// Public routes
	mux.HandleFunc("POST /v1/auth/refresh", h.Refresh)
	mux.HandleFunc("POST /v1/auth/logout", h.Logout)

	// Protected routes
	authMiddleware := middleware.Auth(sessionService)
	mux.Handle("POST /v1/auth/logout/all", authMiddleware(http.HandlerFunc(h.LogoutAll)))
}
