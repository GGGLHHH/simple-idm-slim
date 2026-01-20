package me

import (
	"net/http"

	"github.com/tendant/simple-idm-slim/internal/auth"
	"github.com/tendant/simple-idm-slim/internal/http/middleware"
)

// RegisterRoutes registers me routes (all protected).
func (h *Handler) RegisterRoutes(mux *http.ServeMux, sessionService *auth.SessionService) {
	authMiddleware := middleware.Auth(sessionService)

	mux.Handle("GET /v1/me", authMiddleware(http.HandlerFunc(h.GetMe)))
	mux.Handle("PATCH /v1/me", authMiddleware(http.HandlerFunc(h.UpdateMe)))
}
