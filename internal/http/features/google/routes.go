package google

import (
	"net/http"
)

// RegisterRoutes registers Google OAuth routes.
func (h *Handler) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /v1/auth/google/start", h.Start)
	mux.HandleFunc("GET /v1/auth/google/callback", h.Callback)
}
