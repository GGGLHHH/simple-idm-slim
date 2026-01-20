package http

import (
	"log/slog"
	"net/http"

	"github.com/tendant/simple-idm-slim/internal/auth"
	"github.com/tendant/simple-idm-slim/internal/http/features/google"
	"github.com/tendant/simple-idm-slim/internal/http/features/me"
	"github.com/tendant/simple-idm-slim/internal/http/features/password"
	"github.com/tendant/simple-idm-slim/internal/http/features/session"
	"github.com/tendant/simple-idm-slim/internal/http/middleware"
	"github.com/tendant/simple-idm-slim/internal/httputil"
	"github.com/tendant/simple-idm-slim/internal/repository"
)

// RouterConfig holds configuration for the router.
type RouterConfig struct {
	Logger          *slog.Logger
	PasswordService *auth.PasswordService
	GoogleService   *auth.GoogleService
	SessionService  *auth.SessionService
	UsersRepo       *repository.UsersRepository
}

// NewRouter creates a new HTTP router with all routes registered.
func NewRouter(cfg RouterConfig) http.Handler {
	mux := http.NewServeMux()

	// Health check
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		httputil.JSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})

	// Register feature routes
	passwordHandler := password.NewHandler(cfg.PasswordService, cfg.SessionService)
	passwordHandler.RegisterRoutes(mux)

	if cfg.GoogleService != nil {
		googleHandler := google.NewHandler(cfg.GoogleService, cfg.SessionService)
		googleHandler.RegisterRoutes(mux)
	}

	sessionHandler := session.NewHandler(cfg.SessionService)
	sessionHandler.RegisterRoutes(mux, cfg.SessionService)

	meHandler := me.NewHandler(cfg.UsersRepo)
	meHandler.RegisterRoutes(mux, cfg.SessionService)

	// Apply global middleware
	var handler http.Handler = mux
	handler = middleware.Logging(cfg.Logger)(handler)
	handler = middleware.Recover(cfg.Logger)(handler)

	return handler
}
