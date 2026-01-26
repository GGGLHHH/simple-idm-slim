package google

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"sync"
	"time"

	"github.com/tendant/simple-idm-slim/pkg/auth"
	"github.com/tendant/simple-idm-slim/internal/httputil"
)

// Handler handles Google OAuth endpoints.
type Handler struct {
	googleService  *auth.GoogleService
	sessionService *auth.SessionService
	stateStore     *StateStore
}

// NewHandler creates a new Google handler.
func NewHandler(googleService *auth.GoogleService, sessionService *auth.SessionService) *Handler {
	return &Handler{
		googleService:  googleService,
		sessionService: sessionService,
		stateStore:     NewStateStore(),
	}
}

// StateStore stores OAuth state for CSRF protection.
// In production, use Redis or similar for distributed systems.
type StateStore struct {
	mu     sync.RWMutex
	states map[string]*auth.OAuthState
}

// NewStateStore creates a new state store.
func NewStateStore() *StateStore {
	s := &StateStore{
		states: make(map[string]*auth.OAuthState),
	}
	// Start cleanup goroutine
	go s.cleanup()
	return s
}

func (s *StateStore) Set(state *auth.OAuthState) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.states[state.State] = state
}

func (s *StateStore) Get(state string) (*auth.OAuthState, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	st, ok := s.states[state]
	return st, ok
}

func (s *StateStore) Delete(state string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.states, state)
}

func (s *StateStore) cleanup() {
	ticker := time.NewTicker(5 * time.Minute)
	for range ticker.C {
		s.mu.Lock()
		now := time.Now()
		for key, state := range s.states {
			if now.After(state.ExpiresAt) {
				delete(s.states, key)
			}
		}
		s.mu.Unlock()
	}
}

// generateRandomString generates a cryptographically secure random string.
func generateRandomString(length int) string {
	b := make([]byte, length)
	rand.Read(b)
	return base64.URLEncoding.EncodeToString(b)
}

// Start initiates the Google OAuth flow.
// GET /v1/auth/google/start?redirect_uri=<app_return_uri>
func (h *Handler) Start(w http.ResponseWriter, r *http.Request) {
	redirectURI := r.URL.Query().Get("redirect_uri")
	if redirectURI == "" {
		redirectURI = "/"
	}

	// Generate state and nonce
	state := generateRandomString(32)
	nonce := generateRandomString(32)

	// Store state
	oauthState := &auth.OAuthState{
		State:       state,
		Nonce:       nonce,
		RedirectURI: redirectURI,
		ExpiresAt:   time.Now().Add(10 * time.Minute),
	}
	h.stateStore.Set(oauthState)

	// Generate auth URL and redirect
	authURL := h.googleService.GenerateAuthURL(state, nonce)
	http.Redirect(w, r, authURL, http.StatusFound)
}

// CallbackResponse represents a successful callback response.
type CallbackResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RedirectURI  string `json:"redirect_uri,omitempty"`
}

// Callback handles the Google OAuth callback.
// GET /v1/auth/google/callback?code=...&state=...
func (h *Handler) Callback(w http.ResponseWriter, r *http.Request) {
	code := r.URL.Query().Get("code")
	state := r.URL.Query().Get("state")
	errorParam := r.URL.Query().Get("error")

	// Check for OAuth error
	if errorParam != "" {
		httputil.Error(w, http.StatusBadRequest, errorParam)
		return
	}

	// Validate state
	oauthState, ok := h.stateStore.Get(state)
	if !ok {
		httputil.Error(w, http.StatusBadRequest, "invalid or expired state")
		return
	}
	h.stateStore.Delete(state)

	if time.Now().After(oauthState.ExpiresAt) {
		httputil.Error(w, http.StatusBadRequest, "state expired")
		return
	}

	// Exchange code for tokens
	tokenResp, err := h.googleService.ExchangeCode(r.Context(), code)
	if err != nil {
		httputil.Error(w, http.StatusInternalServerError, "failed to exchange code")
		return
	}

	// Validate ID token
	claims, err := h.googleService.ValidateIDToken(r.Context(), tokenResp.IDToken, oauthState.Nonce)
	if err != nil {
		httputil.Error(w, http.StatusUnauthorized, "invalid ID token")
		return
	}

	// Authenticate (find or create user)
	userID, err := h.googleService.Authenticate(r.Context(), claims)
	if err != nil {
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

	// Return tokens as JSON (or redirect with tokens in fragment/query for SPA)
	// For SPA, you might want to redirect to oauthState.RedirectURI with tokens
	httputil.JSON(w, http.StatusOK, CallbackResponse{
		AccessToken:  tokens.AccessToken,
		RefreshToken: tokens.RefreshToken,
		TokenType:    tokens.TokenType,
		ExpiresIn:    tokens.ExpiresIn,
		RedirectURI:  oauthState.RedirectURI,
	})
}

// CallbackHTML handles the callback and returns an HTML page that posts tokens to the parent window.
// This is useful for popup-based OAuth flows.
func (h *Handler) CallbackHTML(w http.ResponseWriter, r *http.Request) {
	code := r.URL.Query().Get("code")
	state := r.URL.Query().Get("state")
	errorParam := r.URL.Query().Get("error")

	// Check for OAuth error
	if errorParam != "" {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`<html><body><script>window.opener.postMessage({error:"` + errorParam + `"},"*");window.close();</script></body></html>`))
		return
	}

	// Validate state
	oauthState, ok := h.stateStore.Get(state)
	if !ok {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`<html><body><script>window.opener.postMessage({error:"invalid_state"},"*");window.close();</script></body></html>`))
		return
	}
	h.stateStore.Delete(state)

	// Exchange code for tokens
	tokenResp, err := h.googleService.ExchangeCode(r.Context(), code)
	if err != nil {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`<html><body><script>window.opener.postMessage({error:"token_exchange_failed"},"*");window.close();</script></body></html>`))
		return
	}

	// Validate ID token
	claims, err := h.googleService.ValidateIDToken(r.Context(), tokenResp.IDToken, oauthState.Nonce)
	if err != nil {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`<html><body><script>window.opener.postMessage({error:"invalid_token"},"*");window.close();</script></body></html>`))
		return
	}

	// Authenticate
	userID, err := h.googleService.Authenticate(r.Context(), claims)
	if err != nil {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`<html><body><script>window.opener.postMessage({error:"auth_failed"},"*");window.close();</script></body></html>`))
		return
	}

	// Issue session
	opts := auth.IssueSessionOpts{
		IP:        r.RemoteAddr,
		UserAgent: r.UserAgent(),
	}
	tokens, err := h.sessionService.IssueSession(r.Context(), userID, opts)
	if err != nil {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`<html><body><script>window.opener.postMessage({error:"session_failed"},"*");window.close();</script></body></html>`))
		return
	}

	// Return HTML that posts tokens to parent window
	tokenJSON, _ := json.Marshal(map[string]interface{}{
		"access_token":  tokens.AccessToken,
		"refresh_token": tokens.RefreshToken,
		"token_type":    tokens.TokenType,
		"expires_in":    tokens.ExpiresIn,
	})

	w.Header().Set("Content-Type", "text/html")
	w.Write([]byte(`<html><body><script>window.opener.postMessage(` + string(tokenJSON) + `,"*");window.close();</script></body></html>`))
}
