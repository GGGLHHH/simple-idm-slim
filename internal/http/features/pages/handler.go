package pages

import (
	"html/template"
	"net/http"
	"path/filepath"
)

// Handler handles authentication page rendering.
type Handler struct {
	templates map[string]*template.Template
}

// NewHandler creates a new pages handler.
func NewHandler(templatesDir string) (*Handler, error) {
	templates := make(map[string]*template.Template)

	// List of page templates
	pages := []string{"register", "login", "verify-email", "reset-password", "reset-password-confirm", "request-verification"}

	layoutPath := filepath.Join(templatesDir, "layout.html")

	// Parse each page template with the layout
	for _, page := range pages {
		pagePath := filepath.Join(templatesDir, page+".html")
		tmpl, err := template.ParseFiles(layoutPath, pagePath)
		if err != nil {
			return nil, err
		}
		templates[page] = tmpl
	}

	return &Handler{
		templates: templates,
	}, nil
}

// PageData holds data for template rendering.
type PageData struct {
	Title string
}

// Register renders the registration page.
func (h *Handler) Register(w http.ResponseWriter, r *http.Request) {
	h.render(w, "register", PageData{Title: "Register"})
}

// Login renders the login page.
func (h *Handler) Login(w http.ResponseWriter, r *http.Request) {
	h.render(w, "login", PageData{Title: "Sign In"})
}

// VerifyEmail renders the email verification page.
func (h *Handler) VerifyEmail(w http.ResponseWriter, r *http.Request) {
	h.render(w, "verify-email", PageData{Title: "Verify Email"})
}

// ResetPassword renders the password reset request page.
func (h *Handler) ResetPassword(w http.ResponseWriter, r *http.Request) {
	h.render(w, "reset-password", PageData{Title: "Reset Password"})
}

// ResetPasswordConfirm renders the password reset confirmation page.
func (h *Handler) ResetPasswordConfirm(w http.ResponseWriter, r *http.Request) {
	h.render(w, "reset-password-confirm", PageData{Title: "Set New Password"})
}

// RequestVerification renders the request verification email page.
func (h *Handler) RequestVerification(w http.ResponseWriter, r *http.Request) {
	h.render(w, "request-verification", PageData{Title: "Resend Verification Email"})
}

func (h *Handler) render(w http.ResponseWriter, templateName string, data PageData) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	tmpl, ok := h.templates[templateName]
	if !ok {
		http.Error(w, "Template not found", http.StatusInternalServerError)
		return
	}

	// Execute the layout template (which includes the page content)
	if err := tmpl.ExecuteTemplate(w, "layout.html", data); err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
}
