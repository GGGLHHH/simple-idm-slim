package httputil

import (
	"encoding/json"
	"net/http"
)

// JSON writes a JSON response.
func JSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if data != nil {
		json.NewEncoder(w).Encode(data)
	}
}

// ErrorResponse represents an error response.
type ErrorResponse struct {
	Error   string `json:"error"`
	Message string `json:"message,omitempty"`
}

// Error writes a JSON error response.
func Error(w http.ResponseWriter, status int, err string) {
	JSON(w, status, ErrorResponse{Error: err})
}

// ErrorWithMessage writes a JSON error response with additional message.
func ErrorWithMessage(w http.ResponseWriter, status int, err, message string) {
	JSON(w, status, ErrorResponse{Error: err, Message: message})
}
