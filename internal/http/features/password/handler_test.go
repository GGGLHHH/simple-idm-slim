package password

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRegisterRequest_Validation(t *testing.T) {
	tests := []struct {
		name           string
		body           string
		expectedStatus int
		expectedError  string
	}{
		{
			name:           "empty body",
			body:           `{}`,
			expectedStatus: http.StatusBadRequest,
			expectedError:  "email and password are required",
		},
		{
			name:           "missing email",
			body:           `{"password": "password123", "name": "Test"}`,
			expectedStatus: http.StatusBadRequest,
			expectedError:  "email and password are required",
		},
		{
			name:           "missing password",
			body:           `{"email": "test@example.com", "name": "Test"}`,
			expectedStatus: http.StatusBadRequest,
			expectedError:  "email and password are required",
		},
		{
			name:           "invalid json",
			body:           `{invalid}`,
			expectedStatus: http.StatusBadRequest,
			expectedError:  "invalid request body",
		},
	}

	// Create a handler with nil services to test validation only
	// (will panic if validation passes, which is expected)
	handler := &Handler{
		passwordService: nil,
		sessionService:  nil,
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/v1/auth/password/register", bytes.NewBufferString(tt.body))
			req.Header.Set("Content-Type", "application/json")
			rec := httptest.NewRecorder()

			// Use recover to catch panic from nil service (means validation passed)
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("Validation should have failed before reaching service")
				}
			}()

			handler.Register(rec, req)

			if rec.Code != tt.expectedStatus {
				t.Errorf("Status code = %d, want %d", rec.Code, tt.expectedStatus)
			}

			var response map[string]string
			json.NewDecoder(rec.Body).Decode(&response)
			if response["error"] != tt.expectedError {
				t.Errorf("Error = %q, want %q", response["error"], tt.expectedError)
			}
		})
	}
}

func TestLoginRequest_Validation(t *testing.T) {
	tests := []struct {
		name           string
		body           string
		expectedStatus int
		expectedError  string
	}{
		{
			name:           "empty body",
			body:           `{}`,
			expectedStatus: http.StatusBadRequest,
			expectedError:  "email/username and password are required",
		},
		{
			name:           "missing identifier and email",
			body:           `{"password": "password123"}`,
			expectedStatus: http.StatusBadRequest,
			expectedError:  "email/username and password are required",
		},
		{
			name:           "missing password",
			body:           `{"email": "test@example.com"}`,
			expectedStatus: http.StatusBadRequest,
			expectedError:  "email/username and password are required",
		},
		{
			name:           "invalid json",
			body:           `{invalid}`,
			expectedStatus: http.StatusBadRequest,
			expectedError:  "invalid request body",
		},
	}

	handler := &Handler{
		passwordService: nil,
		sessionService:  nil,
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/v1/auth/password/login", bytes.NewBufferString(tt.body))
			req.Header.Set("Content-Type", "application/json")
			rec := httptest.NewRecorder()

			defer func() {
				if r := recover(); r != nil {
					t.Errorf("Validation should have failed before reaching service")
				}
			}()

			handler.Login(rec, req)

			if rec.Code != tt.expectedStatus {
				t.Errorf("Status code = %d, want %d", rec.Code, tt.expectedStatus)
			}

			var response map[string]string
			json.NewDecoder(rec.Body).Decode(&response)
			if response["error"] != tt.expectedError {
				t.Errorf("Error = %q, want %q", response["error"], tt.expectedError)
			}
		})
	}
}

func TestTokenResponse_JSON(t *testing.T) {
	response := TokenResponse{
		AccessToken:  "access-token",
		RefreshToken: "refresh-token",
		TokenType:    "Bearer",
		ExpiresIn:    900,
	}

	data, err := json.Marshal(response)
	if err != nil {
		t.Fatalf("Failed to marshal TokenResponse: %v", err)
	}

	var decoded TokenResponse
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Failed to unmarshal TokenResponse: %v", err)
	}

	if decoded.AccessToken != response.AccessToken {
		t.Errorf("AccessToken mismatch: got %s, want %s", decoded.AccessToken, response.AccessToken)
	}
	if decoded.RefreshToken != response.RefreshToken {
		t.Errorf("RefreshToken mismatch: got %s, want %s", decoded.RefreshToken, response.RefreshToken)
	}
	if decoded.TokenType != response.TokenType {
		t.Errorf("TokenType mismatch: got %s, want %s", decoded.TokenType, response.TokenType)
	}
	if decoded.ExpiresIn != response.ExpiresIn {
		t.Errorf("ExpiresIn mismatch: got %d, want %d", decoded.ExpiresIn, response.ExpiresIn)
	}
}
