package httputil

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestJSON(t *testing.T) {
	tests := []struct {
		name         string
		status       int
		data         interface{}
		expectedBody string
	}{
		{
			name:         "simple object",
			status:       http.StatusOK,
			data:         map[string]string{"message": "hello"},
			expectedBody: `{"message":"hello"}`,
		},
		{
			name:         "nil data",
			status:       http.StatusNoContent,
			data:         nil,
			expectedBody: "",
		},
		{
			name:         "struct",
			status:       http.StatusCreated,
			data:         struct{ Name string }{"test"},
			expectedBody: `{"Name":"test"}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			JSON(rec, tt.status, tt.data)

			if rec.Code != tt.status {
				t.Errorf("Status code = %d, want %d", rec.Code, tt.status)
			}

			if tt.data != nil {
				contentType := rec.Header().Get("Content-Type")
				if contentType != "application/json" {
					t.Errorf("Content-Type = %q, want %q", contentType, "application/json")
				}
			}

			if tt.expectedBody != "" {
				var expected, actual interface{}
				json.Unmarshal([]byte(tt.expectedBody), &expected)
				json.Unmarshal(rec.Body.Bytes(), &actual)

				expectedJSON, _ := json.Marshal(expected)
				actualJSON, _ := json.Marshal(actual)

				if string(expectedJSON) != string(actualJSON) {
					t.Errorf("Body = %s, want %s", rec.Body.String(), tt.expectedBody)
				}
			}
		})
	}
}

func TestError(t *testing.T) {
	rec := httptest.NewRecorder()
	Error(rec, http.StatusBadRequest, "bad request")

	if rec.Code != http.StatusBadRequest {
		t.Errorf("Status code = %d, want %d", rec.Code, http.StatusBadRequest)
	}

	var response ErrorResponse
	json.NewDecoder(rec.Body).Decode(&response)

	if response.Error != "bad request" {
		t.Errorf("Error = %q, want %q", response.Error, "bad request")
	}
	if response.Message != "" {
		t.Errorf("Message should be empty, got %q", response.Message)
	}
}

func TestErrorWithMessage(t *testing.T) {
	rec := httptest.NewRecorder()
	ErrorWithMessage(rec, http.StatusUnauthorized, "unauthorized", "Please login first")

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("Status code = %d, want %d", rec.Code, http.StatusUnauthorized)
	}

	var response ErrorResponse
	json.NewDecoder(rec.Body).Decode(&response)

	if response.Error != "unauthorized" {
		t.Errorf("Error = %q, want %q", response.Error, "unauthorized")
	}
	if response.Message != "Please login first" {
		t.Errorf("Message = %q, want %q", response.Message, "Please login first")
	}
}

func TestErrorResponse_JSON(t *testing.T) {
	response := ErrorResponse{
		Error:   "test_error",
		Message: "Test message",
	}

	data, err := json.Marshal(response)
	if err != nil {
		t.Fatalf("Failed to marshal: %v", err)
	}

	var decoded ErrorResponse
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Failed to unmarshal: %v", err)
	}

	if decoded != response {
		t.Errorf("Mismatch: got %+v, want %+v", decoded, response)
	}
}
