package domain

import (
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestSession_IsValid(t *testing.T) {
	tests := []struct {
		name     string
		session  Session
		expected bool
	}{
		{
			name: "valid session",
			session: Session{
				ID:        uuid.New(),
				UserID:    uuid.New(),
				ExpiresAt: time.Now().Add(1 * time.Hour),
				RevokedAt: nil,
			},
			expected: true,
		},
		{
			name: "expired session",
			session: Session{
				ID:        uuid.New(),
				UserID:    uuid.New(),
				ExpiresAt: time.Now().Add(-1 * time.Hour), // Expired
				RevokedAt: nil,
			},
			expected: false,
		},
		{
			name: "revoked session",
			session: Session{
				ID:        uuid.New(),
				UserID:    uuid.New(),
				ExpiresAt: time.Now().Add(1 * time.Hour),
				RevokedAt: func() *time.Time { t := time.Now(); return &t }(),
			},
			expected: false,
		},
		{
			name: "expired and revoked session",
			session: Session{
				ID:        uuid.New(),
				UserID:    uuid.New(),
				ExpiresAt: time.Now().Add(-1 * time.Hour),
				RevokedAt: func() *time.Time { t := time.Now(); return &t }(),
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.session.IsValid()
			if result != tt.expected {
				t.Errorf("IsValid() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestSession_IsValid_EdgeCases(t *testing.T) {
	// Session expiring exactly now should be invalid
	session := Session{
		ID:        uuid.New(),
		UserID:    uuid.New(),
		ExpiresAt: time.Now(),
		RevokedAt: nil,
	}

	// Give a tiny buffer for test execution
	time.Sleep(1 * time.Millisecond)

	if session.IsValid() {
		t.Error("Session expiring at current time should be invalid")
	}
}
