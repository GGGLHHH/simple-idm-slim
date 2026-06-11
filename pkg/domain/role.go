package domain

import (
	"time"

	"github.com/google/uuid"
)

// Role represents a coarse, platform-level role label owned by the application.
// It answers "what kind of user is this on the platform" — not fine-grained
// business permissions.
type Role struct {
	ID        uuid.UUID
	Name      string
	CreatedAt time.Time
	UpdatedAt time.Time
}
