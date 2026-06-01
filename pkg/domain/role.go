package domain

import (
	"time"

	"github.com/google/uuid"
)

// Role represents an application-owned role name.
type Role struct {
	ID        uuid.UUID
	Name      string
	CreatedAt time.Time
	UpdatedAt time.Time
}
