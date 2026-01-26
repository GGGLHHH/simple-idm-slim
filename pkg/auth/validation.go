package auth

import (
	"regexp"
	"strings"

	"github.com/tendant/simple-idm-slim/pkg/domain"
)

var (
	// Username pattern: 3-30 chars, alphanumeric/underscore/hyphen, must start with alphanumeric
	usernamePattern = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_-]{2,29}$`)
)

// ValidateUsername validates username format.
// Returns domain.ErrInvalidUsername if invalid.
func ValidateUsername(username string) error {
	if username == "" {
		return domain.ErrInvalidUsername
	}

	if !usernamePattern.MatchString(username) {
		return domain.ErrInvalidUsername
	}

	return nil
}

// IsEmail checks if the identifier contains an @ symbol, indicating it's an email.
func IsEmail(identifier string) bool {
	return strings.Contains(identifier, "@")
}
