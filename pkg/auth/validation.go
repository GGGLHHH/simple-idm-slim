package auth

import (
	"strings"
)

// ValidateUsername is retained for backward compatibility.
// Username format policy is left to host applications.
func ValidateUsername(username string) error {
	return nil
}

// IsEmail checks if the identifier contains an @ symbol, indicating it's an email.
func IsEmail(identifier string) bool {
	return strings.Contains(identifier, "@")
}
