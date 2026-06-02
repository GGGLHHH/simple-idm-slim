package auth

import (
	"testing"
)

func TestValidateUsername(t *testing.T) {
	tests := []struct {
		name     string
		username string
	}{
		{
			name:     "alphanumeric",
			username: "user123",
		},
		{
			name:     "with underscore",
			username: "user_name",
		},
		{
			name:     "with hyphen",
			username: "user-name",
		},
		{
			name:     "mixed punctuation",
			username: "user_123-abc",
		},
		{
			name:     "short value",
			username: "ab",
		},
		{
			name:     "empty string",
			username: "",
		},
		{
			name:     "starts with underscore",
			username: "_username",
		},
		{
			name:     "starts with hyphen",
			username: "-username",
		},
		{
			name:     "contains space",
			username: "user name",
		},
		{
			name:     "contains at sign",
			username: "user@name",
		},
		{
			name:     "contains dot",
			username: "user.name",
		},
		{
			name:     "contains special char",
			username: "user!name",
		},
		{
			name:     "unicode characters",
			username: "usér123",
		},
		{
			name:     "emoji",
			username: "user😀",
		},
		{
			name:     "long value",
			username: "abcdefghij1234567890abcdefghijk",
		},
		{
			name:     "minimum legacy valid length",
			username: "abc",
		},
		{
			name:     "maximum legacy valid length",
			username: "abcdefghij1234567890abcdefghij",
		},
		{
			name:     "starts with letter",
			username: "a12",
		},
		{
			name:     "starts with number",
			username: "1ab",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateUsername(tt.username)
			if err != nil {
				t.Errorf("ValidateUsername(%q) error = %v, want nil", tt.username, err)
			}
		})
	}
}

func TestIsEmail(t *testing.T) {
	tests := []struct {
		name       string
		identifier string
		want       bool
	}{
		{
			name:       "valid email",
			identifier: "user@example.com",
			want:       true,
		},
		{
			name:       "email with subdomain",
			identifier: "user@mail.example.com",
			want:       true,
		},
		{
			name:       "username without @",
			identifier: "username",
			want:       false,
		},
		{
			name:       "username with underscore",
			identifier: "user_name",
			want:       false,
		},
		{
			name:       "username with hyphen",
			identifier: "user-name",
			want:       false,
		},
		{
			name:       "empty string",
			identifier: "",
			want:       false,
		},
		{
			name:       "@ at start",
			identifier: "@username",
			want:       true,
		},
		{
			name:       "@ at end",
			identifier: "username@",
			want:       true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsEmail(tt.identifier); got != tt.want {
				t.Errorf("IsEmail(%q) = %v, want %v", tt.identifier, got, tt.want)
			}
		})
	}
}
