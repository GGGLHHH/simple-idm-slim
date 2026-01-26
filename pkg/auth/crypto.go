package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"strings"
)

// randomBytes fills the slice with cryptographically secure random bytes.
func randomBytes(b []byte) (int, error) {
	return rand.Read(b)
}

// GenerateToken generates a cryptographically secure random token.
func GenerateToken(length int) (string, error) {
	b := make([]byte, length)
	if _, err := randomBytes(b); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(b), nil
}

// HashToken creates a SHA-256 hash of a token for storage.
func HashToken(token string) string {
	h := sha256.Sum256([]byte(token))
	return base64.URLEncoding.EncodeToString(h[:])
}

// constantTimeCompare compares two byte slices in constant time.
func constantTimeCompare(a, b []byte) bool {
	return subtle.ConstantTimeCompare(a, b) == 1
}

// encodeArgon2Hash encodes Argon2 hash parameters in PHC format.
func encodeArgon2Hash(hash, salt []byte, time, memory uint32, threads uint8) string {
	b64Salt := base64.RawStdEncoding.EncodeToString(salt)
	b64Hash := base64.RawStdEncoding.EncodeToString(hash)
	return fmt.Sprintf("$argon2id$v=19$m=%d,t=%d,p=%d$%s$%s",
		memory, time, threads, b64Salt, b64Hash)
}

// decodeArgon2Hash decodes an Argon2 hash in PHC format.
func decodeArgon2Hash(encoded string) (hash, salt []byte, time, memory uint32, threads uint8, err error) {
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 {
		err = fmt.Errorf("invalid hash format")
		return
	}

	if parts[1] != "argon2id" {
		err = fmt.Errorf("unsupported hash type: %s", parts[1])
		return
	}

	var version int
	_, err = fmt.Sscanf(parts[2], "v=%d", &version)
	if err != nil {
		return
	}
	if version != 19 {
		err = fmt.Errorf("unsupported argon2 version: %d", version)
		return
	}

	_, err = fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &memory, &time, &threads)
	if err != nil {
		return
	}

	salt, err = base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return
	}

	hash, err = base64.RawStdEncoding.DecodeString(parts[5])
	return
}
