package auth

import (
	"testing"
)

func TestHashPassword(t *testing.T) {
	password := "testpassword123"

	hash, err := HashPassword(password)
	if err != nil {
		t.Fatalf("HashPassword failed: %v", err)
	}

	// Check hash format (Argon2id PHC format)
	if len(hash) == 0 {
		t.Error("HashPassword returned empty hash")
	}

	// Hash should start with $argon2id$
	if hash[:10] != "$argon2id$" {
		t.Errorf("Hash should start with $argon2id$, got: %s", hash[:10])
	}
}

func TestHashPassword_DifferentSalts(t *testing.T) {
	password := "testpassword123"

	hash1, _ := HashPassword(password)
	hash2, _ := HashPassword(password)

	// Same password should produce different hashes (due to random salt)
	if hash1 == hash2 {
		t.Error("Same password should produce different hashes")
	}
}

func TestVerifyPassword(t *testing.T) {
	password := "testpassword123"

	hash, err := HashPassword(password)
	if err != nil {
		t.Fatalf("HashPassword failed: %v", err)
	}

	// Correct password should verify
	if !VerifyPassword(password, hash) {
		t.Error("VerifyPassword should return true for correct password")
	}

	// Wrong password should not verify
	if VerifyPassword("wrongpassword", hash) {
		t.Error("VerifyPassword should return false for wrong password")
	}
}

func TestVerifyPassword_InvalidHash(t *testing.T) {
	// Invalid hash format should return false
	if VerifyPassword("password", "invalid-hash") {
		t.Error("VerifyPassword should return false for invalid hash format")
	}

	// Empty hash should return false
	if VerifyPassword("password", "") {
		t.Error("VerifyPassword should return false for empty hash")
	}
}

func TestGenerateToken(t *testing.T) {
	token1, err := GenerateToken(32)
	if err != nil {
		t.Fatalf("GenerateToken failed: %v", err)
	}

	if len(token1) == 0 {
		t.Error("GenerateToken returned empty token")
	}

	// Generate another token - should be different
	token2, _ := GenerateToken(32)
	if token1 == token2 {
		t.Error("GenerateToken should produce unique tokens")
	}
}

func TestGenerateToken_DifferentLengths(t *testing.T) {
	tests := []struct {
		length      int
		minExpected int
	}{
		{16, 20}, // base64 encoding increases length
		{32, 40},
		{64, 80},
	}

	for _, tt := range tests {
		token, err := GenerateToken(tt.length)
		if err != nil {
			t.Errorf("GenerateToken(%d) failed: %v", tt.length, err)
		}
		if len(token) < tt.minExpected {
			t.Errorf("GenerateToken(%d) returned token too short: %d", tt.length, len(token))
		}
	}
}

func TestHashToken(t *testing.T) {
	token := "test-token-123"

	hash1 := HashToken(token)
	hash2 := HashToken(token)

	// Same token should produce same hash (deterministic)
	if hash1 != hash2 {
		t.Error("HashToken should be deterministic")
	}

	// Different tokens should produce different hashes
	hash3 := HashToken("different-token")
	if hash1 == hash3 {
		t.Error("Different tokens should produce different hashes")
	}
}

func TestEncodeDecodeArgon2Hash(t *testing.T) {
	originalHash := []byte("testhash12345678901234567890ab")
	originalSalt := []byte("testsalt12345678")
	time := uint32(1)
	memory := uint32(65536)
	threads := uint8(4)

	encoded := encodeArgon2Hash(originalHash, originalSalt, time, memory, threads)

	hash, salt, decodedTime, decodedMemory, decodedThreads, err := decodeArgon2Hash(encoded)
	if err != nil {
		t.Fatalf("decodeArgon2Hash failed: %v", err)
	}

	if string(hash) != string(originalHash) {
		t.Errorf("Hash mismatch: got %v, want %v", hash, originalHash)
	}
	if string(salt) != string(originalSalt) {
		t.Errorf("Salt mismatch: got %v, want %v", salt, originalSalt)
	}
	if decodedTime != time {
		t.Errorf("Time mismatch: got %d, want %d", decodedTime, time)
	}
	if decodedMemory != memory {
		t.Errorf("Memory mismatch: got %d, want %d", decodedMemory, memory)
	}
	if decodedThreads != threads {
		t.Errorf("Threads mismatch: got %d, want %d", decodedThreads, threads)
	}
}

func TestDecodeArgon2Hash_InvalidFormats(t *testing.T) {
	invalidHashes := []string{
		"",
		"invalid",
		"$argon2i$v=19$m=65536,t=1,p=4$salt$hash", // wrong type
		"$argon2id$v=18$m=65536,t=1,p=4$salt$hash", // wrong version
		"$argon2id$v=19$invalid$salt$hash",         // invalid params
	}

	for _, invalid := range invalidHashes {
		_, _, _, _, _, err := decodeArgon2Hash(invalid)
		if err == nil {
			t.Errorf("decodeArgon2Hash should fail for: %s", invalid)
		}
	}
}

func BenchmarkHashPassword(b *testing.B) {
	password := "testpassword123"
	for i := 0; i < b.N; i++ {
		HashPassword(password)
	}
}

func BenchmarkVerifyPassword(b *testing.B) {
	password := "testpassword123"
	hash, _ := HashPassword(password)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		VerifyPassword(password, hash)
	}
}
