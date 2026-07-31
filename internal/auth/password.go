package auth

import (
	"fmt"

	"golang.org/x/crypto/bcrypt"
)

// bcryptCost controls how expensive hashing is. 12 is a solid default in
// 2026 — strong enough to resist offline brute force, cheap enough not to
// make every login noticeably slow.
const bcryptCost = 12

// HashPassword hashes a plaintext password using bcrypt.
func HashPassword(password string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcryptCost)
	if err != nil {
		return "", fmt.Errorf("auth: failed to hash password: %w", err)
	}
	return string(hash), nil
}

// VerifyPassword checks a plaintext password against a bcrypt hash. Returns
// nil if it matches, an error otherwise (including bcrypt.ErrMismatchedHashAndPassword).
func VerifyPassword(hash, password string) error {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
}
