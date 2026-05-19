// Package bcrypt provides password hashing and verification
// using the bcrypt algorithm from golang.org/x/crypto/bcrypt.
//
// This package wraps the standard bcrypt functions with a simplified API
// suitable for common authentication use cases.
//
// Example:
//
//	hashed, err := bcrypt.Hash("my-secret-password")
//	if err != nil {
//	    log.Fatal(err)
//	}
//
//	if err := bcrypt.Verify(hashed, "my-secret-password"); err != nil {
//	    log.Fatal("password mismatch")
//	}
package bcrypt

import (
	"fmt"

	"golang.org/x/crypto/bcrypt"
)

// DefaultCost is the default bcrypt cost factor used for hashing.
// A cost of 12 provides a good balance between security and performance.
// Higher values increase computation time exponentially.
const DefaultCost = 12

// Hash takes a plaintext password and returns a bcrypt hashed string.
// It uses DefaultCost (12) as the cost factor.
//
// Returns an error if the password exceeds bcrypt's maximum length of 72 bytes
// or if hashing fails for any other reason.
func Hash(password string) (string, error) {
	if password == "" {
		return "", fmt.Errorf("bcrypt: password must not be empty")
	}

	bytes, err := bcrypt.GenerateFromPassword([]byte(password), DefaultCost)
	if err != nil {
		return "", fmt.Errorf("bcrypt: failed to hash password: %w", err)
	}

	return string(bytes), nil
}

// HashWithCost takes a plaintext password and a custom cost factor,
// then returns a bcrypt hashed string.
//
// The cost must be between bcrypt.MinCost (4) and bcrypt.MaxCost (31).
// For most applications, DefaultCost (12) is recommended.
//
// Returns an error if the password is empty, the cost is invalid,
// or hashing fails.
func HashWithCost(password string, cost int) (string, error) {
	if password == "" {
		return "", fmt.Errorf("bcrypt: password must not be empty")
	}

	if cost < bcrypt.MinCost || cost > bcrypt.MaxCost {
		return "", fmt.Errorf("bcrypt: cost must be between %d and %d", bcrypt.MinCost, bcrypt.MaxCost)
	}

	bytes, err := bcrypt.GenerateFromPassword([]byte(password), cost)
	if err != nil {
		return "", fmt.Errorf("bcrypt: failed to hash password: %w", err)
	}

	return string(bytes), nil
}

// Verify compares a bcrypt hashed password with a plaintext password.
// Returns nil if the password matches the hash, or an error otherwise.
//
// This function is safe against timing attacks as bcrypt.CompareHashAndPassword
// uses constant-time comparison internally.
func Verify(hash, password string) error {
	if hash == "" {
		return fmt.Errorf("bcrypt: hash must not be empty")
	}

	if password == "" {
		return fmt.Errorf("bcrypt: password must not be empty")
	}

	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	if err != nil {
		return fmt.Errorf("bcrypt: password does not match: %w", err)
	}

	return nil
}
