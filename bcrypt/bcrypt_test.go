package bcrypt

import (
	"strings"
	"testing"

	"golang.org/x/crypto/bcrypt"
)

func TestHash(t *testing.T) {
	t.Run("successfully hashes a password", func(t *testing.T) {
		hash, err := Hash("my-secret-password")
		if err != nil {
			t.Fatalf("expected no error, got: %v", err)
		}

		if hash == "" {
			t.Fatal("expected non-empty hash")
		}

		// bcrypt hashes always start with "$2a$" or "$2b$"
		if !strings.HasPrefix(hash, "$2") {
			t.Fatalf("expected bcrypt hash prefix, got: %s", hash)
		}
	})

	t.Run("produces different hashes for the same password", func(t *testing.T) {
		hash1, err := Hash("same-password")
		if err != nil {
			t.Fatalf("expected no error, got: %v", err)
		}

		hash2, err := Hash("same-password")
		if err != nil {
			t.Fatalf("expected no error, got: %v", err)
		}

		if hash1 == hash2 {
			t.Fatal("expected different hashes for same password (due to random salt)")
		}
	})

	t.Run("returns error for empty password", func(t *testing.T) {
		_, err := Hash("")
		if err == nil {
			t.Fatal("expected error for empty password")
		}

		if !strings.Contains(err.Error(), "must not be empty") {
			t.Fatalf("expected empty password error, got: %v", err)
		}
	})
}

func TestHashWithCost(t *testing.T) {
	t.Run("hashes with custom cost", func(t *testing.T) {
		hash, err := HashWithCost("password", 10)
		if err != nil {
			t.Fatalf("expected no error, got: %v", err)
		}

		cost, err := bcrypt.Cost([]byte(hash))
		if err != nil {
			t.Fatalf("expected no error reading cost, got: %v", err)
		}

		if cost != 10 {
			t.Fatalf("expected cost 10, got: %d", cost)
		}
	})

	t.Run("returns error for empty password", func(t *testing.T) {
		_, err := HashWithCost("", 10)
		if err == nil {
			t.Fatal("expected error for empty password")
		}
	})

	t.Run("returns error for invalid cost too low", func(t *testing.T) {
		_, err := HashWithCost("password", bcrypt.MinCost-1)
		if err == nil {
			t.Fatal("expected error for cost below minimum")
		}

		if !strings.Contains(err.Error(), "cost must be between") {
			t.Fatalf("expected cost range error, got: %v", err)
		}
	})

	t.Run("returns error for invalid cost too high", func(t *testing.T) {
		_, err := HashWithCost("password", bcrypt.MaxCost+1)
		if err == nil {
			t.Fatal("expected error for cost above maximum")
		}
	})

	t.Run("accepts minimum cost", func(t *testing.T) {
		hash, err := HashWithCost("password", bcrypt.MinCost)
		if err != nil {
			t.Fatalf("expected no error, got: %v", err)
		}

		if hash == "" {
			t.Fatal("expected non-empty hash")
		}
	})
}

func TestVerify(t *testing.T) {
	t.Run("verifies correct password", func(t *testing.T) {
		password := "correct-password"
		hash, err := Hash(password)
		if err != nil {
			t.Fatalf("expected no error hashing, got: %v", err)
		}

		if err := Verify(hash, password); err != nil {
			t.Fatalf("expected password to match, got: %v", err)
		}
	})

	t.Run("rejects incorrect password", func(t *testing.T) {
		hash, err := Hash("correct-password")
		if err != nil {
			t.Fatalf("expected no error hashing, got: %v", err)
		}

		err = Verify(hash, "wrong-password")
		if err == nil {
			t.Fatal("expected error for wrong password")
		}

		if !strings.Contains(err.Error(), "does not match") {
			t.Fatalf("expected mismatch error, got: %v", err)
		}
	})

	t.Run("returns error for empty hash", func(t *testing.T) {
		err := Verify("", "password")
		if err == nil {
			t.Fatal("expected error for empty hash")
		}

		if !strings.Contains(err.Error(), "hash must not be empty") {
			t.Fatalf("expected empty hash error, got: %v", err)
		}
	})

	t.Run("returns error for empty password", func(t *testing.T) {
		hash, _ := Hash("some-password")
		err := Verify(hash, "")
		if err == nil {
			t.Fatal("expected error for empty password")
		}

		if !strings.Contains(err.Error(), "password must not be empty") {
			t.Fatalf("expected empty password error, got: %v", err)
		}
	})

	t.Run("returns error for invalid hash format", func(t *testing.T) {
		err := Verify("not-a-valid-hash", "password")
		if err == nil {
			t.Fatal("expected error for invalid hash")
		}
	})
}

// TestHashAndVerifyIntegration tests the full hash-then-verify workflow.
func TestHashAndVerifyIntegration(t *testing.T) {
	passwords := []string{
		"simple",
		"P@ssw0rd!123",
		"with spaces and symbols !@#$%^&*()",
		"日本語パスワード",
		strings.Repeat("a", 72), // bcrypt max length
	}

	for _, pw := range passwords {
		t.Run(pw[:min(len(pw), 20)], func(t *testing.T) {
			hash, err := Hash(pw)
			if err != nil {
				t.Fatalf("failed to hash: %v", err)
			}

			if err := Verify(hash, pw); err != nil {
				t.Fatalf("failed to verify: %v", err)
			}
		})
	}
}
