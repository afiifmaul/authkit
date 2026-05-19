package otp

import (
	"strings"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"
)

func TestGenerateSecret(t *testing.T) {
	t.Run("generates secret and QR URL", func(t *testing.T) {
		secret, qrURL, err := GenerateSecret("user@example.com")
		if err != nil {
			t.Fatalf("expected no error, got: %v", err)
		}

		if secret == "" {
			t.Fatal("expected non-empty secret")
		}

		if qrURL == "" {
			t.Fatal("expected non-empty QR URL")
		}

		// QR URL should be an otpauth:// URL
		if !strings.HasPrefix(qrURL, "otpauth://totp/") {
			t.Fatalf("expected otpauth URL, got: %s", qrURL)
		}

		// QR URL should contain the issuer
		if !strings.Contains(qrURL, DefaultIssuer) {
			t.Fatalf("expected QR URL to contain issuer '%s', got: %s", DefaultIssuer, qrURL)
		}

		// QR URL should contain the account name
		if !strings.Contains(qrURL, "user%40example.com") && !strings.Contains(qrURL, "user@example.com") {
			t.Fatalf("expected QR URL to contain account name, got: %s", qrURL)
		}
	})

	t.Run("generates unique secrets", func(t *testing.T) {
		secret1, _, err := GenerateSecret("user1@example.com")
		if err != nil {
			t.Fatalf("expected no error, got: %v", err)
		}

		secret2, _, err := GenerateSecret("user2@example.com")
		if err != nil {
			t.Fatalf("expected no error, got: %v", err)
		}

		if secret1 == secret2 {
			t.Fatal("expected different secrets for different accounts")
		}
	})

	t.Run("returns error for empty account name", func(t *testing.T) {
		_, _, err := GenerateSecret("")
		if err == nil {
			t.Fatal("expected error for empty account name")
		}

		if !strings.Contains(err.Error(), "account name must not be empty") {
			t.Fatalf("expected empty account name error, got: %v", err)
		}
	})
}

func TestGenerateSecretWithIssuer(t *testing.T) {
	t.Run("generates secret with custom issuer", func(t *testing.T) {
		secret, qrURL, err := GenerateSecretWithIssuer("user@example.com", "MyApp")
		if err != nil {
			t.Fatalf("expected no error, got: %v", err)
		}

		if secret == "" {
			t.Fatal("expected non-empty secret")
		}

		if !strings.Contains(qrURL, "MyApp") {
			t.Fatalf("expected QR URL to contain custom issuer 'MyApp', got: %s", qrURL)
		}
	})

	t.Run("returns error for empty account name", func(t *testing.T) {
		_, _, err := GenerateSecretWithIssuer("", "MyApp")
		if err == nil {
			t.Fatal("expected error for empty account name")
		}
	})

	t.Run("returns error for empty issuer", func(t *testing.T) {
		_, _, err := GenerateSecretWithIssuer("user@example.com", "")
		if err == nil {
			t.Fatal("expected error for empty issuer")
		}

		if !strings.Contains(err.Error(), "issuer must not be empty") {
			t.Fatalf("expected empty issuer error, got: %v", err)
		}
	})
}

func TestValidate(t *testing.T) {
	t.Run("validates correct code", func(t *testing.T) {
		secret, _, err := GenerateSecret("user@example.com")
		if err != nil {
			t.Fatalf("failed to generate secret: %v", err)
		}

		// Generate a valid code using the same library
		code, err := totp.GenerateCode(secret, time.Now())
		if err != nil {
			t.Fatalf("failed to generate code: %v", err)
		}

		if !Validate(secret, code) {
			t.Fatal("expected valid code to pass validation")
		}
	})

	t.Run("rejects invalid code", func(t *testing.T) {
		secret, _, err := GenerateSecret("user@example.com")
		if err != nil {
			t.Fatalf("failed to generate secret: %v", err)
		}

		if Validate(secret, "000000") {
			t.Fatal("expected invalid code to fail validation")
		}
	})

	t.Run("returns false for empty secret", func(t *testing.T) {
		if Validate("", "123456") {
			t.Fatal("expected false for empty secret")
		}
	})

	t.Run("returns false for empty code", func(t *testing.T) {
		if Validate("some-secret", "") {
			t.Fatal("expected false for empty code")
		}
	})
}
