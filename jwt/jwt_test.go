package jwt

import (
	"strings"
	"testing"
	"time"
)

const testSecret = "test-secret-key-for-unit-testing"

func TestNew(t *testing.T) {
	t.Run("creates manager with default expiry", func(t *testing.T) {
		m := New(testSecret)

		if m == nil {
			t.Fatal("expected non-nil manager")
		}

		if m.accessTokenExpiry != DefaultAccessTokenExpiry {
			t.Fatalf("expected access expiry %v, got %v", DefaultAccessTokenExpiry, m.accessTokenExpiry)
		}

		if m.refreshTokenExpiry != DefaultRefreshTokenExpiry {
			t.Fatalf("expected refresh expiry %v, got %v", DefaultRefreshTokenExpiry, m.refreshTokenExpiry)
		}
	})

	t.Run("creates manager with custom expiry", func(t *testing.T) {
		accessExp := 30 * time.Minute
		refreshExp := 14 * 24 * time.Hour

		m := New(testSecret,
			WithAccessTokenExpiry(accessExp),
			WithRefreshTokenExpiry(refreshExp),
		)

		if m.accessTokenExpiry != accessExp {
			t.Fatalf("expected access expiry %v, got %v", accessExp, m.accessTokenExpiry)
		}

		if m.refreshTokenExpiry != refreshExp {
			t.Fatalf("expected refresh expiry %v, got %v", refreshExp, m.refreshTokenExpiry)
		}
	})

	t.Run("panics on empty secret", func(t *testing.T) {
		defer func() {
			r := recover()
			if r == nil {
				t.Fatal("expected panic for empty secret")
			}

			msg, ok := r.(string)
			if !ok || !strings.Contains(msg, "must not be empty") {
				t.Fatalf("unexpected panic message: %v", r)
			}
		}()

		New("")
	})
}

func TestGenerateAccessToken(t *testing.T) {
	m := New(testSecret)

	t.Run("generates valid access token", func(t *testing.T) {
		token, err := m.GenerateAccessToken(1, "admin")
		if err != nil {
			t.Fatalf("expected no error, got: %v", err)
		}

		if token == "" {
			t.Fatal("expected non-empty token")
		}

		// JWT tokens have 3 parts separated by dots
		parts := strings.Split(token, ".")
		if len(parts) != 3 {
			t.Fatalf("expected 3 JWT parts, got %d", len(parts))
		}
	})

	t.Run("access token contains correct claims", func(t *testing.T) {
		token, err := m.GenerateAccessToken(42, "editor")
		if err != nil {
			t.Fatalf("expected no error, got: %v", err)
		}

		claims, err := m.ValidateToken(token)
		if err != nil {
			t.Fatalf("expected valid token, got: %v", err)
		}

		if claims.UserID != 42 {
			t.Fatalf("expected UserID 42, got %d", claims.UserID)
		}

		if claims.Role != "editor" {
			t.Fatalf("expected Role 'editor', got '%s'", claims.Role)
		}

		if claims.Type != TokenTypeAccess {
			t.Fatalf("expected Type '%s', got '%s'", TokenTypeAccess, claims.Type)
		}
	})

	t.Run("generates different tokens for different users", func(t *testing.T) {
		token1, _ := m.GenerateAccessToken(1, "admin")
		token2, _ := m.GenerateAccessToken(2, "user")

		if token1 == token2 {
			t.Fatal("expected different tokens for different users")
		}
	})
}

func TestGenerateRefreshToken(t *testing.T) {
	m := New(testSecret)

	t.Run("generates valid refresh token", func(t *testing.T) {
		token, err := m.GenerateRefreshToken(1)
		if err != nil {
			t.Fatalf("expected no error, got: %v", err)
		}

		if token == "" {
			t.Fatal("expected non-empty token")
		}
	})

	t.Run("refresh token has correct type and no role", func(t *testing.T) {
		token, err := m.GenerateRefreshToken(42)
		if err != nil {
			t.Fatalf("expected no error, got: %v", err)
		}

		claims, err := m.ValidateToken(token)
		if err != nil {
			t.Fatalf("expected valid token, got: %v", err)
		}

		if claims.UserID != 42 {
			t.Fatalf("expected UserID 42, got %d", claims.UserID)
		}

		if claims.Role != "" {
			t.Fatalf("expected empty role for refresh token, got '%s'", claims.Role)
		}

		if claims.Type != TokenTypeRefresh {
			t.Fatalf("expected Type '%s', got '%s'", TokenTypeRefresh, claims.Type)
		}
	})
}

func TestValidateToken(t *testing.T) {
	m := New(testSecret)

	t.Run("validates a correct token", func(t *testing.T) {
		token, _ := m.GenerateAccessToken(1, "admin")

		claims, err := m.ValidateToken(token)
		if err != nil {
			t.Fatalf("expected no error, got: %v", err)
		}

		if claims.UserID != 1 {
			t.Fatalf("expected UserID 1, got %d", claims.UserID)
		}
	})

	t.Run("rejects empty token", func(t *testing.T) {
		_, err := m.ValidateToken("")
		if err == nil {
			t.Fatal("expected error for empty token")
		}

		if !strings.Contains(err.Error(), "must not be empty") {
			t.Fatalf("expected empty token error, got: %v", err)
		}
	})

	t.Run("rejects token with wrong secret", func(t *testing.T) {
		m1 := New("secret-one")
		m2 := New("secret-two")

		token, _ := m1.GenerateAccessToken(1, "admin")

		_, err := m2.ValidateToken(token)
		if err == nil {
			t.Fatal("expected error for wrong secret")
		}

		if !strings.Contains(err.Error(), "invalid token") {
			t.Fatalf("expected invalid token error, got: %v", err)
		}
	})

	t.Run("rejects expired token", func(t *testing.T) {
		// Create a manager with a very short expiry.
		// JWT NumericDate uses Unix seconds, so minimum meaningful expiry is 1s.
		shortM := New(testSecret, WithAccessTokenExpiry(1*time.Second))

		token, _ := shortM.GenerateAccessToken(1, "admin")

		// Wait for the token to expire
		time.Sleep(2 * time.Second)

		_, err := shortM.ValidateToken(token)
		if err == nil {
			t.Fatal("expected error for expired token")
		}

		if !strings.Contains(err.Error(), "invalid token") {
			t.Fatalf("expected invalid/expired token error, got: %v", err)
		}
	})

	t.Run("rejects malformed token", func(t *testing.T) {
		_, err := m.ValidateToken("not.a.valid-jwt")
		if err == nil {
			t.Fatal("expected error for malformed token")
		}
	})

	t.Run("rejects tampered token", func(t *testing.T) {
		token, _ := m.GenerateAccessToken(1, "admin")

		// Tamper with the token payload
		parts := strings.Split(token, ".")
		parts[1] = parts[1] + "tampered"
		tampered := strings.Join(parts, ".")

		_, err := m.ValidateToken(tampered)
		if err == nil {
			t.Fatal("expected error for tampered token")
		}
	})
}

func TestTokenExpiryClaims(t *testing.T) {
	m := New(testSecret)

	t.Run("access token has correct expiry window", func(t *testing.T) {
		// JWT NumericDate truncates to seconds, so we use second-level precision.
		before := time.Now().Truncate(time.Second)
		token, _ := m.GenerateAccessToken(1, "admin")
		after := time.Now().Truncate(time.Second).Add(time.Second) // +1s buffer

		claims, err := m.ValidateToken(token)
		if err != nil {
			t.Fatalf("expected valid token, got: %v", err)
		}

		expiresAt := claims.ExpiresAt.Time
		expectedEarliest := before.Add(DefaultAccessTokenExpiry)
		expectedLatest := after.Add(DefaultAccessTokenExpiry)

		if expiresAt.Before(expectedEarliest) || expiresAt.After(expectedLatest) {
			t.Fatalf("expiry %v not in expected range [%v, %v]", expiresAt, expectedEarliest, expectedLatest)
		}
	})

	t.Run("refresh token has correct expiry window", func(t *testing.T) {
		before := time.Now().Truncate(time.Second)
		token, _ := m.GenerateRefreshToken(1)
		after := time.Now().Truncate(time.Second).Add(time.Second)

		claims, err := m.ValidateToken(token)
		if err != nil {
			t.Fatalf("expected valid token, got: %v", err)
		}

		expiresAt := claims.ExpiresAt.Time
		expectedEarliest := before.Add(DefaultRefreshTokenExpiry)
		expectedLatest := after.Add(DefaultRefreshTokenExpiry)

		if expiresAt.Before(expectedEarliest) || expiresAt.After(expectedLatest) {
			t.Fatalf("expiry %v not in expected range [%v, %v]", expiresAt, expectedEarliest, expectedLatest)
		}
	})
}
