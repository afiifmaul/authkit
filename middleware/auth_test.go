package middleware

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	authctx "github.com/afiifnajmi/authkit/context"
	"github.com/afiifnajmi/authkit/jwt"
)

const testSecret = "middleware-test-secret"

// dummyHandler is a simple handler that returns 200 OK with user info from context.
func dummyHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		claims, ok := authctx.GetUser(r.Context())
		if !ok {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"user":"anonymous"}`))
			return
		}

		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"user_id":` + itoa(claims.UserID) + `,"role":"` + claims.Role + `"}`))
	})
}

// itoa is a simple uint to string conversion for tests.
func itoa(n uint) string {
	if n == 0 {
		return "0"
	}
	s := ""
	for n > 0 {
		s = string(rune('0'+n%10)) + s
		n /= 10
	}
	return s
}

func TestRequireAuth(t *testing.T) {
	manager := jwt.New(testSecret)
	handler := RequireAuth(manager)(dummyHandler())

	t.Run("allows valid token", func(t *testing.T) {
		token, err := manager.GenerateAccessToken(1, "admin")
		if err != nil {
			t.Fatalf("failed to generate token: %v", err)
		}

		req := httptest.NewRequest(http.MethodGet, "/protected", nil)
		req.Header.Set("Authorization", "Bearer "+token)

		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		res := rec.Result()
		defer res.Body.Close()

		if res.StatusCode != http.StatusOK {
			t.Fatalf("expected 200, got %d", res.StatusCode)
		}

		body, _ := io.ReadAll(res.Body)
		if !strings.Contains(string(body), `"user_id":1`) {
			t.Fatalf("expected user_id in response, got: %s", body)
		}
	})

	t.Run("rejects missing authorization header", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/protected", nil)
		rec := httptest.NewRecorder()

		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401, got %d", rec.Code)
		}

		body := rec.Body.String()
		if !strings.Contains(body, "missing authorization header") {
			t.Fatalf("expected missing header error, got: %s", body)
		}
	})

	t.Run("rejects invalid authorization format", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/protected", nil)
		req.Header.Set("Authorization", "InvalidFormat token123")

		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		// "InvalidFormat" is not "Bearer", so it should fail
		// Actually, we only check for "bearer" case-insensitively
		// so "InvalidFormat" should fail
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401, got %d", rec.Code)
		}
	})

	t.Run("rejects authorization without space", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/protected", nil)
		req.Header.Set("Authorization", "Bearertoken123")

		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401, got %d", rec.Code)
		}
	})

	t.Run("rejects invalid token", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/protected", nil)
		req.Header.Set("Authorization", "Bearer invalid.jwt.token")

		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401, got %d", rec.Code)
		}

		body := rec.Body.String()
		if !strings.Contains(body, "invalid or expired token") {
			t.Fatalf("expected invalid token error, got: %s", body)
		}
	})

	t.Run("rejects token signed with different secret", func(t *testing.T) {
		otherManager := jwt.New("different-secret")
		token, _ := otherManager.GenerateAccessToken(1, "admin")

		req := httptest.NewRequest(http.MethodGet, "/protected", nil)
		req.Header.Set("Authorization", "Bearer "+token)

		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401, got %d", rec.Code)
		}
	})

	t.Run("accepts case-insensitive Bearer prefix", func(t *testing.T) {
		token, _ := manager.GenerateAccessToken(1, "admin")

		req := httptest.NewRequest(http.MethodGet, "/protected", nil)
		req.Header.Set("Authorization", "bearer "+token)

		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("expected 200 for lowercase bearer, got %d", rec.Code)
		}
	})
}

func TestRequireRole(t *testing.T) {
	manager := jwt.New(testSecret)

	t.Run("allows user with matching role", func(t *testing.T) {
		token, _ := manager.GenerateAccessToken(1, "admin")

		handler := RequireAuth(manager)(RequireRole("admin", "superadmin")(dummyHandler()))

		req := httptest.NewRequest(http.MethodGet, "/admin", nil)
		req.Header.Set("Authorization", "Bearer "+token)

		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", rec.Code)
		}
	})

	t.Run("rejects user with non-matching role", func(t *testing.T) {
		token, _ := manager.GenerateAccessToken(1, "user")

		handler := RequireAuth(manager)(RequireRole("admin")(dummyHandler()))

		req := httptest.NewRequest(http.MethodGet, "/admin", nil)
		req.Header.Set("Authorization", "Bearer "+token)

		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusForbidden {
			t.Fatalf("expected 403, got %d", rec.Code)
		}

		body := rec.Body.String()
		if !strings.Contains(body, "forbidden") {
			t.Fatalf("expected forbidden error, got: %s", body)
		}
	})

	t.Run("rejects unauthenticated user", func(t *testing.T) {
		handler := RequireRole("admin")(dummyHandler())

		req := httptest.NewRequest(http.MethodGet, "/admin", nil)

		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401, got %d", rec.Code)
		}
	})
}
