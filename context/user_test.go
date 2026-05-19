package authctx

import (
	"context"
	"testing"

	"github.com/afiifmaul/authkit/jwt"
)

func TestSetUser(t *testing.T) {
	t.Run("stores claims in context", func(t *testing.T) {
		ctx := context.Background()
		claims := &jwt.Claims{
			UserID: 42,
			Role:   "admin",
			Type:   jwt.TokenTypeAccess,
		}

		ctx = SetUser(ctx, claims)

		// Verify the value is stored
		val := ctx.Value(userKey)
		if val == nil {
			t.Fatal("expected claims to be stored in context")
		}

		stored, ok := val.(*jwt.Claims)
		if !ok {
			t.Fatal("expected stored value to be *jwt.Claims")
		}

		if stored.UserID != 42 {
			t.Fatalf("expected UserID 42, got %d", stored.UserID)
		}
	})
}

func TestGetUser(t *testing.T) {
	t.Run("retrieves claims from context", func(t *testing.T) {
		ctx := context.Background()
		claims := &jwt.Claims{
			UserID: 99,
			Role:   "editor",
			Type:   jwt.TokenTypeAccess,
		}

		ctx = SetUser(ctx, claims)

		got, ok := GetUser(ctx)
		if !ok {
			t.Fatal("expected to find claims in context")
		}

		if got.UserID != 99 {
			t.Fatalf("expected UserID 99, got %d", got.UserID)
		}

		if got.Role != "editor" {
			t.Fatalf("expected Role 'editor', got '%s'", got.Role)
		}
	})

	t.Run("returns false for empty context", func(t *testing.T) {
		ctx := context.Background()

		claims, ok := GetUser(ctx)
		if ok {
			t.Fatal("expected ok to be false for empty context")
		}

		if claims != nil {
			t.Fatal("expected nil claims for empty context")
		}
	})

	t.Run("returns false for context with wrong type", func(t *testing.T) {
		ctx := context.WithValue(context.Background(), userKey, "not-claims")

		claims, ok := GetUser(ctx)
		if ok {
			t.Fatal("expected ok to be false for wrong type")
		}

		if claims != nil {
			t.Fatal("expected nil claims for wrong type")
		}
	})

	t.Run("preserves claims across context chain", func(t *testing.T) {
		ctx := context.Background()
		claims := &jwt.Claims{
			UserID: 1,
			Role:   "admin",
		}

		ctx = SetUser(ctx, claims)

		// Create a derived context (simulates what net/http does)
		derivedCtx := context.WithValue(ctx, struct{ name string }{"other"}, "value")

		got, ok := GetUser(derivedCtx)
		if !ok {
			t.Fatal("expected claims to persist in derived context")
		}

		if got.UserID != 1 {
			t.Fatalf("expected UserID 1, got %d", got.UserID)
		}
	})
}

func TestSetAndGetUserRoundTrip(t *testing.T) {
	claims := &jwt.Claims{
		UserID: 123,
		Role:   "superadmin",
		Type:   jwt.TokenTypeAccess,
	}

	ctx := SetUser(context.Background(), claims)
	got, ok := GetUser(ctx)

	if !ok {
		t.Fatal("expected round-trip to succeed")
	}

	if got != claims {
		t.Fatal("expected same pointer to be returned")
	}
}
