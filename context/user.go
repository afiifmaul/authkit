// Package authctx provides helper functions for storing and retrieving
// authenticated user claims from context.Context.
//
// This package is named authctx (instead of context) to avoid shadowing
// the standard library's context package.
//
// Example:
//
//	// In middleware: store claims in context
//	ctx := authctx.SetUser(r.Context(), claims)
//	r = r.WithContext(ctx)
//
//	// In handler: retrieve claims from context
//	claims, ok := authctx.GetUser(r.Context())
//	if !ok {
//	    http.Error(w, "unauthorized", http.StatusUnauthorized)
//	    return
//	}
//	fmt.Println("UserID:", claims.UserID)
package authctx

import (
	"context"

	"github.com/afiifnajmi/authkit/jwt"
)

// contextKey is an unexported type used as a context key to prevent
// collisions with keys from other packages.
type contextKey struct{}

// userKey is the context key for storing user claims.
var userKey = contextKey{}

// SetUser stores JWT claims in the given context.
// Returns a new context with the claims attached.
//
// This is typically called from authentication middleware after
// successfully validating a JWT token.
func SetUser(ctx context.Context, claims *jwt.Claims) context.Context {
	return context.WithValue(ctx, userKey, claims)
}

// GetUser retrieves JWT claims from the given context.
// Returns the claims and true if found, or nil and false if the context
// does not contain user claims.
//
// This is typically called from HTTP handlers to access the authenticated
// user's information.
func GetUser(ctx context.Context) (*jwt.Claims, bool) {
	claims, ok := ctx.Value(userKey).(*jwt.Claims)
	return claims, ok
}
