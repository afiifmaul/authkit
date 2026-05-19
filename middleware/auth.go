// Package middleware provides HTTP middleware for authentication,
// including JWT token validation for net/http handlers.
//
// The middleware extracts the JWT token from the Authorization header,
// validates it using the provided jwt.Manager, and stores the claims
// in the request context for downstream handlers.
//
// Example:
//
//	manager := jwt.New("secret")
//
//	mux := http.NewServeMux()
//	mux.Handle("/protected", middleware.RequireAuth(manager)(protectedHandler))
//
//	http.ListenAndServe(":8080", mux)
package middleware

import (
	"net/http"
	"strings"

	authctx "github.com/afiifnajmi/authkit/context"
	"github.com/afiifnajmi/authkit/jwt"
)

// RequireAuth returns an HTTP middleware that validates JWT tokens.
// It extracts the token from the "Authorization: Bearer <token>" header,
// validates it using the provided jwt.Manager, and stores the parsed claims
// in the request context.
//
// If the token is missing, malformed, or invalid, the middleware responds
// with HTTP 401 Unauthorized and does not call the next handler.
//
// Usage with net/http:
//
//	protected := middleware.RequireAuth(manager)(myHandler)
//
// Usage as a chain:
//
//	http.Handle("/api/profile", middleware.RequireAuth(manager)(profileHandler))
func RequireAuth(manager *jwt.Manager) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Extract the Authorization header.
			authHeader := r.Header.Get("Authorization")
			if authHeader == "" {
				http.Error(w, `{"error":"missing authorization header"}`, http.StatusUnauthorized)
				return
			}

			// Expect "Bearer <token>" format.
			parts := strings.SplitN(authHeader, " ", 2)
			if len(parts) != 2 || !strings.EqualFold(parts[0], "bearer") {
				http.Error(w, `{"error":"invalid authorization header format"}`, http.StatusUnauthorized)
				return
			}

			tokenString := parts[1]

			// Validate the token.
			claims, err := manager.ValidateToken(tokenString)
			if err != nil {
				http.Error(w, `{"error":"invalid or expired token"}`, http.StatusUnauthorized)
				return
			}

			// Store claims in context and call the next handler.
			ctx := authctx.SetUser(r.Context(), claims)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// RequireRole returns an HTTP middleware that checks if the authenticated user
// has one of the allowed roles. This middleware should be used after RequireAuth.
//
// If the user does not have any of the allowed roles, it responds with
// HTTP 403 Forbidden.
//
// Usage:
//
//	adminOnly := middleware.RequireAuth(manager)(
//	    middleware.RequireRole("admin")(adminHandler),
//	)
func RequireRole(roles ...string) func(http.Handler) http.Handler {
	roleSet := make(map[string]struct{}, len(roles))
	for _, r := range roles {
		roleSet[r] = struct{}{}
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			claims, ok := authctx.GetUser(r.Context())
			if !ok {
				http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
				return
			}

			if _, allowed := roleSet[claims.Role]; !allowed {
				http.Error(w, `{"error":"forbidden: insufficient role"}`, http.StatusForbidden)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}
