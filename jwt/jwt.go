// Package jwt provides JWT (JSON Web Token) generation and validation
// for access tokens and refresh tokens using the golang-jwt/jwt library.
//
// It supports configurable expiration durations and HMAC-SHA256 (HS256) signing.
//
// Example:
//
//	manager := jwt.New("my-super-secret-key")
//
//	accessToken, err := manager.GenerateAccessToken(1, "admin")
//	if err != nil {
//	    log.Fatal(err)
//	}
//
//	claims, err := manager.ValidateToken(accessToken)
//	if err != nil {
//	    log.Fatal(err)
//	}
//
//	fmt.Printf("UserID: %d, Role: %s\n", claims.UserID, claims.Role)
package jwt

import (
	"fmt"
	"time"

	jwtlib "github.com/golang-jwt/jwt/v5"
)

// Default token expiration durations.
const (
	// DefaultAccessTokenExpiry is the default lifetime for access tokens (15 minutes).
	DefaultAccessTokenExpiry = 15 * time.Minute

	// DefaultRefreshTokenExpiry is the default lifetime for refresh tokens (7 days).
	DefaultRefreshTokenExpiry = 7 * 24 * time.Hour
)

// Token type identifiers used in the "type" claim.
const (
	TokenTypeAccess  = "access"
	TokenTypeRefresh = "refresh"
)

// Claims represents the custom JWT claims payload used by authkit.
// It embeds jwt.RegisteredClaims for standard fields like expiration.
type Claims struct {
	UserID uint   `json:"user_id"`
	Role   string `json:"role,omitempty"`
	Type   string `json:"type"`
	jwtlib.RegisteredClaims
}

// Manager handles JWT token generation and validation.
// It holds the signing secret and configurable expiration durations.
type Manager struct {
	secret             []byte
	accessTokenExpiry  time.Duration
	refreshTokenExpiry time.Duration
}

// Option is a functional option for configuring the Manager.
type Option func(*Manager)

// WithAccessTokenExpiry sets a custom access token expiration duration.
func WithAccessTokenExpiry(d time.Duration) Option {
	return func(m *Manager) {
		m.accessTokenExpiry = d
	}
}

// WithRefreshTokenExpiry sets a custom refresh token expiration duration.
func WithRefreshTokenExpiry(d time.Duration) Option {
	return func(m *Manager) {
		m.refreshTokenExpiry = d
	}
}

// New creates a new JWT Manager with the given HMAC secret.
// The secret is used for signing and validating tokens using HS256.
//
// Optional configurations can be provided via functional options:
//
//	manager := jwt.New("secret",
//	    jwt.WithAccessTokenExpiry(30 * time.Minute),
//	    jwt.WithRefreshTokenExpiry(14 * 24 * time.Hour),
//	)
//
// Panics if the secret is empty, as tokens signed with an empty secret
// are inherently insecure.
func New(secret string, opts ...Option) *Manager {
	if secret == "" {
		panic("jwt: secret must not be empty")
	}

	m := &Manager{
		secret:             []byte(secret),
		accessTokenExpiry:  DefaultAccessTokenExpiry,
		refreshTokenExpiry: DefaultRefreshTokenExpiry,
	}

	for _, opt := range opts {
		opt(m)
	}

	return m
}

// GenerateAccessToken creates a signed JWT access token for the given user.
// The token contains the user's ID, role, and a "type" claim set to "access".
//
// Returns the signed token string or an error if signing fails.
func (m *Manager) GenerateAccessToken(userID uint, role string) (string, error) {
	now := time.Now()

	claims := &Claims{
		UserID: userID,
		Role:   role,
		Type:   TokenTypeAccess,
		RegisteredClaims: jwtlib.RegisteredClaims{
			IssuedAt:  jwtlib.NewNumericDate(now),
			ExpiresAt: jwtlib.NewNumericDate(now.Add(m.accessTokenExpiry)),
		},
	}

	token := jwtlib.NewWithClaims(jwtlib.SigningMethodHS256, claims)

	signedToken, err := token.SignedString(m.secret)
	if err != nil {
		return "", fmt.Errorf("jwt: failed to sign access token: %w", err)
	}

	return signedToken, nil
}

// GenerateRefreshToken creates a signed JWT refresh token for the given user.
// The token contains only the user's ID and a "type" claim set to "refresh".
// It does not include a role, as refresh tokens should only be used to obtain
// new access tokens.
//
// Returns the signed token string or an error if signing fails.
func (m *Manager) GenerateRefreshToken(userID uint) (string, error) {
	now := time.Now()

	claims := &Claims{
		UserID: userID,
		Type:   TokenTypeRefresh,
		RegisteredClaims: jwtlib.RegisteredClaims{
			IssuedAt:  jwtlib.NewNumericDate(now),
			ExpiresAt: jwtlib.NewNumericDate(now.Add(m.refreshTokenExpiry)),
		},
	}

	token := jwtlib.NewWithClaims(jwtlib.SigningMethodHS256, claims)

	signedToken, err := token.SignedString(m.secret)
	if err != nil {
		return "", fmt.Errorf("jwt: failed to sign refresh token: %w", err)
	}

	return signedToken, nil
}

// ValidateToken parses and validates a JWT token string.
// It verifies the token signature using the manager's secret and checks
// that the token has not expired.
//
// Returns the parsed Claims if valid, or an error describing why
// validation failed (e.g., expired, malformed, wrong signature).
func (m *Manager) ValidateToken(tokenString string) (*Claims, error) {
	if tokenString == "" {
		return nil, fmt.Errorf("jwt: token must not be empty")
	}

	claims := &Claims{}

	token, err := jwtlib.ParseWithClaims(tokenString, claims, func(token *jwtlib.Token) (interface{}, error) {
		// Ensure the signing method is HMAC (HS256).
		if _, ok := token.Method.(*jwtlib.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("jwt: unexpected signing method: %v", token.Header["alg"])
		}
		return m.secret, nil
	})
	if err != nil {
		return nil, fmt.Errorf("jwt: invalid token: %w", err)
	}

	if !token.Valid {
		return nil, fmt.Errorf("jwt: token is not valid")
	}

	return claims, nil
}
