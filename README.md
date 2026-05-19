# 🔐 AuthKit

[![Go Reference](https://pkg.go.dev/badge/github.com/afiifnajmi/authkit.svg)](https://pkg.go.dev/github.com/afiifnajmi/authkit)
[![Go Report Card](https://goreportcard.com/badge/github.com/afiifnajmi/authkit)](https://goreportcard.com/report/github.com/afiifnajmi/authkit)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

A modular, production-ready authentication toolkit for Go backend applications.

## Features

- 🔑 **Password Hashing** — bcrypt-based password hashing and verification
- 🎫 **JWT Tokens** — Access and refresh token generation with HMAC-SHA256
- 📱 **TOTP/MFA** — Google Authenticator compatible one-time passwords
- 🛡️ **HTTP Middleware** — Ready-to-use authentication middleware for `net/http`
- 👤 **Context Helpers** — Store and retrieve user claims from `context.Context`
- 🧩 **Modular Design** — Use only the packages you need

## Installation

```bash
go get github.com/afiifnajmi/authkit
```

## Quick Start

```go
package main

import (
    "fmt"
    "log"
    "net/http"

    "github.com/afiifnajmi/authkit/bcrypt"
    authctx "github.com/afiifnajmi/authkit/context"
    "github.com/afiifnajmi/authkit/jwt"
    "github.com/afiifnajmi/authkit/middleware"
)

func main() {
    // 1. Hash a password
    hash, _ := bcrypt.Hash("my-password")
    fmt.Println("Hash:", hash)

    // 2. Verify a password
    if err := bcrypt.Verify(hash, "my-password"); err != nil {
        log.Fatal("password mismatch!")
    }

    // 3. Create JWT manager
    manager := jwt.New("your-secret-key")

    // 4. Generate tokens
    accessToken, _ := manager.GenerateAccessToken(1, "admin")
    refreshToken, _ := manager.GenerateRefreshToken(1)

    fmt.Println("Access Token:", accessToken)
    fmt.Println("Refresh Token:", refreshToken)

    // 5. Set up protected routes with middleware
    mux := http.NewServeMux()
    mux.Handle("/profile", middleware.RequireAuth(manager)(
        http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
            claims, _ := authctx.GetUser(r.Context())
            fmt.Fprintf(w, "Hello, user %d!", claims.UserID)
        }),
    ))

    log.Fatal(http.ListenAndServe(":8080", mux))
}
```

## Package Reference

### `bcrypt` — Password Hashing

```go
import "github.com/afiifnajmi/authkit/bcrypt"
```

| Function | Description |
|---|---|
| `Hash(password string) (string, error)` | Hash a password with default cost (12) |
| `HashWithCost(password string, cost int) (string, error)` | Hash with custom cost factor |
| `Verify(hash, password string) error` | Verify a password against a hash |

```go
// Hash a password
hash, err := bcrypt.Hash("secret123")

// Verify a password
err = bcrypt.Verify(hash, "secret123") // nil = match

// Hash with custom cost
hash, err = bcrypt.HashWithCost("secret123", 14)
```

### `jwt` — Token Management

```go
import "github.com/afiifnajmi/authkit/jwt"
```

| Function/Method | Description |
|---|---|
| `New(secret string, opts ...Option) *Manager` | Create a JWT manager |
| `WithAccessTokenExpiry(d time.Duration) Option` | Custom access token expiry |
| `WithRefreshTokenExpiry(d time.Duration) Option` | Custom refresh token expiry |
| `(*Manager).GenerateAccessToken(userID uint, role string) (string, error)` | Generate access token |
| `(*Manager).GenerateRefreshToken(userID uint) (string, error)` | Generate refresh token |
| `(*Manager).ValidateToken(token string) (*Claims, error)` | Validate and parse a token |

```go
// Create manager with custom expiry
manager := jwt.New("secret",
    jwt.WithAccessTokenExpiry(30 * time.Minute),
    jwt.WithRefreshTokenExpiry(14 * 24 * time.Hour),
)

// Generate tokens
accessToken, err := manager.GenerateAccessToken(1, "admin")
refreshToken, err := manager.GenerateRefreshToken(1)

// Validate token
claims, err := manager.ValidateToken(accessToken)
fmt.Println(claims.UserID, claims.Role, claims.Type)
```

### `otp` — TOTP/MFA

```go
import "github.com/afiifnajmi/authkit/otp"
```

| Function | Description |
|---|---|
| `GenerateSecret(accountName string) (secret, qrURL string, err error)` | Generate TOTP secret |
| `GenerateSecretWithIssuer(accountName, issuer string) (secret, qrURL string, err error)` | Generate with custom issuer |
| `Validate(secret, code string) bool` | Validate a TOTP code |

```go
// Generate secret (show QR URL to user)
secret, qrURL, err := otp.GenerateSecret("user@example.com")

// With custom issuer
secret, qrURL, err := otp.GenerateSecretWithIssuer("user@example.com", "MyApp")

// Validate code from authenticator app
valid := otp.Validate(secret, "123456")
```

### `middleware` — HTTP Authentication

```go
import "github.com/afiifnajmi/authkit/middleware"
```

| Function | Description |
|---|---|
| `RequireAuth(manager *jwt.Manager) func(http.Handler) http.Handler` | JWT auth middleware |
| `RequireRole(roles ...string) func(http.Handler) http.Handler` | Role-based access control |

```go
manager := jwt.New("secret")

// Protect a route
mux.Handle("/api/data", middleware.RequireAuth(manager)(dataHandler))

// Require specific role (chain after RequireAuth)
mux.Handle("/api/admin", middleware.RequireAuth(manager)(
    middleware.RequireRole("admin", "superadmin")(adminHandler),
))
```

### `context` (authctx) — User Context Helpers

```go
import authctx "github.com/afiifnajmi/authkit/context"
```

| Function | Description |
|---|---|
| `SetUser(ctx context.Context, claims *jwt.Claims) context.Context` | Store claims in context |
| `GetUser(ctx context.Context) (*jwt.Claims, bool)` | Retrieve claims from context |

```go
// In middleware: store claims
ctx := authctx.SetUser(r.Context(), claims)
r = r.WithContext(ctx)

// In handler: retrieve claims
claims, ok := authctx.GetUser(r.Context())
if !ok {
    http.Error(w, "unauthorized", 401)
    return
}
fmt.Println(claims.UserID, claims.Role)
```

## Project Structure

```
authkit/
├── bcrypt/           # Password hashing and verification
│   ├── bcrypt.go
│   └── bcrypt_test.go
├── jwt/              # JWT access and refresh token management
│   ├── jwt.go
│   └── jwt_test.go
├── otp/              # TOTP/MFA with Google Authenticator
│   ├── otp.go
│   └── otp_test.go
├── middleware/        # HTTP authentication middleware
│   ├── auth.go
│   └── auth_test.go
├── context/          # User claims context helpers
│   ├── user.go
│   └── user_test.go
├── examples/         # Usage examples
│   └── main.go
├── docs/             # Documentation
│   └── architecture.md
├── .gitignore
├── go.mod
├── LICENSE
└── README.md
```

## Running Tests

```bash
# Run all tests
go test ./...

# Run with verbose output
go test -v ./...

# Run specific package tests
go test -v ./bcrypt/
go test -v ./jwt/
go test -v ./otp/
go test -v ./middleware/
go test -v ./context/

# Run with coverage
go test -coverprofile=coverage.out ./...
go tool cover -html=coverage.out -o coverage.html
```

## Running the Example

```bash
go run examples/main.go
```

Then test with curl:

```bash
# 1. Register a user
curl -X POST http://localhost:8080/register \
  -H "Content-Type: application/json" \
  -d '{"password":"secret123"}'

# 2. Login to get tokens
curl -X POST http://localhost:8080/login \
  -H "Content-Type: application/json" \
  -d '{"password":"secret123"}'

# 3. Access protected route (replace <TOKEN> with access_token from step 2)
curl http://localhost:8080/profile \
  -H "Authorization: Bearer <TOKEN>"

# 4. Set up MFA
curl http://localhost:8080/mfa/setup \
  -H "Authorization: Bearer <TOKEN>"
```

## Security Considerations

- **bcrypt cost**: Default cost is 12. Increase for higher security (at the cost of performance).
- **JWT secret**: Use a strong, random secret of at least 32 characters in production.
- **Token storage**: Store refresh tokens securely (e.g., httpOnly cookies, not localStorage).
- **HTTPS**: Always use HTTPS in production to protect tokens in transit.
- **Token rotation**: Implement refresh token rotation to limit the impact of token theft.

## Dependencies

| Package | Purpose |
|---|---|
| [golang.org/x/crypto/bcrypt](https://pkg.go.dev/golang.org/x/crypto/bcrypt) | Password hashing |
| [github.com/golang-jwt/jwt/v5](https://github.com/golang-jwt/jwt) | JWT token handling |
| [github.com/pquerna/otp](https://github.com/pquerna/otp) | TOTP generation and validation |

## License

[MIT](LICENSE)
