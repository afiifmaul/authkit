// Package main demonstrates how to use the authkit library
// for authentication in a Go HTTP server.
//
// Run with: go run examples/main.go
//
// Then test with:
//
//	# Register (hash password)
//	curl -s http://localhost:8080/register -d '{"password":"secret123"}'
//
//	# Login (get tokens)
//	curl -s http://localhost:8080/login -d '{"password":"secret123"}'
//
//	# Access protected route (use the access_token from login response)
//	curl -s http://localhost:8080/profile -H "Authorization: Bearer <access_token>"
//
//	# Generate MFA secret
//	curl -s http://localhost:8080/mfa/setup -H "Authorization: Bearer <access_token>"
package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"sync"

	"github.com/afiifnajmi/authkit/bcrypt"
	authctx "github.com/afiifnajmi/authkit/context"
	authjwt "github.com/afiifnajmi/authkit/jwt"
	"github.com/afiifnajmi/authkit/middleware"
	"github.com/afiifnajmi/authkit/otp"
)

// In-memory user store for demonstration purposes.
// In production, use a proper database.
var (
	userStore = struct {
		sync.RWMutex
		passwordHash string
	}{}
	jwtManager = authjwt.New("my-super-secret-key-change-in-production")
)

func main() {
	mux := http.NewServeMux()

	// Public routes
	mux.HandleFunc("/register", registerHandler)
	mux.HandleFunc("/login", loginHandler)

	// Protected routes (require valid JWT)
	authMiddleware := middleware.RequireAuth(jwtManager)
	mux.Handle("/profile", authMiddleware(http.HandlerFunc(profileHandler)))
	mux.Handle("/mfa/setup", authMiddleware(http.HandlerFunc(mfaSetupHandler)))

	fmt.Println("🔐 AuthKit Example Server")
	fmt.Println("   Listening on http://localhost:8080")
	fmt.Println()
	fmt.Println("   Endpoints:")
	fmt.Println("   POST /register  - Register with password")
	fmt.Println("   POST /login     - Login and get JWT tokens")
	fmt.Println("   GET  /profile   - Protected: get user profile")
	fmt.Println("   GET  /mfa/setup - Protected: generate MFA secret")

	log.Fatal(http.ListenAndServe(":8080", mux))
}

type registerRequest struct {
	Password string `json:"password"`
}

func registerHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}

	var req registerRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid JSON"}`, http.StatusBadRequest)
		return
	}

	if req.Password == "" {
		http.Error(w, `{"error":"password is required"}`, http.StatusBadRequest)
		return
	}

	// Hash the password using authkit/bcrypt
	hash, err := bcrypt.Hash(req.Password)
	if err != nil {
		http.Error(w, `{"error":"failed to hash password"}`, http.StatusInternalServerError)
		return
	}

	// Store the hash (in-memory for demo)
	userStore.Lock()
	userStore.passwordHash = hash
	userStore.Unlock()

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]string{
		"message": "user registered successfully",
	})
}

type loginRequest struct {
	Password string `json:"password"`
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}

	var req loginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid JSON"}`, http.StatusBadRequest)
		return
	}

	// Check if user is registered
	userStore.RLock()
	hash := userStore.passwordHash
	userStore.RUnlock()

	if hash == "" {
		http.Error(w, `{"error":"no user registered, please register first"}`, http.StatusUnauthorized)
		return
	}

	// Verify password using authkit/bcrypt
	if err := bcrypt.Verify(hash, req.Password); err != nil {
		http.Error(w, `{"error":"invalid password"}`, http.StatusUnauthorized)
		return
	}

	// Generate tokens using authkit/jwt
	accessToken, err := jwtManager.GenerateAccessToken(1, "admin")
	if err != nil {
		http.Error(w, `{"error":"failed to generate access token"}`, http.StatusInternalServerError)
		return
	}

	refreshToken, err := jwtManager.GenerateRefreshToken(1)
	if err != nil {
		http.Error(w, `{"error":"failed to generate refresh token"}`, http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"access_token":  accessToken,
		"refresh_token": refreshToken,
		"message":       "login successful",
	})
}

func profileHandler(w http.ResponseWriter, r *http.Request) {
	// Get user from context (set by RequireAuth middleware)
	claims, ok := authctx.GetUser(r.Context())
	if !ok {
		http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"user_id": claims.UserID,
		"role":    claims.Role,
		"type":    claims.Type,
		"message": "this is a protected route",
	})
}

func mfaSetupHandler(w http.ResponseWriter, r *http.Request) {
	claims, ok := authctx.GetUser(r.Context())
	if !ok {
		http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
		return
	}

	// Generate TOTP secret using authkit/otp
	accountName := fmt.Sprintf("user-%d@authkit-demo.com", claims.UserID)
	secret, qrURL, err := otp.GenerateSecret(accountName)
	if err != nil {
		http.Error(w, `{"error":"failed to generate MFA secret"}`, http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"secret":  secret,
		"qr_url":  qrURL,
		"message": "scan the QR URL with Google Authenticator",
	})
}
