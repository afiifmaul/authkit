// Package otp provides TOTP (Time-based One-Time Password) generation
// and validation compatible with Google Authenticator and similar apps.
//
// It uses the pquerna/otp library under the hood.
//
// Example:
//
//	secret, qrURL, err := otp.GenerateSecret("user@example.com")
//	if err != nil {
//	    log.Fatal(err)
//	}
//
//	fmt.Println("Secret:", secret)
//	fmt.Println("QR URL:", qrURL)
//
//	// User scans QR code, then enters the code from their authenticator app:
//	valid := otp.Validate(secret, "123456")
//	fmt.Println("Valid:", valid)
package otp

import (
	"fmt"

	"github.com/pquerna/otp/totp"
)

// DefaultIssuer is the default issuer name used in TOTP generation.
// This appears in the user's authenticator app alongside the account name.
const DefaultIssuer = "AuthKit"

// GenerateSecret creates a new TOTP secret for the given account name.
// It returns:
//   - secret: the base32-encoded secret key that should be stored securely
//   - qrURL: an otpauth:// URL that can be encoded as a QR code for easy scanning
//   - err: any error encountered during generation
//
// The account name typically represents the user's email or username.
func GenerateSecret(accountName string) (secret string, qrURL string, err error) {
	if accountName == "" {
		return "", "", fmt.Errorf("otp: account name must not be empty")
	}

	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      DefaultIssuer,
		AccountName: accountName,
	})
	if err != nil {
		return "", "", fmt.Errorf("otp: failed to generate secret: %w", err)
	}

	return key.Secret(), key.URL(), nil
}

// GenerateSecretWithIssuer creates a new TOTP secret with a custom issuer name.
// This is useful when you want to display your application name in the
// user's authenticator app.
//
// See GenerateSecret for parameter details.
func GenerateSecretWithIssuer(accountName, issuer string) (secret string, qrURL string, err error) {
	if accountName == "" {
		return "", "", fmt.Errorf("otp: account name must not be empty")
	}

	if issuer == "" {
		return "", "", fmt.Errorf("otp: issuer must not be empty")
	}

	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      issuer,
		AccountName: accountName,
	})
	if err != nil {
		return "", "", fmt.Errorf("otp: failed to generate secret: %w", err)
	}

	return key.Secret(), key.URL(), nil
}

// Validate checks whether the given TOTP code is valid for the provided secret.
// It returns true if the code is valid for the current time window, false otherwise.
//
// This function uses the default TOTP parameters (30-second period, 6 digits)
// which are compatible with Google Authenticator and most other authenticator apps.
func Validate(secret, code string) bool {
	if secret == "" || code == "" {
		return false
	}

	return totp.Validate(code, secret)
}
