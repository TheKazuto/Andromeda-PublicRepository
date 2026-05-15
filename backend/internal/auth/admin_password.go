package auth

import (
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/bcrypt"
)

// AdminBcryptCost is the work factor used for hashing admin passwords.
// 12 is the 2025-2026 baseline (about 250 ms on a modern CPU).
const AdminBcryptCost = 12

// MinAdminPasswordLen is the minimum length for admin passwords. Admins
// are higher-value targets, so we enforce both length AND character
// diversity (see ValidateAdminPasswordStrength).
const MinAdminPasswordLen = 12

// ErrInvalidAdminPassword is returned by VerifyAdminPassword when the
// provided password does not match the stored hash.
var ErrInvalidAdminPassword = errors.New("invalid admin password")

// ValidateAdminPasswordStrength enforces length + entropy. Returns nil
// when the password meets at least two of: uppercase, digit, special.
// Used by HashAdminPassword and exposed so the bootstrap path can
// validate before reaching bcrypt.
func ValidateAdminPasswordStrength(plain string) error {
	if plain == "" {
		return errors.New("password cannot be empty")
	}
	if len(plain) < MinAdminPasswordLen {
		return fmt.Errorf("password must be at least %d characters", MinAdminPasswordLen)
	}
	hasUpper := strings.ContainsAny(plain, "ABCDEFGHIJKLMNOPQRSTUVWXYZ")
	hasDigit := strings.ContainsAny(plain, "0123456789")
	hasSpecial := strings.ContainsAny(plain, "!@#$%^&*()-_=+[]{};:,.<>?/\\|`~'\"")
	score := 0
	if hasUpper {
		score++
	}
	if hasDigit {
		score++
	}
	if hasSpecial {
		score++
	}
	if score < 2 {
		return errors.New("password must contain at least two of: uppercase letter, digit, special character")
	}
	return nil
}

// HashAdminPassword applies bcrypt(AdminBcryptCost) to the plain-text
// password after enforcing length + entropy.
func HashAdminPassword(plain string) (string, error) {
	if err := ValidateAdminPasswordStrength(plain); err != nil {
		return "", err
	}
	out, err := bcrypt.GenerateFromPassword([]byte(plain), AdminBcryptCost)
	if err != nil {
		return "", fmt.Errorf("hash admin password: %w", err)
	}
	return string(out), nil
}

// VerifyAdminPassword returns nil iff `plain` matches `hashed`.
// Returns ErrInvalidAdminPassword on mismatch; other errors propagate
// with context so logs can distinguish corrupted hashes from misses.
func VerifyAdminPassword(plain, hashed string) error {
	if hashed == "" {
		return ErrInvalidAdminPassword
	}
	err := bcrypt.CompareHashAndPassword([]byte(hashed), []byte(plain))
	if errors.Is(err, bcrypt.ErrMismatchedHashAndPassword) {
		return ErrInvalidAdminPassword
	}
	if err != nil {
		return fmt.Errorf("verify admin password: %w", err)
	}
	return nil
}
