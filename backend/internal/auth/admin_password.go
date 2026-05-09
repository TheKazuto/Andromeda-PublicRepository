package auth

import (
	"crypto/subtle"
	"errors"

	"golang.org/x/crypto/bcrypt"
)

// AdminBcryptCost is the work factor used for hashing admin passwords.
// 12 is the 2025-2026 baseline (about 250 ms on a modern CPU). Distinct
// from the regular user cost (10) — admins are higher-value targets.
const AdminBcryptCost = 12

// ErrInvalidAdminPassword is returned by VerifyAdminPassword when the
// provided password does not match the stored hash.
var ErrInvalidAdminPassword = errors.New("invalid admin password")

// HashAdminPassword applies bcrypt(AdminBcryptCost) to the plain-text
// password and enforces a 12-character minimum.
func HashAdminPassword(plain string) (string, error) {
	if plain == "" {
		return "", errors.New("password cannot be empty")
	}
	if len(plain) < 12 {
		return "", errors.New("password must be at least 12 characters")
	}
	out, err := bcrypt.GenerateFromPassword([]byte(plain), AdminBcryptCost)
	if err != nil {
		return "", err
	}
	return string(out), nil
}

// VerifyAdminPassword returns nil iff `plain` matches `hashed`.
// Returns ErrInvalidAdminPassword on mismatch; other errors propagate.
func VerifyAdminPassword(plain, hashed string) error {
	if hashed == "" {
		return ErrInvalidAdminPassword
	}
	err := bcrypt.CompareHashAndPassword([]byte(hashed), []byte(plain))
	if errors.Is(err, bcrypt.ErrMismatchedHashAndPassword) {
		return ErrInvalidAdminPassword
	}
	return err
}

// ConstantTimeEqual compares two strings without timing leaks. Used for
// the legacy X-Admin-Token shared-secret check.
func ConstantTimeEqual(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}
