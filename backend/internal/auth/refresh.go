package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"time"
)

// RefreshTokenTTL is how long a freshly issued refresh token remains valid.
// 14 days matches a typical "stay signed in" window — short enough that a
// stolen cookie has a bounded reuse window, long enough that legitimate
// users on infrequently-used devices do not need to re-auth constantly.
const RefreshTokenTTL = 14 * 24 * time.Hour

// PasswordResetTTL is how long a forgot-password email link is valid. Short
// because a longer window just expands the attack surface for password
// reset link interception.
const PasswordResetTTL = 30 * time.Minute

// ErrInvalidRefreshToken is returned when refresh-token validation fails for
// any reason. The HTTP layer should always respond with 401 — never echo
// which check failed (existence vs expiry vs revocation), since revealing
// that lets an attacker probe the token store.
var ErrInvalidRefreshToken = errors.New("invalid refresh token")

// GenerateOpaqueToken returns a 256-bit cryptographically random token, the
// SHA-256 hash of that token (hex), and any error from the OS rng.
//
// Layout:
//   - raw: 32 bytes encoded as URL-safe base64 (no padding) — what travels
//     in the HttpOnly cookie or the password-reset email URL.
//   - hash: hex(sha256(raw)) — what we persist. On verification we hash the
//     supplied token and look it up by hash. SHA-256 is unsalted on purpose
//     — the input is high-entropy random, so a salt would only complicate
//     lookups without adding security.
func GenerateOpaqueToken() (raw, hash string, err error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", "", err
	}
	raw = base64.RawURLEncoding.EncodeToString(buf)
	sum := sha256.Sum256([]byte(raw))
	hash = hex.EncodeToString(sum[:])
	return raw, hash, nil
}

// HashOpaqueToken hashes a token presented by the client so it can be
// looked up against the stored hash. Constant-time comparison happens at
// the SQL layer (UNIQUE index on token_hash).
func HashOpaqueToken(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}
