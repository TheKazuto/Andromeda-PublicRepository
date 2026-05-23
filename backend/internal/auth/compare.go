package auth

import "crypto/subtle"

// ConstantTimeEqual compares two strings without leaking length-independent
// timing information about how many leading bytes matched. Use it for any
// shared-secret check (admin tokens, metrics tokens) so an attacker cannot
// recover the secret byte-by-byte from response timing.
func ConstantTimeEqual(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}
