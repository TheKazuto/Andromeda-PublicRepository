package auth

import (
	"crypto/rand"
	"encoding/base64"
)

// GiftTokenPrefix is the redeem-link prefix for gift cards. The full
// token format is "gft_<32-byte-base64url>".
const GiftTokenPrefix = "gft_"

// GenerateGiftToken returns a fresh redeem token suitable for embedding
// in a public URL. 32 bytes of crypto/rand → ~43 base64url chars after
// the prefix; brute-force lookups are infeasible.
func GenerateGiftToken() (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return GiftTokenPrefix + base64.RawURLEncoding.EncodeToString(buf), nil
}
