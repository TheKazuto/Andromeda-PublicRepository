package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"net/http"
	"strings"
)

const (
	Prefix       = "sk_live_"
	rawLen       = 32
	prefixLength = 12
)

// Generate returns (fullKey, publicPrefix, sha256HexHash).
// The raw key is shown ONCE — storage holds only the hash.
func Generate() (string, string, string, error) {
	buf := make([]byte, rawLen)
	if _, err := rand.Read(buf); err != nil {
		return "", "", "", err
	}
	enc := base64.RawURLEncoding.EncodeToString(buf)
	if len(enc) > 40 {
		enc = enc[:40]
	}
	full := Prefix + enc
	pubPrefix := full[:len(Prefix)+prefixLength] + "…"
	return full, pubPrefix, Hash(full), nil
}

func Hash(key string) string {
	sum := sha256.Sum256([]byte(key))
	return hex.EncodeToString(sum[:])
}

// ExtractAPIKey reads the raw API key from the request. Two forms are
// accepted: "X-Api-Key: <raw>" and "Authorization: Bearer <raw>".
func ExtractAPIKey(r *http.Request) string {
	if v := strings.TrimSpace(r.Header.Get("X-Api-Key")); v != "" {
		return v
	}
	if v := strings.TrimSpace(r.Header.Get("Authorization")); v != "" {
		const bearer = "bearer "
		if len(v) > len(bearer) && strings.EqualFold(v[:len(bearer)], bearer) {
			return strings.TrimSpace(v[len(bearer):])
		}
	}
	return ""
}

// ConstantTimeEqual compares two strings without timing leaks.
func ConstantTimeEqual(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}
