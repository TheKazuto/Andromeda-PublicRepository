package apikeys

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
)

const (
	Prefix       = "sk_live_"
	RawLen       = 32 // bytes -> 64 hex chars
	PrefixLength = 12 // first chars of the random portion shown publicly
)

// Generate returns (fullKey, publicPrefix, sha256HexHash).
// The raw key is shown ONCE to the user — we only store the hash.
func Generate() (string, string, string, error) {
	buf := make([]byte, RawLen)
	if _, err := rand.Read(buf); err != nil {
		return "", "", "", err
	}
	enc := base64.RawURLEncoding.EncodeToString(buf)
	if len(enc) > 40 {
		enc = enc[:40]
	}
	full := Prefix + enc
	pubPrefix := full[:len(Prefix)+PrefixLength] + "…"
	sum := sha256.Sum256([]byte(full))
	return full, pubPrefix, hex.EncodeToString(sum[:]), nil
}

func Hash(key string) string {
	sum := sha256.Sum256([]byte(key))
	return hex.EncodeToString(sum[:])
}
