package auth

import (
	"crypto/sha256"
	"encoding/binary"
)

// Hashv computes SHA-256 over the concatenation of `parts`. Matches
// `andromeda_auth::hash::hashv` byte-for-byte (the Rust side calls the
// Solana `sol_sha256` syscall, which is a streaming SHA-256 absorbing each
// part in sequence).
func Hashv(parts ...[]byte) [32]byte {
	h := sha256.New()
	for _, p := range parts {
		h.Write(p)
	}
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// U64LE returns the little-endian byte representation of v.
func U64LE(v uint64) []byte {
	b := make([]byte, 8)
	binary.LittleEndian.PutUint64(b, v)
	return b
}

// I64LE returns the little-endian two's-complement representation of v.
func I64LE(v int64) []byte {
	b := make([]byte, 8)
	binary.LittleEndian.PutUint64(b, uint64(v))
	return b
}

// U32LE returns the little-endian byte representation of v.
func U32LE(v uint32) []byte {
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, v)
	return b
}

// U16LE returns the little-endian byte representation of v.
func U16LE(v uint16) []byte {
	b := make([]byte, 2)
	binary.LittleEndian.PutUint16(b, v)
	return b
}

// U8 returns a single-byte slice [v].
func U8(v uint8) []byte {
	return []byte{v}
}
