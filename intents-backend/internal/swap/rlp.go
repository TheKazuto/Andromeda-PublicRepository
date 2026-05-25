package swap

import "math/big"

// Minimal RLP encoder — just enough for EIP-1559 (type-2) transactions. Avoids
// pulling in the whole go-ethereum dependency tree for a handful of encodings.
// Reference: https://ethereum.org/en/developers/docs/data-structures-and-encoding/rlp/

// rlpString encodes a byte string per RLP.
func rlpString(b []byte) []byte {
	if len(b) == 1 && b[0] < 0x80 {
		return b
	}
	return append(rlpLenPrefix(len(b), 0x80), b...)
}

// rlpList wraps already-encoded items into an RLP list.
func rlpList(items ...[]byte) []byte {
	var payload []byte
	for _, it := range items {
		payload = append(payload, it...)
	}
	return append(rlpLenPrefix(len(payload), 0xc0), payload...)
}

// rlpLenPrefix builds the RLP length prefix for the given base offset (0x80 for
// strings, 0xc0 for lists).
func rlpLenPrefix(n int, base byte) []byte {
	if n < 56 {
		return []byte{base + byte(n)}
	}
	lenBytes := bigEndian(uint64(n))
	return append([]byte{base + 55 + byte(len(lenBytes))}, lenBytes...)
}

// rlpUint encodes an unsigned integer as a minimal big-endian RLP string (zero
// is the empty string, which RLP renders as 0x80).
func rlpUint(v *big.Int) []byte {
	if v == nil || v.Sign() == 0 {
		return rlpString(nil)
	}
	return rlpString(v.Bytes())
}

// bigEndian returns the minimal big-endian byte representation of n (no leading
// zeros). n == 0 returns a single zero byte (used only for length prefixes).
func bigEndian(n uint64) []byte {
	if n == 0 {
		return []byte{0}
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte(n & 0xff)}, b...)
		n >>= 8
	}
	return b
}
