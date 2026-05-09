package auth

import (
	"encoding/binary"
	"fmt"

	"github.com/gagliardetto/solana-go"
)

// Solana native signature-verification precompile program addresses.
// See `contracts/auth/src/precompile.rs` for the on-chain side.
var (
	Ed25519PrecompileID   = solana.MustPublicKeyFromBase58("Ed25519SigVerify111111111111111111111111111")
	Secp256k1PrecompileID = solana.MustPublicKeyFromBase58("KeccakSecp256k11111111111111111111111111111")
	Secp256r1PrecompileID = solana.MustPublicKeyFromBase58("Secp256r1SigVerify1111111111111111111111111")
	InstructionsSysvarID  = solana.MustPublicKeyFromBase58("Sysvar1nstructions1111111111111111111111111")
)

// Sentinel for "this signature/pubkey/message data lives in the same
// instruction" used by the long-format (Ed25519/Secp256r1) precompile.
const longSelfIndex uint16 = 0xFFFF

// Sentinel for the short-format (Secp256k1) precompile, where instruction
// indexes are u8.
const shortSelfIndex uint8 = 0xFF

const (
	ed25519SigLen      = 64
	ed25519PubkeyLen   = 32
	secp256k1SigLen    = 64
	secp256k1RecidLen  = 1
	secp256k1EthAddr   = 20
	secp256r1SigLen    = 64
	secp256r1PubkeyLen = 33
)

// BuildEd25519PrecompileInstruction returns a Solana instruction targeting the
// Ed25519 precompile that proves `signature` is `pubkey`'s Ed25519 signature
// over `message`. The on-chain `andromeda_auth::precompile::verify_ed25519`
// reads this back from the Instructions sysvar.
func BuildEd25519PrecompileInstruction(pubkey, message, signature []byte) (*solana.GenericInstruction, error) {
	if len(pubkey) != ed25519PubkeyLen {
		return nil, fmt.Errorf("ed25519 pubkey must be %d bytes (got %d)", ed25519PubkeyLen, len(pubkey))
	}
	if len(signature) != ed25519SigLen {
		return nil, fmt.Errorf("ed25519 signature must be %d bytes (got %d)", ed25519SigLen, len(signature))
	}
	const headerLen = 2
	const offsetsLen = 14
	sigOffset := headerLen + offsetsLen
	pubkeyOffset := sigOffset + ed25519SigLen
	messageOffset := pubkeyOffset + ed25519PubkeyLen
	totalLen := messageOffset + len(message)

	data := make([]byte, totalLen)
	data[0] = 1 // num_records
	data[1] = 0 // padding
	off := headerLen
	binary.LittleEndian.PutUint16(data[off:off+2], uint16(sigOffset))
	off += 2
	binary.LittleEndian.PutUint16(data[off:off+2], longSelfIndex)
	off += 2
	binary.LittleEndian.PutUint16(data[off:off+2], uint16(pubkeyOffset))
	off += 2
	binary.LittleEndian.PutUint16(data[off:off+2], longSelfIndex)
	off += 2
	binary.LittleEndian.PutUint16(data[off:off+2], uint16(messageOffset))
	off += 2
	binary.LittleEndian.PutUint16(data[off:off+2], uint16(len(message)))
	off += 2
	binary.LittleEndian.PutUint16(data[off:off+2], longSelfIndex)
	copy(data[sigOffset:], signature)
	copy(data[pubkeyOffset:], pubkey)
	copy(data[messageOffset:], message)
	return solana.NewInstruction(Ed25519PrecompileID, solana.AccountMetaSlice{}, data), nil
}

// BuildSecp256k1PrecompileInstruction returns a Solana instruction targeting
// the secp256k1 precompile (Ethereum-style: validates eth_address derived
// from keccak256(uncompressed_pubkey)).
//
// `signature` is 65 bytes: r || s || recovery_id. `ethAddress` is 20 bytes.
func BuildSecp256k1PrecompileInstruction(ethAddress, message, signature []byte) (*solana.GenericInstruction, error) {
	if len(ethAddress) != secp256k1EthAddr {
		return nil, fmt.Errorf("secp256k1 eth_address must be %d bytes (got %d)", secp256k1EthAddr, len(ethAddress))
	}
	if len(signature) != secp256k1SigLen+secp256k1RecidLen {
		return nil, fmt.Errorf("secp256k1 signature must be %d bytes (r||s||recid)", secp256k1SigLen+secp256k1RecidLen)
	}
	const headerLen = 1
	const offsetsLen = 11
	sigOffset := headerLen + offsetsLen
	ethAddrOffset := sigOffset + secp256k1SigLen + secp256k1RecidLen
	messageOffset := ethAddrOffset + secp256k1EthAddr
	totalLen := messageOffset + len(message)

	data := make([]byte, totalLen)
	data[0] = 1 // num_records
	off := headerLen
	binary.LittleEndian.PutUint16(data[off:off+2], uint16(sigOffset))
	off += 2
	data[off] = shortSelfIndex
	off++
	binary.LittleEndian.PutUint16(data[off:off+2], uint16(ethAddrOffset))
	off += 2
	data[off] = shortSelfIndex
	off++
	binary.LittleEndian.PutUint16(data[off:off+2], uint16(messageOffset))
	off += 2
	binary.LittleEndian.PutUint16(data[off:off+2], uint16(len(message)))
	off += 2
	data[off] = shortSelfIndex
	copy(data[sigOffset:], signature)
	copy(data[ethAddrOffset:], ethAddress)
	copy(data[messageOffset:], message)
	return solana.NewInstruction(Secp256k1PrecompileID, solana.AccountMetaSlice{}, data), nil
}

// BuildSecp256r1PrecompileInstruction returns a Solana instruction targeting
// the secp256r1 precompile. Pubkey must be 33 bytes (compressed P-256);
// signature must be 64 bytes (r||s, low-S enforced by the runtime).
func BuildSecp256r1PrecompileInstruction(pubkey, message, signature []byte) (*solana.GenericInstruction, error) {
	if len(pubkey) != secp256r1PubkeyLen {
		return nil, fmt.Errorf("secp256r1 pubkey must be %d bytes compressed (got %d)", secp256r1PubkeyLen, len(pubkey))
	}
	if len(signature) != secp256r1SigLen {
		return nil, fmt.Errorf("secp256r1 signature must be %d bytes r||s (got %d)", secp256r1SigLen, len(signature))
	}
	const headerLen = 2
	const offsetsLen = 14
	sigOffset := headerLen + offsetsLen
	pubkeyOffset := sigOffset + secp256r1SigLen
	messageOffset := pubkeyOffset + secp256r1PubkeyLen
	totalLen := messageOffset + len(message)

	data := make([]byte, totalLen)
	data[0] = 1
	data[1] = 0
	off := headerLen
	binary.LittleEndian.PutUint16(data[off:off+2], uint16(sigOffset))
	off += 2
	binary.LittleEndian.PutUint16(data[off:off+2], longSelfIndex)
	off += 2
	binary.LittleEndian.PutUint16(data[off:off+2], uint16(pubkeyOffset))
	off += 2
	binary.LittleEndian.PutUint16(data[off:off+2], longSelfIndex)
	off += 2
	binary.LittleEndian.PutUint16(data[off:off+2], uint16(messageOffset))
	off += 2
	binary.LittleEndian.PutUint16(data[off:off+2], uint16(len(message)))
	off += 2
	binary.LittleEndian.PutUint16(data[off:off+2], longSelfIndex)
	copy(data[sigOffset:], signature)
	copy(data[pubkeyOffset:], pubkey)
	copy(data[messageOffset:], message)
	return solana.NewInstruction(Secp256r1PrecompileID, solana.AccountMetaSlice{}, data), nil
}

// BuildCredentialPrecompile is the high-level entrypoint: given a member slot,
// the challenge bytes, and the off-chain signature (plus optional WebAuthn
// payloads), pick the right precompile and build the instruction.
//
// For SchemeWebAuthn the on-chain signed message is
// `webauthnAuthData || sha256(webauthnClientDataJSON)` — the runtime verifies
// the precompile call against that, and the on-chain handler
// (`andromeda_auth::verify_webauthn`) cross-checks that the canonical
// challenge appears base64url-no-pad inside `clientDataJSON.challenge`.
func BuildCredentialPrecompile(
	slot [MemberSlotLen]byte,
	challenge [32]byte,
	signature []byte,
	webauthnAuthData []byte,
	webauthnClientDataJSON []byte,
) (*solana.GenericInstruction, error) {
	scheme := slot[0]
	switch scheme {
	case SchemeEd25519:
		return BuildEd25519PrecompileInstruction(slot[1:1+ed25519PubkeyLen], challenge[:], signature)
	case SchemeSecp256k1:
		return BuildSecp256k1PrecompileInstruction(slot[1:1+secp256k1EthAddr], challenge[:], signature)
	case SchemeSecp256r1:
		return BuildSecp256r1PrecompileInstruction(slot[1:1+secp256r1PubkeyLen], challenge[:], signature)
	case SchemeWebAuthn:
		if len(webauthnAuthData) == 0 || len(webauthnClientDataJSON) == 0 {
			return nil, fmt.Errorf("webauthn member requires authenticatorData and clientDataJSON")
		}
		// Reconstruct WebAuthn signed message = authData || sha256(cdj).
		cdjHash := Hashv(webauthnClientDataJSON)
		signed := make([]byte, len(webauthnAuthData)+32)
		copy(signed, webauthnAuthData)
		copy(signed[len(webauthnAuthData):], cdjHash[:])
		return BuildSecp256r1PrecompileInstruction(slot[1:1+secp256r1PubkeyLen], signed, signature)
	default:
		return nil, ErrUnsupportedScheme
	}
}
