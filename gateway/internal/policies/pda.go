package policies

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"

	"github.com/gagliardetto/solana-go"
)

var (
	cpiAuthoritySeed = []byte("__ika_cpi_authority")
	dwalletSeed      = []byte("dwallet")
	allowlistSeed    = []byte("allowlist")
	velocitySeed     = []byte("velocity")
	timelockSeed     = []byte("timelock")
	sessionKeysSeed  = []byte("session_key")
	oracleSeed       = []byte("oracle")
	passkeySeed      = []byte("passkey")
	fheGatedSeed     = []byte("fhe_gated")
	msgApprovalSeed  = []byte("message_approval")
)

// MemberSlotLen is the canonical 34-byte slot length matching `auth.MemberSlotLen`.
const MemberSlotLen = 34

// InitAuthorityHashFromSlot computes sha256(slot) — the 32-byte hash that
// participates in the policy PDA seed (Audit C2 / Opção 4). Each
// (dwallet, init_authority) pair produces a distinct PDA.
func InitAuthorityHashFromSlot(slot [MemberSlotLen]byte) [32]byte {
	return sha256.Sum256(slot[:])
}

// PolicyPDA returns the policy account PDA for non-session-keys templates.
// Seeds: [<template-prefix>, dwallet_pubkey, init_authority_hash].
//
// Audit C2 (Opção 4): the seed includes init_authority_hash so multiple
// initializations cannot collide on the same dwallet — squat-resistant.
//
// For session-keys, use SessionKeyPolicyPDA — its seed adds session_index.
func PolicyPDA(templateName string, programID, dwallet solana.PublicKey, initAuthorityHash [32]byte) (solana.PublicKey, uint8, error) {
	var seedPrefix []byte
	switch templateName {
	case TemplateAllowlist:
		seedPrefix = allowlistSeed
	case TemplateVelocityGuard:
		seedPrefix = velocitySeed
	case TemplateTimeLock:
		seedPrefix = timelockSeed
	case TemplateOracleConditional:
		seedPrefix = oracleSeed
	case TemplatePasskeyStepUp:
		seedPrefix = passkeySeed
	case TemplateFHEGated:
		seedPrefix = fheGatedSeed
	case TemplateSessionKeys:
		return solana.PublicKey{}, 0, fmt.Errorf("use SessionKeyPolicyPDA for session-keys (needs session_index)")
	default:
		return solana.PublicKey{}, 0, ErrUnknownTemplate
	}
	return solana.FindProgramAddress([][]byte{seedPrefix, dwallet.Bytes(), initAuthorityHash[:]}, programID)
}

// SessionKeyPolicyPDA returns the session-keys policy PDA.
// Seeds: ["session_key", dwallet_pubkey, init_authority_hash, session_index_le_u32].
//
// Audit H6: session_index in the seed allows multiple sessions per
// (dwallet, init_authority) — owner can run sessions to dApp A and dApp B
// simultaneously without cross-interference.
func SessionKeyPolicyPDA(programID, dwallet solana.PublicKey, initAuthorityHash [32]byte, sessionIndex uint32) (solana.PublicKey, uint8, error) {
	var idxBytes [4]byte
	binary.LittleEndian.PutUint32(idxBytes[:], sessionIndex)
	return solana.FindProgramAddress(
		[][]byte{sessionKeysSeed, dwallet.Bytes(), initAuthorityHash[:], idxBytes[:]},
		programID,
	)
}

// CPIAuthorityPDA returns the CPI authority PDA for an Andromeda template.
// Seeds: ["__ika_cpi_authority"]. The dWallet's authority must be set to this
// PDA for the template to be allowed to approve messages on its behalf.
func CPIAuthorityPDA(programID solana.PublicKey) (solana.PublicKey, uint8, error) {
	return solana.FindProgramAddress([][]byte{cpiAuthoritySeed}, programID)
}

// MessageApprovalPDA derives the Ika MessageApproval PDA the way the dWallet
// program expects, matching the documented layout in
// `ika-pre-alpha/docs/src/reference/accounts.md`:
//
//	seeds = ["dwallet", chunks_of(curve_u16_le || dwallet_public_key),
//	         "message_approval", scheme_u16_le, message_digest, [meta_digest]]
//
// `metaDigest` is omitted from the seeds when all 32 bytes are zero (the
// "no metadata" sentinel).
func MessageApprovalPDA(
	ikaProgramID solana.PublicKey,
	curve uint16,
	dwalletPublicKey []byte,
	scheme uint16,
	messageDigest []byte,
	metaDigest []byte,
) (solana.PublicKey, uint8, error) {
	if len(messageDigest) != 32 {
		return solana.PublicKey{}, 0, fmt.Errorf("message_digest must be 32 bytes, got %d", len(messageDigest))
	}
	if len(metaDigest) != 32 {
		return solana.PublicKey{}, 0, fmt.Errorf("meta_digest must be 32 bytes, got %d", len(metaDigest))
	}

	var schemeBytes [2]byte
	binary.LittleEndian.PutUint16(schemeBytes[:], scheme)

	seeds := [][]byte{dwalletSeed}
	for _, chunk := range chunkDwalletSeedPayload(curve, dwalletPublicKey) {
		seeds = append(seeds, chunk)
	}
	seeds = append(seeds, msgApprovalSeed)
	seeds = append(seeds, schemeBytes[:])
	seeds = append(seeds, messageDigest)
	if !isAllZero(metaDigest) {
		seeds = append(seeds, metaDigest)
	}
	return solana.FindProgramAddress(seeds, ikaProgramID)
}

// chunkDwalletSeedPayload concatenates `curve_u16_le || pk` and splits it into
// pieces of at most 32 bytes (Solana's MAX_SEED_LEN). Returns the per-seed
// slices in the order the dWallet program expects.
func chunkDwalletSeedPayload(curve uint16, pk []byte) [][]byte {
	buf := make([]byte, 2+len(pk))
	binary.LittleEndian.PutUint16(buf[0:2], curve)
	copy(buf[2:], pk)
	chunks := make([][]byte, 0, (len(buf)+31)/32)
	for i := 0; i < len(buf); i += 32 {
		end := i + 32
		if end > len(buf) {
			end = len(buf)
		}
		chunks = append(chunks, buf[i:end])
	}
	return chunks
}

// DWalletPDA derives the DWallet account PDA from `(curve, public_key)`. The
// dWallet pubkey we treat as `dwallet_account` everywhere else is exactly this
// PDA.
func DWalletPDA(ikaProgramID solana.PublicKey, curve uint16, pk []byte) (solana.PublicKey, uint8, error) {
	chunks := chunkDwalletSeedPayload(curve, pk)
	seeds := [][]byte{dwalletSeed}
	for _, c := range chunks {
		seeds = append(seeds, c)
	}
	return solana.FindProgramAddress(seeds, ikaProgramID)
}

func isAllZero(b []byte) bool {
	for _, x := range b {
		if x != 0 {
			return false
		}
	}
	return true
}
