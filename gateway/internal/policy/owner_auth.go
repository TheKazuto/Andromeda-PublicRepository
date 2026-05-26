package policy

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"

	"github.com/gagliardetto/solana-go"
)

// SwapMeta carries the swap-specific clear-signing fields the on-chain handler
// binds when `signing_kind = SIGNING_KIND_SWAP`. Token addresses are 32-byte
// address-padded (mint for Solana, EVM contract zero-padded); `ChainTag` is
// ASCII null-padded (e.g. "solana\x00\x00", "evm:1\x00\x00\x00"). Symbols are
// NEVER bound on-chain — UI renders human names on top of the bound addresses.
type SwapMeta struct {
	FromToken    [32]byte
	ToToken      [32]byte
	MinAmountOut uint64
	ChainTag     [8]byte
}

// ValidateChainTag returns nil when `tag` matches the on-chain
// `swap_sign_message` renderer's contract: ASCII printable bytes
// (0x20..=0x7E) up to the first NUL, then zero-padding to 8 bytes. A non-NUL
// non-printable byte BEFORE the first NUL would make the Rust renderer fail
// with `HumanMessageError::NonAscii`, causing the request_signature tx to be
// rejected on-chain. Validating off-chain surfaces the problem in the gateway
// /challenge response instead of letting the dev waste gas on a doomed
// broadcast.
//
// Defense-in-depth helper: callers (Intents orchestrator, custom dev code) are
// expected to validate at the moment they encode the tag. `ComputeOwnerAuthChallenge`
// and `BuildOwnerAuthPrecompile` call this internally to guarantee end-to-end.
func ValidateChainTag(tag [8]byte) error {
	for i := 0; i < len(tag); i++ {
		b := tag[i]
		if b == 0 {
			// Trailing zeros — anything after the first NUL is allowed (and
			// ignored by the renderer).
			return nil
		}
		if b < 0x20 || b > 0x7E {
			return fmt.Errorf("chain_tag byte %d (0x%02x) is not printable ASCII", i, b)
		}
	}
	return nil
}

// BundleProof carries the bundle challenge proof for a single leg of a multi-
// digest bundle. `ThisIndex` is the position of THIS leg's metadata digest in
// the bundle; `OtherDigests` are the other legs' metadata digests in supplied
// order ((Total - 1) entries). Mirror of the on-chain bundle_use_challenge.
type BundleProof struct {
	Total        uint8 // 2..=MaxBundleTotal
	ThisIndex    uint8 // 0..=Total-1
	OtherDigests [][32]byte
}

// OwnerAuthInput carries every input needed to recompute the Fase 1 (A1)
// owner-authorization challenge and build the precompile instruction the
// gateway relays alongside `request_signature` (disc 1).
//
// Update 7 (2026-05-26): `Swap` (optional) selects the SWAP signing kind +
// swap_use_challenge / bundle_use_challenge variants. `Bundle` (optional)
// selects the multi-digest bundle challenge. Both can be set together (a SWAP
// leg participating in a bundle) — the on-chain handler reconstructs the same
// hash from the bundle proof + per-leg swap metadata.
type OwnerAuthInput struct {
	OwnerSlot              [MemberSlotLen]byte
	SignatureBase64        string
	WebauthnAuthDataBase64 string
	WebauthnCDJBase64      string

	Engine, DWallet solana.PublicKey
	MetadataDigest  [32]byte
	Destination     [32]byte
	Amount          uint64
	SignatureScheme uint16

	// Optional — when non-nil, the SWAP signing kind is used and the human
	// message renders the semantic swap fields.
	Swap *SwapMeta

	// Optional — when non-nil, the bundle challenge variant is used.
	Bundle *BundleProof
}

// OwnerAuthChallenge is the payload the client gets back from a `/challenge`
// route so the dWallet owner can sign off-chain. `OwnerAuthChallengeHex` is
// the 32-byte digest to sign; the rest is informational (lets a UI render
// what is being authorized + lets the client verify the gateway didn't lie).
type OwnerAuthChallenge struct {
	OwnerAuthChallengeHex string
	OwnerAuthPreimageHex  string
	HumanMessage          string
}

// ComputeOwnerAuthChallenge builds the owner-authorization challenge for the
// given inputs without consuming a signature — used by `/v1/intents/swap/challenge`
// and any future challenge surface that needs to expose the digest to the
// owner before they sign. Ramifies on (Swap, Bundle):
//   - Swap=nil, Bundle=nil: legacy `normal_use_challenge`.
//   - Swap=set, Bundle=nil: `swap_use_challenge` (semantic swap clear-signing).
//   - Swap=nil, Bundle=set: `bundle_use_challenge` with op_tag = OpNormalSign.
//   - Swap=set, Bundle=set: `bundle_use_challenge` with op_tag = OpSwapSign.
func ComputeOwnerAuthChallenge(in OwnerAuthInput) (OwnerAuthChallenge, error) {
	if in.Swap != nil {
		if err := ValidateChainTag(in.Swap.ChainTag); err != nil {
			return OwnerAuthChallenge{}, fmt.Errorf("invalid swap chain_tag: %w", err)
		}
	}
	human, opTag := renderHumanForOwnerAuth(in)

	if in.Bundle != nil {
		bc := &BundleUseChallengeInput{
			Engine:             in.Engine,
			DWallet:            in.DWallet,
			ThisMetadataDigest: in.MetadataDigest,
			OwnerSlot:          in.OwnerSlot,
			Total:              in.Bundle.Total,
			ThisIndex:          in.Bundle.ThisIndex,
			OtherDigests:       in.Bundle.OtherDigests,
		}
		preimage, err := bc.Preimage()
		if err != nil {
			return OwnerAuthChallenge{}, err
		}
		challenge, err := bc.Hash()
		if err != nil {
			return OwnerAuthChallenge{}, err
		}
		// `human` / `opTag` are informational (UI overlay) — not bound to the
		// bundle hash. Return them so the wallet can still show a meaningful
		// per-leg clear-signing line, while ALL legs share the same challenge.
		_ = opTag
		return OwnerAuthChallenge{
			OwnerAuthChallengeHex: hex.EncodeToString(challenge[:]),
			OwnerAuthPreimageHex:  hex.EncodeToString(preimage),
			HumanMessage:          string(human),
		}, nil
	}

	if in.Swap != nil {
		sc := &SwapUseChallengeInput{
			HumanMessage:   human,
			Engine:         in.Engine,
			DWallet:        in.DWallet,
			MetadataDigest: in.MetadataDigest,
			OwnerSlot:      in.OwnerSlot,
		}
		preimage := sc.Preimage()
		challenge := sc.Hash()
		return OwnerAuthChallenge{
			OwnerAuthChallengeHex: hex.EncodeToString(challenge[:]),
			OwnerAuthPreimageHex:  hex.EncodeToString(preimage),
			HumanMessage:          string(human),
		}, nil
	}

	nuc := &NormalUseChallengeInput{
		HumanMessage:   human,
		Engine:         in.Engine,
		DWallet:        in.DWallet,
		MetadataDigest: in.MetadataDigest,
		OwnerSlot:      in.OwnerSlot,
	}
	preimage := nuc.Preimage()
	challenge := nuc.Hash()
	return OwnerAuthChallenge{
		OwnerAuthChallengeHex: hex.EncodeToString(challenge[:]),
		OwnerAuthPreimageHex:  hex.EncodeToString(preimage),
		HumanMessage:          string(human),
	}, nil
}

// renderHumanForOwnerAuth picks the right clear-signing renderer for the input
// and returns (human_bytes, op_tag). The op tag is used by the bundle variant
// (each leg's bundle hash includes its own op tag).
func renderHumanForOwnerAuth(in OwnerAuthInput) ([]byte, []byte) {
	if in.Swap != nil {
		return HumanMessageSwap(in.DWallet, in.Swap.FromToken, in.Amount, in.Swap.ToToken, in.Swap.MinAmountOut, in.Swap.ChainTag, in.SignatureScheme), OpSwapSign
	}
	return HumanMessageNormalSign(in.DWallet, in.Destination, in.Amount, in.SignatureScheme), OpNormalSign
}

// BuildOwnerAuthPrecompile recomputes the owner-authorization challenge
// defensively (so a tampered client value can't substitute the digest) and
// assembles the Solana precompile instruction that proves the dWallet owner
// authorized the signature. Pure function — no HTTP, no logging — so HTTP
// handlers and the programmatic `AuthorizeSwap` path share the same code.
func BuildOwnerAuthPrecompile(in OwnerAuthInput) (solana.Instruction, error) {
	if in.SignatureBase64 == "" {
		return nil, fmt.Errorf("owner_auth_required: signature_base64 is required")
	}
	sig, err := base64.StdEncoding.DecodeString(in.SignatureBase64)
	if err != nil {
		return nil, fmt.Errorf("signature_base64: %w", err)
	}
	var authData, cdj []byte
	if in.WebauthnAuthDataBase64 != "" {
		if authData, err = base64.StdEncoding.DecodeString(in.WebauthnAuthDataBase64); err != nil {
			return nil, fmt.Errorf("webauthn_auth_data_base64: %w", err)
		}
	}
	if in.WebauthnCDJBase64 != "" {
		if cdj, err = base64.StdEncoding.DecodeString(in.WebauthnCDJBase64); err != nil {
			return nil, fmt.Errorf("webauthn_cdj_base64: %w", err)
		}
	}
	ch, err := ComputeOwnerAuthChallenge(in)
	if err != nil {
		return nil, err
	}
	challenge, _ := mustHex32(ch.OwnerAuthChallengeHex)
	ix, err := buildCredentialPrecompile(in.OwnerSlot, challenge, sig, authData, cdj)
	if err != nil {
		return nil, fmt.Errorf("invalid_signature: %w", err)
	}
	return ix, nil
}
