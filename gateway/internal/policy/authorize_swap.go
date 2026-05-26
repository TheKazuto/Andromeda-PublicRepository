package policy

import (
	"context"
	"encoding/hex"
	"fmt"

	"github.com/gagliardetto/solana-go"
)

// SwapAuthorizeInput carries the dWallet identity, message digest and the
// dWallet owner's authorization an intents swap needs to authorize a signature
// through the PolicyEngine. Zero-trust (Fase 1, A1): the owner signs the
// `normal_use_challenge` off-chain and the gateway relays the precompile —
// AuthorizeSwap no longer signs in the user's place.
//
// `Destination` + `Amount` + `AssetIndex` are the real swap parameters bound
// into the metadata digest (and therefore into the challenge the owner signs),
// so a gateway compromise can't relay an approval for a different transaction.
type SwapAuthorizeInput struct {
	DwalletAddress          string
	InitAuthorityHashHex    string // hex32
	MessageDigestHex        string // hex32 (prepare-message digestHex)
	UserPubkeyHex           string // hex32 (dWallet owner pubkey)
	SignatureScheme         uint16
	IkaCurve                uint16
	IkaDWalletPubkeyHex     string // 1..96-byte curve pubkey hex
	IkaMsgMetadataDigestHex string // "" or hex32 (zero for Solana)

	// Spending binding (real swap destination + value). Empty / zero defaults
	// keep ChallengeDigest computations backwards-compatible with no spending
	// rule active.
	DestinationHex string // "" or hex32
	Amount         uint64
	AssetIndex     uint8

	// Owner authorization (mandatory at submit time; omitted at challenge time).
	OwnerSlotHex             string // hex (MemberSlotLen×2 chars) — scheme+identifier
	OwnerSignatureBase64     string
	OwnerWebAuthnAuthDataB64 string
	OwnerWebAuthnCDJB64      string

	// Update 7 (2026-05-26): when non-nil, selects the SWAP signing kind. The
	// owner sees a semantic swap clear-signing message ("Swap X of <from_token>
	// for at least Y of <to_token> on <chain>") and the metadata_digest binds
	// the swap fields (V3) so a gateway compromise can't relay an approval for
	// a different token/route.
	Swap *SwapMeta

	// Update 7 (2026-05-26): when non-nil, this leg participates in a multi-
	// digest bundle. One owner signature covers `Bundle.Total` distinct
	// request_signature legs (e.g. EVM 2-step approve+swap). The on-chain
	// handler recomputes the same `bundle_use_challenge` hash from each leg's
	// own viewpoint, so the same signature unlocks each leg.
	Bundle *BundleProof
}

// AuthorizeResult is the landed approval tx + the slot it confirmed in (0 when
// not confirmed in time — the caller can resolve it from the tx signature).
type AuthorizeResult struct {
	TxSignature       string
	ApprovalSlot      uint64
	EngineAddress     string
	MetadataDigestHex string
}

// swapChallenge computes the request-signature challenge digest (and the
// derived engine + dwallet keys) for a swap. Binds the real destination +
// amount + asset_index so the same digest the owner signs is what the on-chain
// program recomputes. Single source shared by AuthorizeSwap, SwapChallengeDigest
// and SwapOwnerAuthChallenge so they never drift.
//
// Update 7 (2026-05-26): when `in.Swap != nil`, computes the V3 swap metadata
// digest (`swap_metadata_digest`); otherwise the V2 normal metadata digest.
func (s *Service) swapChallenge(in SwapAuthorizeInput) (metaDigest [32]byte, engine, dwallet solana.PublicKey, err error) {
	dwallet, err = solana.PublicKeyFromBase58(in.DwalletAddress)
	if err != nil {
		return metaDigest, engine, dwallet, fmt.Errorf("invalid dwallet address: %w", err)
	}
	initHash, err := mustHex32(in.InitAuthorityHashHex)
	if err != nil {
		return metaDigest, engine, dwallet, fmt.Errorf("invalid init_authority_hash: %w", err)
	}
	msgDigest, err := mustHex32(in.MessageDigestHex)
	if err != nil {
		return metaDigest, engine, dwallet, fmt.Errorf("invalid message_digest: %w", err)
	}
	userPK, err := mustHex32(in.UserPubkeyHex)
	if err != nil {
		return metaDigest, engine, dwallet, fmt.Errorf("invalid user_pubkey: %w", err)
	}
	engine, _, err = EnginePDA(s.ProgramID, dwallet, initHash)
	if err != nil {
		return metaDigest, engine, dwallet, fmt.Errorf("engine pda: %w", err)
	}
	dest, err := optionalHex32(in.DestinationHex)
	if err != nil {
		return metaDigest, engine, dwallet, fmt.Errorf("invalid destination_hex: %w", err)
	}
	if in.Swap != nil {
		swapInput := &SwapMetadataDigestInput{
			Engine:          engine,
			DWallet:         dwallet,
			MessageDigest:   msgDigest,
			Destination:     dest,
			UserPubkey:      userPK,
			SignatureScheme: in.SignatureScheme,
			RulesGeneration: 0,
			FromAmount:      in.Amount,
			AssetIndex:      in.AssetIndex,
			FromToken:       in.Swap.FromToken,
			ToToken:         in.Swap.ToToken,
			MinAmountOut:    in.Swap.MinAmountOut,
			ChainTag:        in.Swap.ChainTag,
		}
		return swapInput.Hash(), engine, dwallet, nil
	}
	metaInput := &RequestMetadataDigestInput{
		Engine:          engine,
		DWallet:         dwallet,
		MessageDigest:   msgDigest,
		Destination:     dest,
		UserPubkey:      userPK,
		SignatureScheme: in.SignatureScheme,
		Path:            1, // AppliesNormal
		RulesGeneration: 0,
		Amount:          in.Amount,
		AssetIndex:      in.AssetIndex,
	}
	return metaInput.Hash(), engine, dwallet, nil
}

// SwapChallengeDigest returns the request-signature challenge digest (hex) for a
// swap. It is the presign-prefetch cache key the intents orchestrator uses at
// prepare time, and equals the MetadataDigestHex AuthorizeSwap returns at submit.
func (s *Service) SwapChallengeDigest(in SwapAuthorizeInput) (string, error) {
	meta, _, _, err := s.swapChallenge(in)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(meta[:]), nil
}

// SwapOwnerAuthChallenge derives the owner-authorization challenge the
// dWallet owner must sign off-chain before AuthorizeSwap can relay the
// precompile. Pure computation (no network, no signing) — called by the
// intents orchestrator's `/swap/challenge` route. `OwnerSlotHex` is required.
//
// Ramifies on (in.Swap, in.Bundle):
//   - both nil: legacy NORMAL single-digest challenge.
//   - Swap set, Bundle nil: SWAP single-digest challenge (semantic clear-signing).
//   - Bundle set (Swap may be set): bundle challenge variant.
func (s *Service) SwapOwnerAuthChallenge(in SwapAuthorizeInput) (OwnerAuthChallenge, error) {
	if in.OwnerSlotHex == "" {
		return OwnerAuthChallenge{}, fmt.Errorf("owner_slot_hex is required")
	}
	ownerSlot, err := decodeMemberSlotHex(in.OwnerSlotHex)
	if err != nil {
		return OwnerAuthChallenge{}, fmt.Errorf("invalid owner_slot_hex: %w", err)
	}
	meta, engine, dwallet, err := s.swapChallenge(in)
	if err != nil {
		return OwnerAuthChallenge{}, err
	}
	dest, err := optionalHex32(in.DestinationHex)
	if err != nil {
		return OwnerAuthChallenge{}, fmt.Errorf("invalid destination_hex: %w", err)
	}
	return ComputeOwnerAuthChallenge(OwnerAuthInput{
		OwnerSlot:       ownerSlot,
		Engine:          engine,
		DWallet:         dwallet,
		MetadataDigest:  meta,
		Destination:     dest,
		Amount:          in.Amount,
		SignatureScheme: in.SignatureScheme,
		Swap:            in.Swap,
		Bundle:          in.Bundle,
	})
}

// AuthorizeSwap computes the challenge, builds and lands the gas-sponsored
// request_signature transaction (auto-resolving the engine's active rule PDAs),
// and best-effort confirms its slot. Reuses the exact same assembler as the
// HTTP submit so the two never drift. Returns the approval tx signature + slot
// the orchestrator hands to POST /v1/dwallet/sign.
//
// Zero-trust contract (Fase 1, A1): `OwnerSlotHex` + `OwnerSignatureBase64`
// are mandatory; the owner must have signed the `normal_use_challenge` (which
// binds metadata_digest + destination + amount + scheme) off-chain. Without
// them this fails fast with a clear error — never relays a signature the on-
// chain handler would reject.
func (s *Service) AuthorizeSwap(ctx context.Context, in SwapAuthorizeInput) (AuthorizeResult, error) {
	if in.OwnerSlotHex == "" || in.OwnerSignatureBase64 == "" {
		return AuthorizeResult{}, fmt.Errorf("owner_auth_required: owner_slot_hex + owner_signature_base64 are required (zero-trust)")
	}
	ownerSlot, err := decodeMemberSlotHex(in.OwnerSlotHex)
	if err != nil {
		return AuthorizeResult{}, fmt.Errorf("invalid owner_slot_hex: %w", err)
	}
	if s.GasSponsor == nil {
		return AuthorizeResult{}, fmt.Errorf("gas sponsor not configured")
	}
	metaDigest, _, _, err := s.swapChallenge(in)
	if err != nil {
		return AuthorizeResult{}, err
	}
	dest, err := optionalHex32(in.DestinationHex)
	if err != nil {
		return AuthorizeResult{}, fmt.Errorf("invalid destination_hex: %w", err)
	}
	req := requestSignatureSubmitRequest{
		DwalletAddress:          in.DwalletAddress,
		InitAuthorityHash:       in.InitAuthorityHashHex,
		MessageDigestHex:        in.MessageDigestHex,
		MetadataDigestHex:       hex.EncodeToString(metaDigest[:]),
		UserPubkeyHex:           in.UserPubkeyHex,
		SignatureScheme:         in.SignatureScheme,
		DestinationHex:          hex.EncodeToString(dest[:]),
		RulesGeneration:         0,
		AutoResolveAccounts:     true,
		IkaCurve:                in.IkaCurve,
		IkaDWalletPubkey:        in.IkaDWalletPubkeyHex,
		IkaMsgMetadataDigestHex: in.IkaMsgMetadataDigestHex,
		Amount:                  in.Amount,
		AssetIndex:              in.AssetIndex,
		Swap:                    in.Swap,
		Bundle:                  in.Bundle,
	}

	mainIx, engineOut, dwalletOut, auxCaches, berr := s.assembleRequestSignatureIx(ctx, &req, s.GasSponsor.PublicKey())
	if berr != nil {
		return AuthorizeResult{}, fmt.Errorf("assemble request_signature: %s", berr.msg)
	}

	ownerPrecompile, err := BuildOwnerAuthPrecompile(OwnerAuthInput{
		OwnerSlot:              ownerSlot,
		SignatureBase64:        in.OwnerSignatureBase64,
		WebauthnAuthDataBase64: in.OwnerWebAuthnAuthDataB64,
		WebauthnCDJBase64:      in.OwnerWebAuthnCDJB64,
		Engine:                 engineOut,
		DWallet:                dwalletOut,
		MetadataDigest:         metaDigest,
		Destination:            dest,
		Amount:                 in.Amount,
		SignatureScheme:        in.SignatureScheme,
		Swap:                   in.Swap,
		Bundle:                 in.Bundle,
	})
	if err != nil {
		return AuthorizeResult{}, fmt.Errorf("build owner_auth precompile: %w", err)
	}

	// Order: [owner_auth_precompile, refresh_feed*, request_signature].
	ixs := []solana.Instruction{ownerPrecompile}
	if s.oracleRefresher != nil && len(auxCaches) > 0 {
		if refreshIxs, rerr := s.oracleRefresher.RefreshIxs(ctx, auxCaches); rerr == nil && len(refreshIxs) > 0 {
			ixs = append(ixs, refreshIxs...)
		}
	}
	ixs = append(ixs, mainIx)

	sigOut, err := s.GasSponsor.SignAndSend(ctx, ixs)
	if err != nil {
		return AuthorizeResult{}, fmt.Errorf("send request_signature: %w", err)
	}

	return AuthorizeResult{
		TxSignature:       sigOut.String(),
		ApprovalSlot:      s.confirmApprovalSlot(ctx, sigOut),
		EngineAddress:     engineOut.String(),
		MetadataDigestHex: hex.EncodeToString(metaDigest[:]),
	}, nil
}

// optionalHex32 decodes a hex32 string into [32]byte. Empty string yields a
// zero array (the on-chain handler treats zero destination as "no allowlist
// bind" for non-spending paths).
func optionalHex32(s string) ([32]byte, error) {
	var out [32]byte
	if s == "" {
		return out, nil
	}
	return mustHex32(s)
}

// decodeMemberSlotHex parses a `MemberSlotLen` (1+32) byte slot in hex. First
// byte is the scheme; the rest is the identifier. The scheme's expected
// identifier length (mirror of `andromeda_auth::idLenForScheme`) is enforced
// further down by the precompile builder when assembling the credential.
func decodeMemberSlotHex(s string) ([MemberSlotLen]byte, error) {
	var out [MemberSlotLen]byte
	b, err := hex.DecodeString(s)
	if err != nil {
		return out, err
	}
	if len(b) != MemberSlotLen {
		return out, fmt.Errorf("owner_slot_hex: expected %d bytes, got %d", MemberSlotLen, len(b))
	}
	copy(out[:], b)
	return out, nil
}
