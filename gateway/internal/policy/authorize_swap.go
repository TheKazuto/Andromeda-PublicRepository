package policy

import (
	"context"
	"encoding/hex"
	"fmt"

	"github.com/gagliardetto/solana-go"
)

// SwapAuthorizeInput carries the dWallet identity + message digest an intents
// swap needs to authorize a signature through the PolicyEngine. Authorization is
// entirely on-chain (the active rules) — there is no owner signature, exactly
// like POST /v1/policy/request-signature/submit and the oracle monitor firer.
//
// The MVP binds the normal path with a zero destination and no spending amount,
// matching scripts/smoke-cross-chain-v3.mjs (path=1, destination=32×0, amount=0).
type SwapAuthorizeInput struct {
	DwalletAddress          string
	InitAuthorityHashHex    string // hex32
	MessageDigestHex        string // hex32 (prepare-message digestHex)
	UserPubkeyHex           string // hex32 (dWallet owner pubkey)
	SignatureScheme         uint16
	IkaCurve                uint16
	IkaDWalletPubkeyHex     string // 1..96-byte curve pubkey hex
	IkaMsgMetadataDigestHex string // "" or hex32 (zero for Solana)
}

// AuthorizeResult is the landed approval tx + the slot it confirmed in (0 when
// not confirmed in time — the caller can resolve it from the tx signature).
type AuthorizeResult struct {
	TxSignature       string
	ApprovalSlot      uint64
	EngineAddress     string
	MetadataDigestHex string
}

// swapChallenge computes the request-signature challenge digest (and the derived
// engine + dwallet keys) for a swap. Normal path, zero destination, no spending
// binding — the same canonical inputs the on-chain program recomputes. Single
// source shared by AuthorizeSwap and SwapChallengeDigest so they never drift.
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
	var zero32 [32]byte
	metaInput := &RequestMetadataDigestInput{
		Engine:          engine,
		DWallet:         dwallet,
		MessageDigest:   msgDigest,
		Destination:     zero32,
		UserPubkey:      userPK,
		SignatureScheme: in.SignatureScheme,
		Path:            1, // AppliesNormal
		RulesGeneration: 0,
		Amount:          0,
		AssetIndex:      0,
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

// AuthorizeSwap computes the challenge, builds and lands the gas-sponsored
// request_signature transaction (auto-resolving the engine's active rule PDAs),
// and best-effort confirms its slot. It reuses the exact same assembler as the
// HTTP submit so the two never drift. Returns the approval tx signature + slot
// the orchestrator hands to POST /v1/dwallet/sign.
func (s *Service) AuthorizeSwap(ctx context.Context, in SwapAuthorizeInput) (AuthorizeResult, error) {
	if s.GasSponsor == nil {
		return AuthorizeResult{}, fmt.Errorf("gas sponsor not configured")
	}
	metaDigest, _, _, err := s.swapChallenge(in)
	if err != nil {
		return AuthorizeResult{}, err
	}
	var zero32 [32]byte
	req := requestSignatureSubmitRequest{
		DwalletAddress:          in.DwalletAddress,
		InitAuthorityHash:       in.InitAuthorityHashHex,
		MessageDigestHex:        in.MessageDigestHex,
		MetadataDigestHex:       hex.EncodeToString(metaDigest[:]),
		UserPubkeyHex:           in.UserPubkeyHex,
		SignatureScheme:         in.SignatureScheme,
		DestinationHex:          hex.EncodeToString(zero32[:]),
		RulesGeneration:         0,
		AutoResolveAccounts:     true,
		IkaCurve:                in.IkaCurve,
		IkaDWalletPubkey:        in.IkaDWalletPubkeyHex,
		IkaMsgMetadataDigestHex: in.IkaMsgMetadataDigestHex,
	}

	mainIx, engineOut, _, auxCaches, berr := s.assembleRequestSignatureIx(ctx, &req, s.GasSponsor.PublicKey())
	if berr != nil {
		return AuthorizeResult{}, fmt.Errorf("assemble request_signature: %s", berr.msg)
	}

	// Refresh-on-sign: prepend a refresh_feed per sponsored FeedCache (best-effort).
	ixs := []solana.Instruction{mainIx}
	if s.oracleRefresher != nil && len(auxCaches) > 0 {
		if refreshIxs, rerr := s.oracleRefresher.RefreshIxs(ctx, auxCaches); rerr == nil && len(refreshIxs) > 0 {
			ixs = append(refreshIxs, mainIx)
		}
	}

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
