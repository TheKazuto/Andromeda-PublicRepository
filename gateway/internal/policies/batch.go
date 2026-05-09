package policies

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gagliardetto/solana-go"
	"github.com/gagliardetto/solana-go/rpc"
)

// Auto-batching (Andromeda Features Roadmap §11) bundles N request_signature
// instructions into K transactions, respecting Solana's 1232-byte raw
// transaction size limit. Each tx still hits the same policy program(s);
// devs that sign in volume avoid paying base-fee + rent for every signature.
//
// We greedily pack instructions into a tx until either:
//   - max_per_tx is reached (default 8), OR
//   - the next instruction would push the encoded tx past `txSizeLimit`.
//
// The endpoint returns one entry per resulting tx, each with its
// `unsigned_tx_base64` and the slice of original `request_indices` it covers.

// Conservative ceiling — Solana hard limit is 1232 bytes, but we leave room
// for the dev's own signing overhead.
const txSizeLimit = 1180

type batchReq struct {
	Requests  []requestSignatureReq `json:"requests"`
	MaxPerTx  int                   `json:"max_per_tx,omitempty"` // default 8
}

type batchResp struct {
	Batches []batchEntry `json:"batches"`
}

type batchEntry struct {
	UnsignedTxBase64 string `json:"unsigned_tx_base64"`
	RequestIndices   []int  `json:"request_indices"`
	SizeBytes        int    `json:"size_bytes"`
}

// batch is the handler for POST /v1/signatures/batch. Mounted from
// MountRoutes; see Andromeda Features Roadmap §11.
func (s *Service) batch(w http.ResponseWriter, r *http.Request) {
	var req batchReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid_body", "invalid JSON body")
		return
	}
	if len(req.Requests) == 0 {
		writeErr(w, http.StatusBadRequest, "empty_batch", "requests must be non-empty")
		return
	}
	if len(req.Requests) > 64 {
		writeErr(w, http.StatusBadRequest, "batch_too_large", "max 64 requests per call")
		return
	}
	maxPerTx := req.MaxPerTx
	if maxPerTx <= 0 || maxPerTx > 16 {
		maxPerTx = 8
	}

	// Build every instruction up-front so we can size-pack them.
	type buildOut struct {
		idx int
		ix  solana.Instruction
		// `payer` is whatever payer the dev specified for THIS request.
		// We require all payers to match in a single batch — mixed-payer
		// batches don't fit Solana's tx-payer model anyway.
		payer solana.PublicKey
	}
	built := make([]buildOut, 0, len(req.Requests))
	var firstPayer solana.PublicKey
	for i, sub := range req.Requests {
		ix, payer, err := s.buildRequestSigInstruction(r.Context(), sub)
		if err != nil {
			writeErr(w, http.StatusBadRequest, "build_failed",
				fmt.Sprintf("requests[%d]: %v", i, err))
			return
		}
		if i == 0 {
			firstPayer = payer
		} else if !payer.Equals(firstPayer) {
			writeErr(w, http.StatusBadRequest, "payer_mismatch",
				fmt.Sprintf("requests[%d] payer %s != requests[0] %s — batch requires a single payer",
					i, payer, firstPayer))
			return
		}
		built = append(built, buildOut{idx: i, ix: ix, payer: payer})
	}

	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	recent, err := s.RPCClient.GetLatestBlockhash(ctx, rpc.CommitmentConfirmed)
	if err != nil {
		writeErr(w, http.StatusBadGateway, "blockhash_failed", err.Error())
		return
	}

	out := batchResp{Batches: make([]batchEntry, 0)}
	current := []buildOut{}
	flush := func() error {
		if len(current) == 0 {
			return nil
		}
		ixs := make([]solana.Instruction, 0, len(current))
		idxs := make([]int, 0, len(current))
		for _, b := range current {
			ixs = append(ixs, b.ix)
			idxs = append(idxs, b.idx)
		}
		tx, err := solana.NewTransaction(ixs, recent.Value.Blockhash, solana.TransactionPayer(firstPayer))
		if err != nil {
			return fmt.Errorf("build batch tx: %w", err)
		}
		raw, err := tx.MarshalBinary()
		if err != nil {
			return fmt.Errorf("marshal batch tx: %w", err)
		}
		out.Batches = append(out.Batches, batchEntry{
			UnsignedTxBase64: base64.StdEncoding.EncodeToString(raw),
			RequestIndices:   idxs,
			SizeBytes:        len(raw),
		})
		current = current[:0]
		return nil
	}

	for _, b := range built {
		// Trial-pack: tentative add → marshal → measure → roll back if oversized.
		probe := append(append([]buildOut(nil), current...), b)
		ixs := make([]solana.Instruction, 0, len(probe))
		for _, p := range probe {
			ixs = append(ixs, p.ix)
		}
		tx, err := solana.NewTransaction(ixs, recent.Value.Blockhash, solana.TransactionPayer(firstPayer))
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "tx_build_failed", err.Error())
			return
		}
		raw, err := tx.MarshalBinary()
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "tx_marshal_failed", err.Error())
			return
		}
		// If a single ix already overflows, the batch can never include it.
		if len(current) == 0 && len(raw) > txSizeLimit {
			writeErr(w, http.StatusBadRequest, "request_too_large",
				fmt.Sprintf("requests[%d] alone is %d bytes (>%d)", b.idx, len(raw), txSizeLimit))
			return
		}
		if len(raw) > txSizeLimit || len(current) >= maxPerTx {
			if err := flush(); err != nil {
				writeErr(w, http.StatusInternalServerError, "flush_failed", err.Error())
				return
			}
		}
		current = append(current, b)
	}
	if err := flush(); err != nil {
		writeErr(w, http.StatusInternalServerError, "flush_failed", err.Error())
		return
	}

	writeJSON(w, http.StatusOK, out)
}

// buildRequestSigInstruction is the shared builder used by both the single
// request_signature endpoint and the batch endpoint. Returns the ix + the
// payer used for transaction-level signing.
func (s *Service) buildRequestSigInstruction(ctx context.Context, req requestSignatureReq) (solana.Instruction, solana.PublicKey, error) {
	_ = ctx // reserved for future per-request RPC calls
	template := normaliseTemplate(req)
	if template == "" {
		return nil, solana.PublicKey{}, fmt.Errorf("request_signature has no template — set template field on each request")
	}
	if s.GasSponsor == nil {
		return nil, solana.PublicKey{}, fmt.Errorf("gas sponsor not configured (ANDROMEDA_GAS_SPONSOR_KEYPAIR)")
	}
	dwallet, err := solana.PublicKeyFromBase58(req.DwalletAddress)
	if err != nil {
		return nil, solana.PublicKey{}, fmt.Errorf("dwallet_address: %w", err)
	}
	// Audit C2 (Opção 4): every batch entry must include init_authority_hash
	// for the gateway to derive the policy PDA.
	initAuthorityHash, err := decodeInitAuthorityHash(req.InitAuthorityHashBase64)
	if err != nil {
		return nil, solana.PublicKey{}, fmt.Errorf("init_authority_hash_base64: %w", err)
	}
	// In v2 the gas sponsor is the single fee payer of every batch tx — no
	// per-request payer override and no `owner != payer` constraint.
	payer := s.GasSponsor.PublicKey()
	msg, err := decodeFixed32(req.MessageDigestB64)
	if err != nil {
		return nil, solana.PublicKey{}, fmt.Errorf("message_digest_base64: %w", err)
	}
	meta := [32]byte{}
	if req.MetadataDigestB64 != "" {
		meta, err = decodeFixed32(req.MetadataDigestB64)
		if err != nil {
			return nil, solana.PublicKey{}, fmt.Errorf("metadata_digest_base64: %w", err)
		}
	}
	user, err := decodeFixed32(req.UserPubkeyB64)
	if err != nil {
		return nil, solana.PublicKey{}, fmt.Errorf("user_pubkey_base64: %w", err)
	}
	if req.DwalletPublicKeyB64 == "" {
		return nil, solana.PublicKey{}, fmt.Errorf("dwallet_public_key_base64 required")
	}
	dwalletPK, err := base64.StdEncoding.DecodeString(req.DwalletPublicKeyB64)
	if err != nil {
		return nil, solana.PublicKey{}, fmt.Errorf("dwallet_public_key_base64: %w", err)
	}
	switch len(dwalletPK) {
	case 32, 33, 65:
	default:
		return nil, solana.PublicKey{}, fmt.Errorf("dwallet_public_key must be 32/33/65 bytes")
	}
	_, msgBump, err := MessageApprovalPDA(
		s.Registry.IkaProgramID,
		req.DwalletCurve, dwalletPK, req.SignatureScheme,
		msg[:], meta[:],
	)
	if err != nil {
		return nil, solana.PublicKey{}, fmt.Errorf("message_approval_pda: %w", err)
	}

	common := RequestSigCommon{
		Dwallet:           dwallet,
		DwalletCurve:      req.DwalletCurve,
		DwalletPublicKey:  dwalletPK,
		Sponsor:           payer,
		InitAuthorityHash: initAuthorityHash,
		MessageDigest:     msg,
		MetaDigest:        meta,
		UserPubkey:        user,
		SignatureScheme:   req.SignatureScheme,
		CurrentTS:         time.Now().Unix(),
	}
	var ix solana.Instruction
	switch template {
	case TemplateAllowlist:
		if req.Destination == "" {
			return nil, solana.PublicKey{}, fmt.Errorf("destination required for allowlist")
		}
		destPk, err := solana.PublicKeyFromBase58(req.Destination)
		if err != nil {
			return nil, solana.PublicKey{}, fmt.Errorf("destination: %w", err)
		}
		var destBytes [32]byte
		copy(destBytes[:], destPk.Bytes())
		ix, err = BuildAllowlistRequestSignature(s.Registry, AllowlistRequestSignatureInput{
			RequestSigCommon: common, MessageApprovalBump: msgBump,
			CpiAuthorityBump: req.CpiAuthorityBump, Destination: destBytes,
		})
		if err != nil {
			return nil, solana.PublicKey{}, err
		}
	case TemplateVelocityGuard:
		ix, err = BuildVelocityRequestSignature(s.Registry, VelocityRequestSignatureInput{
			RequestSigCommon: common, MessageApprovalBump: msgBump,
			CpiAuthorityBump: req.CpiAuthorityBump,
		})
		if err != nil {
			return nil, solana.PublicKey{}, err
		}
	case TemplateTimeLock:
		ix, err = BuildTimeLockRequestSignature(s.Registry, TimeLockRequestSignatureInput{
			RequestSigCommon: common, MessageApprovalBump: msgBump,
			CpiAuthorityBump: req.CpiAuthorityBump,
		})
		if err != nil {
			return nil, solana.PublicKey{}, err
		}
	default:
		return nil, solana.PublicKey{}, fmt.Errorf("template %q not supported in batch yet", template)
	}
	return ix, payer, nil
}

// normaliseTemplate returns the request's `template` field, lower-cased and
// trimmed. Empty result means the caller forgot to set it.
func normaliseTemplate(req requestSignatureReq) string {
	return strings.ToLower(strings.TrimSpace(req.Template))
}
