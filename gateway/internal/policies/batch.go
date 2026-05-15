package policies

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/gagliardetto/solana-go"
	"github.com/gagliardetto/solana-go/rpc"

	"github.com/shinkalabs/andromeda-gateway/internal/gasponsor"
)

// Auto-batching (Andromeda Features Roadmap §11) bundles N request_signature
// instructions into K transactions, respecting Solana's 1232-byte raw
// transaction size limit. Each tx still hits the same policy program(s);
// devs that sign in volume avoid paying base-fee + rent for every signature.
//
// All 7 request_signature templates are supported here (allowlist-destinations,
// velocity-guard, time-lock, oracle-conditional, passkey-step-up below-threshold
// or step-up, session-keys, fhe-gated). Templates that emit a precompile +
// main instruction pair (passkey step-up, fhe-gated) are kept together inside
// the same tx — the trial-packer never splits an atomic group.
//
// The gateway partial-signs each tx as the gas sponsor before returning, so
// the dev only has to add the remaining signatures (session-keys session
// signer is the only common extra) and submit via /v1/private-tx/submit.
//
// `common` is an optional block of shared fields (dwallet, curve, public key,
// init_authority_hash, etc) that every request inherits when not overridden.
// This is the "batch de mesma dWallet, N mensagens" shorthand — only
// `message_digest_base64` (plus template-specific extras like destination)
// has to be set per item.

// Conservative ceiling — Solana hard limit is 1232 bytes. We leave a bit of
// room for the partial signature slots (~64 bytes each, already accounted
// for inside the message header).
const txSizeLimit = 1180

type batchReq struct {
	Requests []requestSignatureReq `json:"requests"`
	Common   *requestSignatureReq  `json:"common,omitempty"`
	MaxPerTx int                   `json:"max_per_tx,omitempty"` // default 8
}

type batchResp struct {
	Batches []batchEntry `json:"batches"`
}

type batchEntry struct {
	// `unsigned_tx_base64` is named for backwards compatibility — the tx is
	// partially signed by the gas sponsor when returned. If
	// `signers_required` is empty the dev can submit as-is.
	UnsignedTxBase64 string   `json:"unsigned_tx_base64"`
	RequestIndices   []int    `json:"request_indices"`
	SizeBytes        int      `json:"size_bytes"`
	GasSponsorSigned bool     `json:"gas_sponsor_signed"`
	SignersRequired  []string `json:"signers_required"`
}

// builtRequest is the per-request output of buildRequestSigInstructions: a
// group of ix that must stay together inside one tx, plus the extra outer
// signers (besides the gas sponsor) that the tx will require.
type builtRequest struct {
	idx    int
	ixs    []solana.Instruction
	extras []solana.PublicKey
}

// batch is the handler for POST /v1/signatures/batch. Mounted from
// MountRoutes; see Andromeda Features Roadmap §11.
func (s *Service) batch(w http.ResponseWriter, r *http.Request) {
	if !s.requireSponsor(w) {
		return
	}
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

	built := make([]builtRequest, 0, len(req.Requests))
	for i, sub := range req.Requests {
		merged := mergeWithCommon(sub, req.Common)
		ixs, extras, err := s.buildRequestSigInstructions(r.Context(), merged)
		if err != nil {
			writeErr(w, http.StatusBadRequest, "build_failed",
				fmt.Sprintf("requests[%d]: %v", i, err))
			return
		}
		built = append(built, builtRequest{idx: i, ixs: ixs, extras: extras})
	}

	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	recent, err := s.RPCClient.GetLatestBlockhash(ctx, rpc.CommitmentConfirmed)
	if err != nil {
		writeErr(w, http.StatusBadGateway, "blockhash_failed", err.Error())
		return
	}

	payer := s.GasSponsor.PublicKey()

	out := batchResp{Batches: make([]batchEntry, 0)}
	current := make([]builtRequest, 0, maxPerTx)
	flush := func() error {
		if len(current) == 0 {
			return nil
		}
		raw, err := buildAndPartialSign(flattenIxs(current), recent.Value.Blockhash, payer, s.GasSponsor)
		if err != nil {
			return err
		}
		idxs := make([]int, 0, len(current))
		for _, b := range current {
			idxs = append(idxs, b.idx)
		}
		extras := uniqueExtras(current, payer)
		out.Batches = append(out.Batches, batchEntry{
			UnsignedTxBase64: base64.StdEncoding.EncodeToString(raw),
			RequestIndices:   idxs,
			SizeBytes:        len(raw),
			GasSponsorSigned: true,
			SignersRequired:  pubkeysToStrings(extras),
		})
		current = current[:0]
		return nil
	}

	for _, b := range built {
		probe := append(append([]builtRequest(nil), current...), b)
		raw, perr := buildAndPartialSign(flattenIxs(probe), recent.Value.Blockhash, payer, s.GasSponsor)
		if perr != nil {
			writeErr(w, http.StatusInternalServerError, "tx_build_failed", perr.Error())
			return
		}
		if len(current) == 0 && len(raw) > txSizeLimit {
			writeErr(w, http.StatusBadRequest, "request_too_large",
				fmt.Sprintf("requests[%d] alone is %d bytes (>%d)", b.idx, len(raw), txSizeLimit))
			return
		}
		if len(raw) > txSizeLimit || ixCountTotal(current)+len(b.ixs) > maxPerTx {
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

func flattenIxs(groups []builtRequest) []solana.Instruction {
	total := 0
	for _, g := range groups {
		total += len(g.ixs)
	}
	out := make([]solana.Instruction, 0, total)
	for _, g := range groups {
		out = append(out, g.ixs...)
	}
	return out
}

func ixCountTotal(groups []builtRequest) int {
	n := 0
	for _, g := range groups {
		n += len(g.ixs)
	}
	return n
}

func uniqueExtras(groups []builtRequest, payer solana.PublicKey) []solana.PublicKey {
	seen := map[solana.PublicKey]bool{}
	out := make([]solana.PublicKey, 0)
	for _, g := range groups {
		for _, k := range g.extras {
			if k.Equals(payer) || seen[k] {
				continue
			}
			seen[k] = true
			out = append(out, k)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].String() < out[j].String() })
	return out
}

func pubkeysToStrings(keys []solana.PublicKey) []string {
	out := make([]string, len(keys))
	for i, k := range keys {
		out[i] = k.String()
	}
	return out
}

// buildAndPartialSign assembles a legacy tx with the gas sponsor as fee
// payer, partial-signs it with the sponsor key, and returns the binary-
// marshalled bytes. Slots for additional signers stay zeroed for the dev
// to fill in client-side.
func buildAndPartialSign(
	ixs []solana.Instruction,
	blockhash solana.Hash,
	payer solana.PublicKey,
	sponsor *gasponsor.Signer,
) ([]byte, error) {
	tx, err := solana.NewTransaction(ixs, blockhash, solana.TransactionPayer(payer))
	if err != nil {
		return nil, fmt.Errorf("build tx: %w", err)
	}
	if err := sponsor.PartialSignTx(tx); err != nil {
		return nil, err
	}
	raw, err := tx.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("marshal tx: %w", err)
	}
	return raw, nil
}

// mergeWithCommon returns a copy of `req` where any empty/zero field is
// filled from `common`. `req`'s non-zero values always take precedence.
func mergeWithCommon(req requestSignatureReq, common *requestSignatureReq) requestSignatureReq {
	if common == nil {
		return req
	}
	mergeStr(&req.Template, common.Template)
	mergeStr(&req.DwalletAddress, common.DwalletAddress)
	mergeStr(&req.DwalletPublicKeyB64, common.DwalletPublicKeyB64)
	mergeStr(&req.MessageDigestB64, common.MessageDigestB64)
	mergeStr(&req.MetadataDigestB64, common.MetadataDigestB64)
	mergeStr(&req.UserPubkeyB64, common.UserPubkeyB64)
	mergeStr(&req.Destination, common.Destination)
	mergeStr(&req.InitAuthorityHashBase64, common.InitAuthorityHashBase64)
	mergeStr(&req.OracleFeed, common.OracleFeed)
	mergeStr(&req.PasskeyPubkeyB64, common.PasskeyPubkeyB64)
	mergeStr(&req.WebauthnAuthDataB64, common.WebauthnAuthDataB64)
	mergeStr(&req.WebauthnCDJB64, common.WebauthnCDJB64)
	mergeStr(&req.WebauthnSignatureB64, common.WebauthnSignatureB64)
	mergeStr(&req.DecisionSignatureB64, common.DecisionSignatureB64)
	mergeStr(&req.FHEAuthority, common.FHEAuthority)
	mergeStr(&req.SessionSigner, common.SessionSigner)
	mergeStr(&req.DestinationProgram, common.DestinationProgram)
	if req.DwalletCurve == 0 {
		req.DwalletCurve = common.DwalletCurve
	}
	if req.SignatureScheme == 0 {
		req.SignatureScheme = common.SignatureScheme
	}
	if req.CpiAuthorityBump == 0 {
		req.CpiAuthorityBump = common.CpiAuthorityBump
	}
	if req.TxAmount == nil {
		req.TxAmount = common.TxAmount
	}
	if !req.StepUp {
		req.StepUp = common.StepUp
	}
	if req.ExpectedStepUpNonce == nil {
		req.ExpectedStepUpNonce = common.ExpectedStepUpNonce
	}
	if req.DecisionCreatedSlot == nil {
		req.DecisionCreatedSlot = common.DecisionCreatedSlot
	}
	if req.DecisionAuthorize == nil {
		req.DecisionAuthorize = common.DecisionAuthorize
	}
	if req.SessionIndex == nil {
		req.SessionIndex = common.SessionIndex
	}
	if req.Amount == nil {
		req.Amount = common.Amount
	}
	if req.ExpectedSignatureNonceB == nil {
		req.ExpectedSignatureNonceB = common.ExpectedSignatureNonceB
	}
	return req
}

func mergeStr(dst *string, src string) {
	if *dst == "" {
		*dst = src
	}
}

// buildRequestSigInstructions assembles every instruction (precompile + main,
// when applicable) for a single request and reports which extra outer-tx
// signers it brings (besides the gas sponsor). The trial-packer treats the
// returned ix slice as atomic — it is never split across two txs.
func (s *Service) buildRequestSigInstructions(
	ctx context.Context,
	req requestSignatureReq,
) ([]solana.Instruction, []solana.PublicKey, error) {
	_ = ctx
	template := normaliseTemplate(req)
	if template == "" {
		return nil, nil, fmt.Errorf("request has no template — set the template field on each request or on `common`")
	}
	if s.GasSponsor == nil {
		return nil, nil, fmt.Errorf("gas sponsor not configured (ANDROMEDA_GAS_SPONSOR_KEYPAIR)")
	}
	dwallet, err := solana.PublicKeyFromBase58(req.DwalletAddress)
	if err != nil {
		return nil, nil, fmt.Errorf("dwallet_address: %w", err)
	}
	initAuthorityHash, err := decodeInitAuthorityHash(req.InitAuthorityHashBase64)
	if err != nil {
		return nil, nil, fmt.Errorf("init_authority_hash_base64: %w", err)
	}
	payer := s.GasSponsor.PublicKey()
	msg, err := decodeFixed32(req.MessageDigestB64)
	if err != nil {
		return nil, nil, fmt.Errorf("message_digest_base64: %w", err)
	}
	meta := [32]byte{}
	if req.MetadataDigestB64 != "" {
		meta, err = decodeFixed32(req.MetadataDigestB64)
		if err != nil {
			return nil, nil, fmt.Errorf("metadata_digest_base64: %w", err)
		}
	}
	user, err := decodeFixed32(req.UserPubkeyB64)
	if err != nil {
		return nil, nil, fmt.Errorf("user_pubkey_base64: %w", err)
	}
	if req.DwalletPublicKeyB64 == "" {
		return nil, nil, fmt.Errorf("dwallet_public_key_base64 required")
	}
	dwalletPK, err := base64.StdEncoding.DecodeString(req.DwalletPublicKeyB64)
	if err != nil {
		return nil, nil, fmt.Errorf("dwallet_public_key_base64: %w", err)
	}
	switch len(dwalletPK) {
	case 32, 33, 65:
	default:
		return nil, nil, fmt.Errorf("dwallet_public_key must be 32/33/65 bytes")
	}
	_, msgBump, err := MessageApprovalPDA(
		s.Registry.IkaProgramID,
		req.DwalletCurve, dwalletPK, req.SignatureScheme,
		msg[:], meta[:],
	)
	if err != nil {
		return nil, nil, fmt.Errorf("message_approval_pda: %w", err)
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
	}

	switch template {
	case TemplateAllowlist:
		if req.Destination == "" {
			return nil, nil, fmt.Errorf("destination required for allowlist")
		}
		destPk, err := solana.PublicKeyFromBase58(req.Destination)
		if err != nil {
			return nil, nil, fmt.Errorf("destination: %w", err)
		}
		var destBytes [32]byte
		copy(destBytes[:], destPk.Bytes())
		ix, err := BuildAllowlistRequestSignature(s.Registry, AllowlistRequestSignatureInput{
			RequestSigCommon: common, MessageApprovalBump: msgBump,
			CpiAuthorityBump: req.CpiAuthorityBump, Destination: destBytes,
		})
		if err != nil {
			return nil, nil, err
		}
		return []solana.Instruction{ix}, nil, nil

	case TemplateVelocityGuard:
		ix, err := BuildVelocityRequestSignature(s.Registry, VelocityRequestSignatureInput{
			RequestSigCommon: common, MessageApprovalBump: msgBump,
			CpiAuthorityBump: req.CpiAuthorityBump,
		})
		if err != nil {
			return nil, nil, err
		}
		return []solana.Instruction{ix}, nil, nil

	case TemplateTimeLock:
		ix, err := BuildTimeLockRequestSignature(s.Registry, TimeLockRequestSignatureInput{
			RequestSigCommon: common, MessageApprovalBump: msgBump,
			CpiAuthorityBump: req.CpiAuthorityBump,
		})
		if err != nil {
			return nil, nil, err
		}
		return []solana.Instruction{ix}, nil, nil

	case TemplateOracleConditional:
		if req.OracleFeed == "" {
			return nil, nil, fmt.Errorf("oracle_feed required for oracle-conditional")
		}
		feed, err := solana.PublicKeyFromBase58(req.OracleFeed)
		if err != nil {
			return nil, nil, fmt.Errorf("oracle_feed: %w", err)
		}
		ix, err := BuildOracleRequestSignature(s.Registry, OracleRequestSignatureInput{
			RequestSigCommon: common, MessageApprovalBump: msgBump,
			CpiAuthorityBump: req.CpiAuthorityBump, OracleFeed: feed,
		})
		if err != nil {
			return nil, nil, err
		}
		return []solana.Instruction{ix}, nil, nil

	case TemplatePasskeyStepUp:
		if req.TxAmount == nil {
			return nil, nil, fmt.Errorf("tx_amount required for passkey-step-up")
		}
		if !req.StepUp {
			ix, err := BuildPasskeyRequestSignature(s.Registry, PasskeyRequestSignatureInput{
				RequestSigCommon: common, MessageApprovalBump: msgBump,
				CpiAuthorityBump: req.CpiAuthorityBump, TxAmount: *req.TxAmount,
			})
			if err != nil {
				return nil, nil, err
			}
			return []solana.Instruction{ix}, nil, nil
		}
		if req.ExpectedStepUpNonce == nil {
			return nil, nil, fmt.Errorf("expected_step_up_nonce required for passkey step-up")
		}
		pkb, err := base64.StdEncoding.DecodeString(req.PasskeyPubkeyB64)
		if err != nil || len(pkb) != 33 {
			return nil, nil, fmt.Errorf("passkey_pubkey_base64 must decode to 33 bytes")
		}
		var pk [33]byte
		copy(pk[:], pkb)
		ad, err := base64.StdEncoding.DecodeString(req.WebauthnAuthDataB64)
		if err != nil || len(ad) == 0 {
			return nil, nil, fmt.Errorf("webauthn_auth_data_base64 required for passkey step-up")
		}
		cdj, err := base64.StdEncoding.DecodeString(req.WebauthnCDJB64)
		if err != nil || len(cdj) == 0 {
			return nil, nil, fmt.Errorf("webauthn_client_data_json_base64 required for passkey step-up")
		}
		sig, err := base64.StdEncoding.DecodeString(req.WebauthnSignatureB64)
		if err != nil || len(sig) != 64 {
			return nil, nil, fmt.Errorf("webauthn_signature_base64 must decode to 64 bytes")
		}
		ixs, err := BuildPasskeyRequestSignatureStepUp(s.Registry, PasskeyRequestSignatureStepUpInput{
			RequestSigCommon:       common,
			MessageApprovalBump:    msgBump,
			CpiAuthorityBump:       req.CpiAuthorityBump,
			TxAmount:               *req.TxAmount,
			ExpectedStepUpNonce:    *req.ExpectedStepUpNonce,
			PasskeyPubkey:          pk,
			WebauthnAuthData:       ad,
			WebauthnClientDataJSON: cdj,
			WebauthnSignature:      sig,
		})
		if err != nil {
			return nil, nil, err
		}
		return ixs, nil, nil

	case TemplateFHEGated:
		if req.DecisionCreatedSlot == nil || req.DecisionAuthorize == nil {
			return nil, nil, fmt.Errorf("decision_created_slot and decision_authorize required for fhe-gated")
		}
		if req.FHEAuthority == "" {
			return nil, nil, fmt.Errorf("fhe_authority required for fhe-gated")
		}
		fa, err := solana.PublicKeyFromBase58(req.FHEAuthority)
		if err != nil {
			return nil, nil, fmt.Errorf("fhe_authority: %w", err)
		}
		ds, err := base64.StdEncoding.DecodeString(req.DecisionSignatureB64)
		if err != nil || len(ds) != 64 {
			return nil, nil, fmt.Errorf("decision_signature_base64 must decode to 64 bytes")
		}
		ixs, err := BuildFHEGatedRequestSignature(s.Registry, FHEGatedRequestSignatureInput{
			RequestSigCommon:    common,
			MessageApprovalBump: msgBump,
			CpiAuthorityBump:    req.CpiAuthorityBump,
			DecisionCreatedSlot: *req.DecisionCreatedSlot,
			DecisionAuthorize:   *req.DecisionAuthorize,
			DecisionSignature:   ds,
			FHEAuthority:        fa,
		})
		if err != nil {
			return nil, nil, err
		}
		return ixs, nil, nil

	case TemplateSessionKeys:
		if req.SessionIndex == nil {
			return nil, nil, fmt.Errorf("session_index required for session-keys")
		}
		if req.SessionSigner == "" {
			return nil, nil, fmt.Errorf("session_signer required for session-keys (dev co-signs the returned tx with this keypair)")
		}
		if req.Amount == nil || req.ExpectedSignatureNonceB == nil {
			return nil, nil, fmt.Errorf("amount and expected_signature_nonce required for session-keys")
		}
		if req.DestinationProgram == "" {
			return nil, nil, fmt.Errorf("destination_program required for session-keys")
		}
		signer, err := solana.PublicKeyFromBase58(req.SessionSigner)
		if err != nil {
			return nil, nil, fmt.Errorf("session_signer: %w", err)
		}
		destProg, err := solana.PublicKeyFromBase58(req.DestinationProgram)
		if err != nil {
			return nil, nil, fmt.Errorf("destination_program: %w", err)
		}
		var destBytes [32]byte
		copy(destBytes[:], destProg.Bytes())
		ix, err := BuildSessionKeysRequestSignature(s.Registry, SessionKeysRequestSignatureInput{
			RequestSigCommon:       common,
			SessionIndex:           *req.SessionIndex,
			SessionSigner:          signer,
			MessageApprovalBump:    msgBump,
			CpiAuthorityBump:       req.CpiAuthorityBump,
			Amount:                 *req.Amount,
			DestinationProgram:     destBytes,
			ExpectedSignatureNonce: *req.ExpectedSignatureNonceB,
		})
		if err != nil {
			return nil, nil, err
		}
		return []solana.Instruction{ix}, []solana.PublicKey{signer}, nil
	}
	return nil, nil, fmt.Errorf("template %q not supported in batch", template)
}

// normaliseTemplate returns the request's `template` field, lower-cased and
// trimmed. Empty result means the caller forgot to set it.
func normaliseTemplate(req requestSignatureReq) string {
	return strings.ToLower(strings.TrimSpace(req.Template))
}
