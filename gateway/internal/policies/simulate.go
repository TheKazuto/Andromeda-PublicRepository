package policies

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/gagliardetto/solana-go"
	"github.com/gagliardetto/solana-go/rpc"
)

// simulateReq mirrors requestSignatureReq with the same fields. The handler
// builds the SAME instruction the request_signature endpoint would emit, but
// dispatches it through `simulateTransaction` (sigVerify=false) so the dev
// can dry-run a signing call without burning gas, presigns, or a real
// MessageApproval.
type simulateReq struct {
	Template             string `json:"template"`
	DwalletAddress       string `json:"dwallet_address"`
	DwalletCurve         uint16 `json:"dwallet_curve"`
	DwalletPublicKeyB64  string `json:"dwallet_public_key_base64"`
	PayerAddress         string `json:"payer_address"`
	MessageDigestBase64  string `json:"message_digest_base64"`
	MetadataDigestBase64 string `json:"metadata_digest_base64"`
	UserPubkeyBase64     string `json:"user_pubkey_base64"`
	SignatureScheme      uint16 `json:"signature_scheme"`
	CpiAuthorityBump     uint8  `json:"cpi_authority_bump"`

	// Audit C2 (Opção 4): client supplies init_authority_hash so the
	// simulator addresses the correct policy PDA. Audit C1 removed
	// current_slot — Clock sysvar handles it on-chain.
	InitAuthorityHashBase64 string `json:"init_authority_hash_base64"`

	// allowlist-only
	Destination string `json:"destination,omitempty"`
}

// SimulateResult is the dev-friendly summary returned to the caller.
type SimulateResult struct {
	WouldSucceed     bool     `json:"would_succeed"`
	PolicyError      string   `json:"policy_error,omitempty"` // populated when policy program fails
	Boundary         string   `json:"boundary"`               // "policy", "ika_cpi", "succeeded"
	EstimatedCU      uint64   `json:"estimated_cu"`           // CUs consumed by our policy program
	EstimatedCUTotal uint64   `json:"estimated_cu_total"`     // total CUs across the whole tx
	Logs             []string `json:"logs"`
	WouldEmitEvents  []string `json:"would_emit_events"`
	Warnings         []string `json:"warnings,omitempty"`
}

func (s *Service) simulate(w http.ResponseWriter, r *http.Request) {
	var req simulateReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid_body", "invalid JSON body")
		return
	}
	template := strings.ToLower(strings.TrimSpace(req.Template))
	if template == "" {
		writeErr(w, http.StatusBadRequest, "missing_template", "template is required")
		return
	}

	dwallet, err := solana.PublicKeyFromBase58(req.DwalletAddress)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid_dwallet", "dwallet_address must be base58")
		return
	}
	payer, err := solana.PublicKeyFromBase58(req.PayerAddress)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid_payer", "payer_address must be base58")
		return
	}
	initAuthorityHash, err := decodeInitAuthorityHash(req.InitAuthorityHashBase64)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid_init_authority_hash", err.Error())
		return
	}
	msg, err := decodeFixed32(req.MessageDigestBase64)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid_message_digest", err.Error())
		return
	}
	meta := [32]byte{}
	if req.MetadataDigestBase64 != "" {
		meta, err = decodeFixed32(req.MetadataDigestBase64)
		if err != nil {
			writeErr(w, http.StatusBadRequest, "invalid_metadata_digest", err.Error())
			return
		}
	}
	user, err := decodeFixed32(req.UserPubkeyBase64)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid_user_pubkey", err.Error())
		return
	}
	if req.DwalletPublicKeyB64 == "" {
		writeErr(w, http.StatusBadRequest, "missing_dwallet_public_key",
			"dwallet_public_key_base64 is required")
		return
	}
	dwalletPK, err := base64.StdEncoding.DecodeString(req.DwalletPublicKeyB64)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid_dwallet_public_key", err.Error())
		return
	}
	switch len(dwalletPK) {
	case 32, 33, 65:
	default:
		writeErr(w, http.StatusBadRequest, "invalid_dwallet_public_key",
			"dwallet_public_key must decode to 32, 33 or 65 bytes")
		return
	}
	_, msgBump, err := MessageApprovalPDA(
		s.Registry.IkaProgramID,
		req.DwalletCurve, dwalletPK,
		req.SignatureScheme,
		msg[:], meta[:],
	)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "pda_failed", err.Error())
		return
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

	var ix solana.Instruction
	switch template {
	case TemplateAllowlist:
		if req.Destination == "" {
			writeErr(w, http.StatusBadRequest, "missing_destination", "destination is required")
			return
		}
		destPk, err := solana.PublicKeyFromBase58(req.Destination)
		if err != nil {
			writeErr(w, http.StatusBadRequest, "invalid_destination", err.Error())
			return
		}
		var destBytes [32]byte
		copy(destBytes[:], destPk.Bytes())
		ix, err = BuildAllowlistRequestSignature(s.Registry, AllowlistRequestSignatureInput{
			RequestSigCommon: common, MessageApprovalBump: msgBump,
			CpiAuthorityBump: req.CpiAuthorityBump, Destination: destBytes,
		})
		if err != nil {
			writeErr(w, http.StatusServiceUnavailable, "template_not_deployed", err.Error())
			return
		}
	case TemplateVelocityGuard:
		ix, err = BuildVelocityRequestSignature(s.Registry, VelocityRequestSignatureInput{
			RequestSigCommon: common, MessageApprovalBump: msgBump,
			CpiAuthorityBump: req.CpiAuthorityBump,
		})
		if err != nil {
			writeErr(w, http.StatusServiceUnavailable, "template_not_deployed", err.Error())
			return
		}
	case TemplateTimeLock:
		ix, err = BuildTimeLockRequestSignature(s.Registry, TimeLockRequestSignatureInput{
			RequestSigCommon: common, MessageApprovalBump: msgBump,
			CpiAuthorityBump: req.CpiAuthorityBump,
		})
		if err != nil {
			writeErr(w, http.StatusServiceUnavailable, "template_not_deployed", err.Error())
			return
		}
	default:
		writeErr(w, http.StatusNotFound, "unknown_template", template+" is not a known template")
		return
	}

	// Build a tx with the recent blockhash and an unsigned envelope. The RPC
	// is told to skip signature verification so the simulator runs even
	// though the payer hasn't signed.
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	recent, err := s.RPCClient.GetLatestBlockhash(ctx, rpc.CommitmentConfirmed)
	if err != nil {
		writeErr(w, http.StatusBadGateway, "blockhash_failed", err.Error())
		return
	}
	tx, err := solana.NewTransaction(
		[]solana.Instruction{ix},
		recent.Value.Blockhash,
		solana.TransactionPayer(payer),
	)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "tx_build_failed", err.Error())
		return
	}
	sigVerify := false
	commitment := rpc.CommitmentConfirmed
	sim, err := s.RPCClient.SimulateTransactionWithOpts(ctx, tx, &rpc.SimulateTransactionOpts{
		SigVerify:              sigVerify,
		Commitment:             commitment,
		ReplaceRecentBlockhash: true,
	})
	if err != nil {
		writeErr(w, http.StatusBadGateway, "simulate_rpc_failed", err.Error())
		return
	}

	progID, _ := s.Registry.ProgramID(template)
	out := summarizeSimulation(sim, progID.String(), s.Registry.IkaProgramID.String())
	writeJSON(w, http.StatusOK, out)
}

// reCUConsumed pulls the per-program "consumed N of M compute units" line.
var reCUConsumed = regexp.MustCompile(`Program (\S+) consumed (\d+) of (\d+) compute units`)

// summarizeSimulation walks the simulation logs and produces a dev-friendly
// SimulateResult. The boundary classifier reports:
//
//   - "policy": the policy program failed (constraint check rejected the request)
//   - "ika_cpi": the policy approved and CPI'd; the Ika program errored after
//     entry — typically because the dwallet account is not a real DWallet PDA
//   - "succeeded": no error reported
func summarizeSimulation(sim *rpc.SimulateTransactionResponse, policyProgID, ikaProgID string) SimulateResult {
	res := SimulateResult{
		WouldEmitEvents: []string{},
	}
	if sim == nil || sim.Value == nil {
		res.PolicyError = "no simulation result"
		return res
	}
	res.Logs = append(res.Logs, sim.Value.Logs...)

	// Track program invocations to determine where execution stopped.
	policyInvoked := false
	ikaInvoked := false
	for _, line := range sim.Value.Logs {
		if line == fmt.Sprintf("Program %s invoke [1]", policyProgID) {
			policyInvoked = true
		}
		if line == fmt.Sprintf("Program %s invoke [2]", ikaProgID) {
			ikaInvoked = true
		}
		if matches := reCUConsumed.FindStringSubmatch(line); len(matches) == 4 {
			n, _ := strconv.ParseUint(matches[2], 10, 64)
			if matches[1] == policyProgID {
				res.EstimatedCU = n
			}
			if res.EstimatedCUTotal < n {
				res.EstimatedCUTotal = n
			}
		}
	}

	if sim.Value.Err == nil {
		res.WouldSucceed = true
		res.Boundary = "succeeded"
	} else {
		raw, _ := json.Marshal(sim.Value.Err)
		errStr := string(raw)
		switch {
		case ikaInvoked:
			res.Boundary = "ika_cpi"
			res.PolicyError = fmt.Sprintf("CPI to Ika failed: %s — typically expected for dry-run with a non-existent dWallet", errStr)
			// Policy logic itself succeeded; mark would_succeed=false for
			// truthiness but flag clearly via Boundary.
		case policyInvoked:
			res.Boundary = "policy"
			res.PolicyError = fmt.Sprintf("policy rejected: %s", errStr)
		default:
			res.Boundary = "policy"
			res.PolicyError = fmt.Sprintf("execution failed before our program ran: %s", errStr)
		}
	}

	// Surface any "Program log: …" lines as candidate events; once contracts
	// emit canonical events via emit!() this becomes more precise.
	for _, line := range sim.Value.Logs {
		if strings.HasPrefix(line, "Program data: ") {
			res.WouldEmitEvents = append(res.WouldEmitEvents, "policy.event(data)")
		}
	}
	return res
}
