// B1 audit fix (2026-05-25): REST surface for `remove_rule` (disc 110).
//
//	POST /v1/policy/rules/{ruleIndex}/remove/challenge  → owner challenge to sign
//	POST /v1/policy/rules/{ruleIndex}/remove/submit     → lands [precompile + remove_rule]
//
// Removing a rule closes its sub-PDA (rent → recipient, bound in the challenge),
// frees the slot, and lets the same kind be recreated. The client reads the
// rule's CURRENT `generation` + `config_hash` from GET /v1/policy/{dwallet} and
// passes them here so the off-chain challenge matches the on-chain recompute.
package policy

import (
	"encoding/binary"
	"encoding/hex"
	"net/http"
	"strconv"

	"github.com/gagliardetto/solana-go"
	"github.com/go-chi/chi/v5"

	"github.com/shinkalabs/andromeda-gateway/internal/httpx"
)

type removeRuleChallengeRequest struct {
	DwalletAddress    string         `json:"dwallet_address" validate:"required,solana_pubkey"`
	InitAuthorityHash string         `json:"init_authority_hash_hex" validate:"required,hex_len=32"`
	OwnerSlot         memberSlotJSON `json:"owner_slot" validate:"required"`
	RuleKind          uint8          `json:"rule_kind" validate:"required,min=1,max=9"`
	// Current on-chain values for the rule being removed (read from
	// GET /v1/policy/{dwallet}). The challenge binds generation+1 and the
	// current config_hash, mirroring the on-chain recompute.
	RuleGeneration uint32 `json:"rule_generation" validate:"required,min=1"`
	ConfigHashHex  string `json:"config_hash_hex" validate:"required,hex_len=32"`
	ExpectedNonce  uint64 `json:"expected_nonce"`
	// Receives the reclaimed rent; bound into the challenge so a stolen
	// signature cannot redirect it.
	Recipient string `json:"recipient" validate:"required,solana_pubkey"`
}

type removeRuleChallengeResponse struct {
	ProgramID     string `json:"program_id"`
	EngineAddress string `json:"engine_address"`
	RulePDA       string `json:"rule_pda"`
	OpTag         string `json:"op_tag"`
	HumanMessage  string `json:"human_message"`
	PreimageHex   string `json:"preimage_hex"`
	ChallengeHex  string `json:"challenge_hex"`
}

// buildRemoveRuleChallenge assembles the canonical AdminChallengeInput for a
// remove_rule, shared by the challenge and submit handlers so they never drift.
func (s *Service) buildRemoveRuleChallenge(
	engine, dwallet, recipient solana.PublicKey,
	ownerSlot [MemberSlotLen]byte,
	ruleKind, ruleIndex uint8,
	currentGeneration uint32,
	configHash [32]byte,
	expectedNonce uint64,
) *AdminChallengeInput {
	newGen := currentGeneration + 1
	var genLE [4]byte
	binary.LittleEndian.PutUint32(genLE[:], newGen)
	recip := recipient.Bytes()
	return &AdminChallengeInput{
		OpTag:          OpRemoveRule,
		HumanMessage:   HumanMessageAllowlistPause(engine, dwallet),
		Engine:         engine,
		DWallet:        dwallet,
		RuleKind:       ruleKind,
		RuleIndex:      ruleIndex,
		RuleGeneration: newGen,
		ExpectedNonce:  expectedNonce,
		ConfigHash:     configHash,
		OwnerSlot:      ownerSlot,
		Extras:         [][]byte{recip, genLE[:]},
	}
}

func ruleIndexFromPath(w http.ResponseWriter, r *http.Request) (uint8, bool) {
	ruleIndex, err := strconv.Atoi(chi.URLParam(r, "ruleIndex"))
	if err != nil || ruleIndex < 0 || ruleIndex >= MaxRules {
		httpx.WriteError(w, http.StatusBadRequest, "invalid_rule_index", "ruleIndex must be 0..15")
		return 0, false
	}
	return uint8(ruleIndex), true
}

func (s *Service) removeRuleChallenge(w http.ResponseWriter, r *http.Request) {
	ruleIndex, ok := ruleIndexFromPath(w, r)
	if !ok {
		return
	}
	var req removeRuleChallengeRequest
	if !httpx.BindAndValidate(w, r, &req, 4<<10) {
		return
	}
	if _, err := SeedForKind(RuleKind(req.RuleKind)); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid_field", "rule_kind has no removable sub-PDA")
		return
	}
	dwallet, _ := solana.PublicKeyFromBase58(req.DwalletAddress)
	initHash, _ := mustHex32(req.InitAuthorityHash)
	configHash, _ := mustHex32(req.ConfigHashHex)
	recipient, _ := solana.PublicKeyFromBase58(req.Recipient)
	ownerSlot, err := req.OwnerSlot.decode()
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid_field", "owner_slot: "+err.Error())
		return
	}
	engine, _, err := EnginePDA(s.ProgramID, dwallet, initHash)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "pda_derivation_failed", err.Error())
		return
	}
	rulePDA, _, err := RulePDA(s.ProgramID, engine, RuleKind(req.RuleKind), ruleIndex)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "pda_derivation_failed", err.Error())
		return
	}
	ch := s.buildRemoveRuleChallenge(engine, dwallet, recipient, ownerSlot,
		req.RuleKind, ruleIndex, req.RuleGeneration, configHash, req.ExpectedNonce)
	preimage, err := ch.Preimage()
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "encode_failed", err.Error())
		return
	}
	h, _ := ch.Hash()
	httpx.WriteJSON(w, http.StatusOK, removeRuleChallengeResponse{
		ProgramID:     s.ProgramID.String(),
		EngineAddress: engine.String(),
		RulePDA:       rulePDA.String(),
		OpTag:         string(OpRemoveRule),
		HumanMessage:  string(ch.HumanMessage),
		PreimageHex:   hex.EncodeToString(preimage),
		ChallengeHex:  hex.EncodeToString(h[:]),
	})
}

type removeRuleSubmitRequest struct {
	signedSubmitFields
	DwalletAddress    string         `json:"dwallet_address" validate:"required,solana_pubkey"`
	InitAuthorityHash string         `json:"init_authority_hash_hex" validate:"required,hex_len=32"`
	OwnerSlot         memberSlotJSON `json:"owner_slot" validate:"required"`
	RuleKind          uint8          `json:"rule_kind" validate:"required,min=1,max=9"`
	RuleGeneration    uint32         `json:"rule_generation" validate:"required,min=1"`
	ConfigHashHex     string         `json:"config_hash_hex" validate:"required,hex_len=32"`
	ExpectedNonce     uint64         `json:"expected_nonce"`
	Recipient         string         `json:"recipient" validate:"required,solana_pubkey"`
}

func (s *Service) removeRuleSubmit(w http.ResponseWriter, r *http.Request) {
	if !s.requireSubmitWiring(w) {
		return
	}
	ruleIndex, ok := ruleIndexFromPath(w, r)
	if !ok {
		return
	}
	var req removeRuleSubmitRequest
	if !httpx.BindAndValidate(w, r, &req, 16<<10) {
		return
	}
	if _, err := SeedForKind(RuleKind(req.RuleKind)); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid_field", "rule_kind has no removable sub-PDA")
		return
	}
	sig, authData, cdj, err := req.decode()
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid_field", err.Error())
		return
	}
	dwallet, _ := solana.PublicKeyFromBase58(req.DwalletAddress)
	initHash, _ := mustHex32(req.InitAuthorityHash)
	configHash, _ := mustHex32(req.ConfigHashHex)
	recipient, _ := solana.PublicKeyFromBase58(req.Recipient)
	ownerSlot, err := req.OwnerSlot.decode()
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid_field", "owner_slot: "+err.Error())
		return
	}
	engine, _, err := EnginePDA(s.ProgramID, dwallet, initHash)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "pda_derivation_failed", err.Error())
		return
	}
	rulePDA, _, err := RulePDA(s.ProgramID, engine, RuleKind(req.RuleKind), ruleIndex)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "pda_derivation_failed", err.Error())
		return
	}

	ch := s.buildRemoveRuleChallenge(engine, dwallet, recipient, ownerSlot,
		req.RuleKind, ruleIndex, req.RuleGeneration, configHash, req.ExpectedNonce)
	challenge, err := ch.Hash()
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "encode_failed", err.Error())
		return
	}
	precompile, err := buildCredentialPrecompile(ownerSlot, challenge, sig, authData, cdj)
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid_signature", err.Error())
		return
	}
	mainIx, err := RemoveRule(RemoveRuleParams{
		ProgramID:         s.ProgramID,
		Engine:            engine,
		DWallet:           dwallet,
		RulePDA:           rulePDA,
		Recipient:         recipient,
		Payer:             s.GasSponsor.PublicKey(),
		InitAuthorityHash: initHash,
		ExpectedNonce:     req.ExpectedNonce,
		RuleIndex:         ruleIndex,
	})
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "build_failed", err.Error())
		return
	}
	sigOut, err := s.GasSponsor.SignAndSend(r.Context(), []solana.Instruction{precompile, mainIx})
	if err != nil {
		httpx.WriteError(w, http.StatusBadGateway, "send_failed", err.Error())
		return
	}
	s.appendAuditSubmit(r, "rule.remove", engine.String(), dwallet.String(), sigOut.String(),
		`{"rule_kind":`+strconv.Itoa(int(req.RuleKind))+`,"rule_index":`+strconv.Itoa(int(ruleIndex))+`}`)
	httpx.WriteJSON(w, http.StatusOK, txSignatureResponse{
		TxSignature:   sigOut.String(),
		EngineAddress: engine.String(),
	})
}
