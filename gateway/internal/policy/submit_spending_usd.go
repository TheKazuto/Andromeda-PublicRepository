package policy

import (
	"encoding/binary"
	"fmt"
	"net/http"

	"github.com/shinkalabs/andromeda-gateway/internal/httpx"

	"github.com/gagliardetto/solana-go"
)

// addRuleSpendingUsdSubmit lands [precompile + add_rule_spending_usd (disc 18)].
// The rule is created with feeds_count=0; assets are appended afterwards via the
// items/add (disc 19) endpoint. First add bumps the rule generation 0 → 1.
func (s *Service) addRuleSpendingUsdSubmit(w http.ResponseWriter, r *http.Request, req addRuleSubmitRequest) {
	sig, authData, cdj, err := req.decode()
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid_field", err.Error())
		return
	}
	dwallet, _ := solana.PublicKeyFromBase58(req.DwalletAddress)
	initHash, _ := mustHex32(req.InitAuthorityHash)
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

	emptyFeeds := make([]byte, MaxSpendingUsdFeeds*SpendingUsdFeedBytes)
	configHash, err := SpendingUsdConfigHash(
		req.AppliesTo, 0, req.FreshnessSecondsDiv16, req.MinConfidenceBpsDiv4,
		req.MaxPerTxUsd, req.MaxPerDayUsd, req.MaxPerWeekUsd, emptyFeeds,
	)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	human := HumanMessageSpendingUsdAdd(req.MaxPerTxUsd, req.MaxPerDayUsd, req.MaxPerWeekUsd, engine, dwallet)
	gen := uint32(1) // first add — generation 0 → 1
	var genLE [4]byte
	binary.LittleEndian.PutUint32(genLE[:], gen)
	caps := spendingUsdCaps(req.MaxPerTxUsd, req.MaxPerDayUsd, req.MaxPerWeekUsd)
	ch := &AdminChallengeInput{
		OpTag:          OpAddSpendingUsd,
		HumanMessage:   human,
		Engine:         engine,
		DWallet:        dwallet,
		RuleKind:       uint8(KindSpendingUsd),
		RuleIndex:      req.RuleIndex,
		RuleGeneration: gen,
		ExpectedNonce:  req.ExpectedNonce,
		ConfigHash:     configHash,
		OwnerSlot:      ownerSlot,
		Extras:         [][]byte{{req.AppliesTo}, {req.FreshnessSecondsDiv16}, {req.MinConfidenceBpsDiv4}, caps[:], genLE[:]},
	}
	challenge, _ := ch.Hash()

	precompile, err := buildCredentialPrecompile(ownerSlot, challenge, sig, authData, cdj)
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid_signature", err.Error())
		return
	}
	mainIx, err := AddRuleSpendingUsd(AddRuleSpendingUsdParams{
		ProgramID:             s.ProgramID,
		Engine:                engine,
		DWallet:               dwallet,
		Payer:                 s.GasSponsor.PublicKey(),
		InitAuthorityHash:     initHash,
		ExpectedNonce:         req.ExpectedNonce,
		RuleIndex:             req.RuleIndex,
		AppliesTo:             req.AppliesTo,
		FreshnessSecondsDiv16: req.FreshnessSecondsDiv16,
		MaxConfidenceBpsDiv4:  req.MinConfidenceBpsDiv4,
		MaxPerTxUsd:           req.MaxPerTxUsd,
		MaxPerDayUsd:          req.MaxPerDayUsd,
		MaxPerWeekUsd:         req.MaxPerWeekUsd,
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
	extra := fmt.Sprintf(`{"rule_kind":%d,"rule_index":%d,"applies_to":%d}`,
		req.RuleKind, req.RuleIndex, req.AppliesTo)
	s.appendAuditSubmit(r, "rule.add", engine.String(), dwallet.String(), sigOut.String(), extra)
	httpx.WriteJSON(w, http.StatusOK, txSignatureResponse{
		TxSignature:   sigOut.String(),
		EngineAddress: engine.String(),
	})
}

// itemsAddSpendingUsdSubmit lands [precompile + update_rule_spending_usd_add_feed
// (disc 19)]. rule_generation must be the post-update value (current + 1).
func (s *Service) itemsAddSpendingUsdSubmit(w http.ResponseWriter, r *http.Request, req itemsAddSubmitRequest, ruleIndex uint8) {
	if req.FeedAccount == "" {
		httpx.WriteError(w, http.StatusBadRequest, "invalid_field", "feed_account is required for rule_kind=9")
		return
	}
	feedCache, err := solana.PublicKeyFromBase58(req.FeedAccount)
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid_field", "feed_account: "+err.Error())
		return
	}
	sig, authData, cdj, err := req.decode()
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid_field", err.Error())
		return
	}
	dwallet, _ := solana.PublicKeyFromBase58(req.DwalletAddress)
	initHash, _ := mustHex32(req.InitAuthorityHash)
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

	human := HumanMessageSpendingUsdAddFeed(feedCache, req.Decimals, engine, dwallet)
	var genLE [4]byte
	binary.LittleEndian.PutUint32(genLE[:], req.RuleGeneration)
	fc := feedCache.Bytes()
	ch := &AdminChallengeInput{
		OpTag:          OpSpendingUsdAddFeed,
		HumanMessage:   human,
		Engine:         engine,
		DWallet:        dwallet,
		RuleKind:       uint8(KindSpendingUsd),
		RuleIndex:      ruleIndex,
		RuleGeneration: req.RuleGeneration,
		ExpectedNonce:  req.ExpectedNonce,
		ConfigHash:     [32]byte{},
		OwnerSlot:      ownerSlot,
		Extras:         [][]byte{fc, {req.Decimals}, genLE[:]},
	}
	challenge, _ := ch.Hash()

	precompile, err := buildCredentialPrecompile(ownerSlot, challenge, sig, authData, cdj)
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid_signature", err.Error())
		return
	}
	var feedCacheArr [32]byte
	copy(feedCacheArr[:], fc)
	mainIx, err := UpdateRuleSpendingUsdAddFeed(UpdateRuleSpendingUsdAddFeedParams{
		ProgramID:         s.ProgramID,
		Engine:            engine,
		DWallet:           dwallet,
		Payer:             s.GasSponsor.PublicKey(),
		InitAuthorityHash: initHash,
		ExpectedNonce:     req.ExpectedNonce,
		RuleIndex:         ruleIndex,
		FeedCacheAccount:  feedCacheArr,
		Decimals:          req.Decimals,
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
	extra := fmt.Sprintf(`{"rule_kind":%d,"rule_index":%d}`, req.RuleKind, ruleIndex)
	s.appendAuditSubmit(r, "rule.items.add", engine.String(), dwallet.String(), sigOut.String(), extra)
	httpx.WriteJSON(w, http.StatusOK, txSignatureResponse{
		TxSignature:   sigOut.String(),
		EngineAddress: engine.String(),
	})
}
