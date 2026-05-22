package policy

import (
	"encoding/binary"
	"encoding/hex"
	"net/http"

	"github.com/shinkalabs/andromeda-gateway/internal/httpx"

	"github.com/gagliardetto/solana-go"
)

// spendingUsdCaps packs the three USD ceilings into the canonical 24-byte LE
// block used by both the config_hash and the admin challenge extras.
func spendingUsdCaps(maxPerTx, maxPerDay, maxPerWeek uint64) [24]byte {
	var caps [24]byte
	binary.LittleEndian.PutUint64(caps[0:8], maxPerTx)
	binary.LittleEndian.PutUint64(caps[8:16], maxPerDay)
	binary.LittleEndian.PutUint64(caps[16:24], maxPerWeek)
	return caps
}

// addRuleSpendingUsdChallenge builds the disc 18 (add_rule_spending_usd) admin
// challenge. The rule is created with feeds_count=0; assets are appended later
// via items/add (disc 19). First add bumps the rule generation 0 → 1.
func (s *Service) addRuleSpendingUsdChallenge(w http.ResponseWriter, req addRuleRequest) {
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
	rulePDA, _, err := RulePDA(s.ProgramID, engine, KindSpendingUsd, req.RuleIndex)
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
	gen := req.RuleGeneration
	if gen == 0 {
		gen = 1 // first add bumps generation 0 → 1
	}
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
	preimage, err := ch.Preimage()
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "encode_failed", err.Error())
		return
	}
	h, _ := ch.Hash()
	httpx.WriteJSON(w, http.StatusOK, addRuleChallengeResponse{
		ProgramID:     s.ProgramID.String(),
		EngineAddress: engine.String(),
		RulePDA:       rulePDA.String(),
		OpTag:         string(OpAddSpendingUsd),
		HumanMessage:  string(human),
		ConfigHashHex: hex.EncodeToString(configHash[:]),
		PreimageHex:   hex.EncodeToString(preimage),
		ChallengeHex:  hex.EncodeToString(h[:]),
	})
}

// itemsAddSpendingUsdChallenge builds the disc 19 (update_rule_spending_usd_add_feed)
// admin challenge. rule_generation must be the post-update value (current + 1).
func (s *Service) itemsAddSpendingUsdChallenge(w http.ResponseWriter, req itemsAddRequest, ruleIndex uint8) {
	if req.FeedAccount == "" {
		httpx.WriteError(w, http.StatusBadRequest, "invalid_field", "feed_account is required for rule_kind=9")
		return
	}
	feedCache, err := solana.PublicKeyFromBase58(req.FeedAccount)
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid_field", "feed_account: "+err.Error())
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
	rulePDA, _, err := RulePDA(s.ProgramID, engine, KindSpendingUsd, ruleIndex)
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
		ConfigHash:     [32]byte{}, // placeholder per lib.rs disc 19
		OwnerSlot:      ownerSlot,
		Extras:         [][]byte{fc, {req.Decimals}, genLE[:]},
	}
	preimage, err := ch.Preimage()
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "encode_failed", err.Error())
		return
	}
	h, _ := ch.Hash()
	httpx.WriteJSON(w, http.StatusOK, itemsAddChallengeResponse{
		ProgramID:     s.ProgramID.String(),
		EngineAddress: engine.String(),
		RulePDA:       rulePDA.String(),
		OpTag:         string(OpSpendingUsdAddFeed),
		HumanMessage:  string(human),
		PreimageHex:   hex.EncodeToString(preimage),
		ChallengeHex:  hex.EncodeToString(h[:]),
	})
}
