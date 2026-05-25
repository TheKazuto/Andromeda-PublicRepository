package policy

import (
	"testing"

	"github.com/gagliardetto/solana-go"
)

// TestParseOracleFeeds pins the oracle sub-PDA offsets the gateway-resolved
// path relies on (applies_to @97, feeds_count @98, feeds_flat @105, 80B/feed
// with feed_account at [0..32]). Mirror of the on-chain dispatch.
func TestParseOracleFeeds(t *testing.T) {
	feedA := mustPub(t, "7UVimffxr9ow1uXYxsr4LHAcV58mLzhmwaeKvJ1pjLiE")
	feedB := mustPub(t, "So11111111111111111111111111111111111111112")

	// Build a synthetic oracle sub-PDA: header (disc..96) + applies_to(97) +
	// feeds_count(98) + pad(99..105) + 2 feeds.
	d := make([]byte, oracleFeedsFlatOff+2*oracleFeedBytes)
	d[0] = 2 // rule account discriminator
	d[ruleAppliesToOffset] = AppliesNormal
	d[oracleFeedsCountOff] = 2
	copy(d[oracleFeedsFlatOff:], feedA[:])                 // feed 0 account
	copy(d[oracleFeedsFlatOff+oracleFeedBytes:], feedB[:]) // feed 1 account

	feeds, applies, err := parseOracleFeeds(d)
	if err != nil {
		t.Fatalf("parseOracleFeeds: %v", err)
	}
	if applies != AppliesNormal {
		t.Errorf("applies = %d, want %d", applies, AppliesNormal)
	}
	if len(feeds) != 2 || !feeds[0].Equals(feedA) || !feeds[1].Equals(feedB) {
		t.Errorf("feeds = %v, want [%s %s]", feeds, feedA, feedB)
	}

	// feeds_count above the cap is rejected.
	d[oracleFeedsCountOff] = maxOracleFeeds + 1
	if _, _, err := parseOracleFeeds(d); err == nil {
		t.Error("expected error for feeds_count over cap")
	}
}

// TestRequestSignature_OracleAuxOrdering pins the trailing-account contract the
// on-chain dispatch relies on: per active slot the sub-PDA (writable) is
// immediately followed by its auxiliary read-only accounts (Oracle: one
// FeedCache per feed), interleaved in slot order. Mirror of the SBF dispatch
// (`AccountMeta::new(rule_pda)` + `new_readonly(feed)`).
func TestRequestSignature_OracleAuxOrdering(t *testing.T) {
	programID := mustPub(t, "ARfJadMTH8mvAWprE8oMoRGNamKVDX9GV3URvudYyXgL")
	engine := mustPub(t, "9MaRaGinB3P9EDkD5kLzsfM4PPuMDGXQPYzEz7pUtiU4")
	dwallet := mustPub(t, "4aNkFccW7p2nZDC72wMqFxoKvJMVJQ28Pm7WcpqS9d14")
	payer := mustPub(t, "11111111111111111111111111111112")

	rule0 := mustPub(t, "So11111111111111111111111111111111111111112")
	feedCache := mustPub(t, "7UVimffxr9ow1uXYxsr4LHAcV58mLzhmwaeKvJ1pjLiE")
	rule1 := mustPub(t, "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v")

	ix, err := RequestSignature(RequestSignatureParams{
		ProgramID:       programID,
		Engine:          engine,
		DWallet:         dwallet,
		Coordinator:     dwallet,
		MessageApproval: dwallet,
		Payer:           payer,
		CPIAuthority:    dwallet,
		CallerProgram:   payer,
		DWalletProgram:  payer,
		RulePDAs:        []solana.PublicKey{rule0, rule1},
		RuleAux:         [][]solana.PublicKey{{feedCache}, nil}, // slot0 oracle, slot1 none
	})
	if err != nil {
		t.Fatalf("RequestSignature: %v", err)
	}

	metas := ix.Accounts()
	// 13 fixed accounts precede the trailing remaining_accounts.
	const fixed = 13
	if len(metas) != fixed+3 {
		t.Fatalf("expected %d accounts, got %d", fixed+3, len(metas))
	}

	want := []struct {
		pk       solana.PublicKey
		writable bool
	}{
		{rule0, true},      // slot 0 sub-PDA — writable
		{feedCache, false}, // slot 0 aux FeedCache — read-only
		{rule1, true},      // slot 1 sub-PDA — writable
	}
	for i, w := range want {
		m := metas[fixed+i]
		if !m.PublicKey.Equals(w.pk) {
			t.Errorf("trailing[%d]: pubkey = %s, want %s", i, m.PublicKey, w.pk)
		}
		if m.IsWritable != w.writable {
			t.Errorf("trailing[%d] (%s): writable = %v, want %v", i, w.pk, m.IsWritable, w.writable)
		}
		if m.IsSigner {
			t.Errorf("trailing[%d] (%s): unexpected signer", i, w.pk)
		}
	}
}
