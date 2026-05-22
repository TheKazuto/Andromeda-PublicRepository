package policy

import (
	"context"
	"fmt"

	"github.com/gagliardetto/solana-go"
	"github.com/gagliardetto/solana-go/rpc"
)

// Sub-PDA (rule account) offsets used to resolve trailing accounts on-chain.
// Mirror of `contracts/policy-engine/src/lib.rs` (disc at byte 0).
const (
	ruleAppliesToOffset = 97  // applies_to byte
	oracleFeedsCountOff = 98  // feeds_count u8
	oracleFeedsFlatOff  = 105 // feeds_flat start
	oracleFeedBytes     = 80  // [0..32] feed_account, [32..64] feed_owner, [64..80] band
	maxOracleFeeds      = 4   // == MAX_ORACLE_FEEDS on-chain
	// Update 3 — KIND_SPENDING_USD sub-PDA layout (mirror of SpendingUsdRule).
	spendingFeedsCountOff = 98  // feeds_count u8
	spendingFeedsFlatOff  = 161 // feeds_flat start
	spendingFeedBytes     = 33  // [0..32] feed_cache_account, [32] decimals
	maxSpendingFeeds      = 16  // == MAX_SPENDING_USD_FEEDS on-chain
)

// resolveTrailingAccounts reads the on-chain PolicyEngine + each active rule
// sub-PDA and returns the request_signature trailing accounts for PATH_NORMAL:
// one sub-PDA per active slot (in slot order) and, for each oracle slot that
// applies to PATH_NORMAL, its FeedCache accounts. This mirrors the dispatch's
// account consumption exactly — the on-chain handler asserts there are no
// leftover remaining_accounts, so the resolution must be precise.
//
// Passkey rules consume runtime aux (auth_data + cdj from the WebAuthn
// assertion) that cannot be derived from chain. If an active passkey rule
// applies to PATH_NORMAL, this returns an error so the caller supplies the
// accounts manually instead.
func (s *Service) resolveTrailingAccounts(
	ctx context.Context, engine solana.PublicKey, assetIndex uint8,
) (rulePDAs []solana.PublicKey, ruleAux [][]solana.PublicKey, err error) {
	acct, err := s.RPCClient.GetAccountInfoWithOpts(ctx, engine, &rpc.GetAccountInfoOpts{
		Commitment: rpc.CommitmentConfirmed,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("rpc get engine: %w", err)
	}
	if acct == nil || acct.Value == nil {
		return nil, nil, fmt.Errorf("engine account not found")
	}
	state, err := DecodePolicyEngine(acct.Value.Data.GetBinary())
	if err != nil {
		return nil, nil, err
	}

	for i := 0; i < MaxRules; i++ {
		e := state.Rules[i]
		// Mirror the on-chain dispatch (lib.rs: `kind == KIND_EMPTY ||
		// enabled != 1 { continue }`): it consumes a remaining account ONLY
		// for enabled, non-empty slots and asserts no leftovers. Including a
		// disabled slot here would append an extra account and revert the tx.
		if e.Kind == KindEmpty || !e.Enabled {
			continue
		}
		rulePDAs = append(rulePDAs, e.RulePDA)
		var aux []solana.PublicKey

		switch e.Kind {
		case KindOracle:
			feeds, applies, ferr := fetchOracleFeedAccounts(ctx, s.RPCClient, e.RulePDA)
			if ferr != nil {
				return nil, nil, fmt.Errorf("rule slot %d (oracle): %w", i, ferr)
			}
			// The dispatch only consumes oracle aux when the rule applies to
			// PATH_NORMAL; otherwise the sub-PDA alone is consumed.
			if applies&AppliesNormal != 0 {
				aux = feeds
			}
		case KindSpendingUsd:
			// The dispatch consumes exactly ONE aux for a spending rule: the
			// FeedCache of the moved asset (`asset_index`). Unlike oracle, the
			// index is a per-request value, so we read feeds_flat[asset_index].
			feed, applies, ferr := fetchSpendingFeedAccount(ctx, s.RPCClient, e.RulePDA, assetIndex)
			if ferr != nil {
				return nil, nil, fmt.Errorf("rule slot %d (spending): %w", i, ferr)
			}
			if applies&AppliesNormal != 0 {
				aux = []solana.PublicKey{feed}
			}
		case KindPasskey:
			applies, perr := fetchRuleAppliesTo(ctx, s.RPCClient, e.RulePDA)
			if perr != nil {
				return nil, nil, fmt.Errorf("rule slot %d (passkey): %w", i, perr)
			}
			if applies&AppliesNormal != 0 {
				return nil, nil, fmt.Errorf(
					"auto-resolve unsupported: active passkey rule in slot %d consumes runtime aux (auth_data + cdj); pass rule_pdas + rule_aux_accounts manually", i)
			}
		}
		ruleAux = append(ruleAux, aux)
	}
	return rulePDAs, ruleAux, nil
}

// fetchOracleFeedAccounts reads an oracle sub-PDA and returns its feed accounts
// (the FeedCache PDAs) in feeds_flat order, plus the rule's applies_to mask.
func fetchOracleFeedAccounts(
	ctx context.Context, c *rpc.Client, rulePDA solana.PublicKey,
) ([]solana.PublicKey, uint8, error) {
	d, err := ruleSubPDAData(ctx, c, rulePDA)
	if err != nil {
		return nil, 0, err
	}
	return parseOracleFeeds(d)
}

// parseOracleFeeds extracts the feed accounts + applies_to from an oracle
// sub-PDA's raw data. Pure (no RPC) so the offset logic is unit-tested.
func parseOracleFeeds(d []byte) ([]solana.PublicKey, uint8, error) {
	if len(d) <= oracleFeedsCountOff {
		return nil, 0, fmt.Errorf("oracle sub-PDA too short (%d)", len(d))
	}
	applies := d[ruleAppliesToOffset]
	count := int(d[oracleFeedsCountOff])
	if count > maxOracleFeeds {
		return nil, 0, fmt.Errorf("oracle feeds_count %d exceeds max %d", count, maxOracleFeeds)
	}
	need := oracleFeedsFlatOff + count*oracleFeedBytes
	if len(d) < need {
		return nil, 0, fmt.Errorf("oracle sub-PDA truncated: need %d, have %d", need, len(d))
	}
	feeds := make([]solana.PublicKey, 0, count)
	for i := 0; i < count; i++ {
		base := oracleFeedsFlatOff + i*oracleFeedBytes
		var pk solana.PublicKey
		copy(pk[:], d[base:base+32])
		feeds = append(feeds, pk)
	}
	return feeds, applies, nil
}

// fetchSpendingFeedAccount reads a KIND_SPENDING_USD sub-PDA and returns the
// FeedCache account at `assetIndex` plus the rule's applies_to mask.
func fetchSpendingFeedAccount(
	ctx context.Context, c *rpc.Client, rulePDA solana.PublicKey, assetIndex uint8,
) (solana.PublicKey, uint8, error) {
	d, err := ruleSubPDAData(ctx, c, rulePDA)
	if err != nil {
		return solana.PublicKey{}, 0, err
	}
	return parseSpendingFeed(d, assetIndex)
}

// parseSpendingFeed extracts the feed_cache_account at `assetIndex` + the
// applies_to mask from a spending sub-PDA's raw data. Pure (no RPC).
func parseSpendingFeed(d []byte, assetIndex uint8) (solana.PublicKey, uint8, error) {
	if len(d) <= spendingFeedsCountOff {
		return solana.PublicKey{}, 0, fmt.Errorf("spending sub-PDA too short (%d)", len(d))
	}
	applies := d[ruleAppliesToOffset]
	count := int(d[spendingFeedsCountOff])
	if count > maxSpendingFeeds {
		return solana.PublicKey{}, 0, fmt.Errorf("spending feeds_count %d exceeds max %d", count, maxSpendingFeeds)
	}
	if int(assetIndex) >= count {
		return solana.PublicKey{}, 0, fmt.Errorf("asset_index %d out of range (feeds_count %d)", assetIndex, count)
	}
	base := spendingFeedsFlatOff + int(assetIndex)*spendingFeedBytes
	if len(d) < base+32 {
		return solana.PublicKey{}, 0, fmt.Errorf("spending sub-PDA truncated: need %d, have %d", base+32, len(d))
	}
	var pk solana.PublicKey
	copy(pk[:], d[base:base+32])
	return pk, applies, nil
}

func fetchRuleAppliesTo(ctx context.Context, c *rpc.Client, rulePDA solana.PublicKey) (uint8, error) {
	d, err := ruleSubPDAData(ctx, c, rulePDA)
	if err != nil {
		return 0, err
	}
	if len(d) <= ruleAppliesToOffset {
		return 0, fmt.Errorf("rule sub-PDA too short (%d)", len(d))
	}
	return d[ruleAppliesToOffset], nil
}

func ruleSubPDAData(ctx context.Context, c *rpc.Client, rulePDA solana.PublicKey) ([]byte, error) {
	acct, err := c.GetAccountInfoWithOpts(ctx, rulePDA, &rpc.GetAccountInfoOpts{
		Commitment: rpc.CommitmentConfirmed,
	})
	if err != nil {
		return nil, err
	}
	if acct == nil || acct.Value == nil {
		return nil, fmt.Errorf("rule sub-PDA %s not found", rulePDA)
	}
	return acct.Value.Data.GetBinary(), nil
}
