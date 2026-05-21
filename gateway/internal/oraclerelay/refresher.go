package oraclerelay

import (
	"context"
	"fmt"

	"github.com/gagliardetto/solana-go"
)

// Refresher builds `refresh_feed` instructions for the gateway to prepend to a
// gas-sponsored `request_signature`, so each FeedCache the tx reads is fresh at
// signing time (refresh-on-sign). It is the counterpart of the managed crank:
// the crank keeps caches warm on a cadence, while refresh-on-sign guarantees
// freshness at the exact signing moment and works even with the crank off.
//
// `refresh_feed` is permissionless, so no authority key is needed — the policy
// service's gas sponsor is the tx fee payer. Integrity comes from the on-chain
// Pyth verification in the adapter, not from who pays.
//
// Implements `policy.OracleRefresher`.
type Refresher struct {
	programID solana.PublicKey
	configPDA solana.PublicKey
	cluster   string
	store     *Store
}

// NewRefresher derives the adapter config PDA and returns a Refresher bound to
// the given cluster's feed catalog.
func NewRefresher(programID solana.PublicKey, cluster string, store *Store) (*Refresher, error) {
	if store == nil {
		return nil, fmt.Errorf("oraclerelay: refresher needs a store")
	}
	cfg, _, err := AdapterConfigPDA(programID)
	if err != nil {
		return nil, fmt.Errorf("derive adapter config pda: %w", err)
	}
	if cluster == "" {
		cluster = "devnet"
	}
	return &Refresher{programID: programID, configPDA: cfg, cluster: cluster, store: store}, nil
}

// RefreshIxs returns a `refresh_feed` instruction for each of `feedCaches` that
// is a sponsored, sponsored-source feed in the catalog. Unknown caches (not in
// our DB) and pull-mode feeds (`price_update_v2`, which need a client-supplied
// post_update) are skipped — never errored — so a request reading a mix of
// feeds still refreshes the ones we manage. Order follows `feedCaches`.
func (r *Refresher) RefreshIxs(ctx context.Context, feedCaches []solana.PublicKey) ([]solana.Instruction, error) {
	if len(feedCaches) == 0 {
		return nil, nil
	}
	feeds, err := r.store.ListActive(ctx, r.cluster)
	if err != nil {
		return nil, fmt.Errorf("list active feeds: %w", err)
	}
	return r.refreshIxsFor(feedCaches, feeds), nil
}

// refreshIxsFor is the pure selection logic (no RPC/DB): given the caches a tx
// will read and the active feed catalog, return the refresh_feed ixs for the
// sponsored, push-source (`price_feed`) feeds, in input order. Unit-tested.
func (r *Refresher) refreshIxsFor(feedCaches []solana.PublicKey, feeds []Feed) []solana.Instruction {
	byCache := make(map[string]Feed, len(feeds))
	for _, f := range feeds {
		byCache[f.FeedCachePDA] = f
	}

	var out []solana.Instruction
	for _, cache := range feedCaches {
		f, ok := byCache[cache.String()]
		if !ok {
			continue // not a sponsored catalog feed — leave to crank / client
		}
		if f.PythAccountKind != kindPriceFeed {
			continue // pull mode: client assembles post_update + refresh itself
		}
		pyth, perr := solana.PublicKeyFromBase58(f.PythAccount)
		if perr != nil {
			continue // malformed row — skip rather than poison the signing tx
		}
		out = append(out, RefreshFeedIx(r.programID, r.configPDA, cache, pyth))
	}
	return out
}
