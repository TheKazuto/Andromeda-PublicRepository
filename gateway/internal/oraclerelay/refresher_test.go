package oraclerelay

import (
	"testing"

	"github.com/gagliardetto/solana-go"
)

func TestRefresherRefreshIxsFor(t *testing.T) {
	programID := solana.MustPublicKeyFromBase58("A6xjw8jkJTFjpjHCRSFxVt1d1KbBZdh3XBNYvTfLZxP2")
	r, err := NewRefresher(programID, "devnet", &Store{}) // store unused by refreshIxsFor
	if err != nil {
		t.Fatalf("NewRefresher: %v", err)
	}

	solCache := solana.MustPublicKeyFromBase58("HgP6MZnaXdmuWoYtvNry56mjWG8oc1ZsijWJ5AgY3VUe")
	solSource := solana.MustPublicKeyFromBase58("7UVimffxr9ow1uXYxsr4LHAcV58mLzhmwaeKvJ1pjLiE")
	pullCache := solana.MustPublicKeyFromBase58("8AnETQSm8S7RchVA9SX7tHppCZbgMrA7sBS4Aneq9xyn")
	unknownCache := solana.MustPublicKeyFromBase58("ARfJadMTH8mvAWprE8oMoRGNamKVDX9GV3URvudYyXgL")

	feeds := []Feed{
		{
			FeedCachePDA:    solCache.String(),
			PythAccount:     solSource.String(),
			PythAccountKind: kindPriceFeed,
		},
		{
			FeedCachePDA:    pullCache.String(),
			PythAccount:     solSource.String(),
			PythAccountKind: kindPriceUpdateV2, // pull mode → must be skipped
		},
	}

	// Mix: a sponsored push feed, a pull feed, an unknown cache. Only the push
	// feed should produce a refresh ix.
	caches := []solana.PublicKey{solCache, pullCache, unknownCache}
	ixs := r.refreshIxsFor(caches, feeds)
	if len(ixs) != 1 {
		t.Fatalf("expected 1 refresh ix, got %d", len(ixs))
	}

	ix := ixs[0]
	if !ix.ProgramID().Equals(programID) {
		t.Fatalf("program id = %s, want %s", ix.ProgramID(), programID)
	}
	accts := ix.Accounts()
	// refresh_feed accounts: [config, feedCache(w), priceUpdate, clock].
	if len(accts) != 4 {
		t.Fatalf("expected 4 accounts, got %d", len(accts))
	}
	if !accts[1].PublicKey.Equals(solCache) || !accts[1].IsWritable {
		t.Fatalf("account[1] should be the writable FeedCache %s, got %s (writable=%v)",
			solCache, accts[1].PublicKey, accts[1].IsWritable)
	}
	if !accts[2].PublicKey.Equals(solSource) {
		t.Fatalf("account[2] should be the pyth source %s, got %s", solSource, accts[2].PublicKey)
	}

	// Empty input → no ixs.
	if got := r.refreshIxsFor(nil, feeds); got != nil {
		t.Fatalf("expected nil for empty caches, got %d", len(got))
	}
}
