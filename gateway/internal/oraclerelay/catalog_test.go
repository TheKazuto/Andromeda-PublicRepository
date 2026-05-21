package oraclerelay

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gagliardetto/solana-go"
)

const sampleCatalog = `[
  {"id":"ef0d8b6fda2ceba41da15d4095d1da392a0d2f8ed0c6c7bc0f4cfac8c280b56d",
   "attributes":{"asset_type":"Crypto","base":"SOL","quote_currency":"USD","symbol":"Crypto.SOL/USD"}},
  {"id":"e62df6c8b4a85fe1a67db44dc12de5db330f7ac66b72dc658afedf0f4a415b43",
   "attributes":{"asset_type":"Crypto","base":"BTC","quote_currency":"USD","symbol":"Crypto.BTC/USD"}},
  {"id":"not-hex","attributes":{"asset_type":"Crypto","base":"BAD","quote_currency":"USD","symbol":"x"}}
]`

func testProgramID(t *testing.T) solana.PublicKey {
	t.Helper()
	pk, err := solana.PublicKeyFromBase58("A6xjw8jkJTFjpjHCRSFxVt1d1KbBZdh3XBNYvTfLZxP2")
	if err != nil {
		t.Fatal(err)
	}
	return pk
}

func TestParseCatalog(t *testing.T) {
	pid := testProgramID(t)
	entries, err := parseCatalog([]byte(sampleCatalog), pid)
	if err != nil {
		t.Fatalf("parseCatalog: %v", err)
	}
	// The malformed id is skipped, not fatal.
	if len(entries) != 2 {
		t.Fatalf("expected 2 entries (1 skipped), got %d", len(entries))
	}
	if entries[0].Symbol != "Crypto.SOL/USD" || entries[0].Base != "SOL" {
		t.Errorf("unexpected entry[0]: %+v", entries[0])
	}
	// FeedCache PDA must match the canonical derivation for that feed id.
	feedID := decodeMust(t, entries[0].FeedIDHex)
	wantPDA, _, err := FeedCachePDA(pid, feedID)
	if err != nil {
		t.Fatal(err)
	}
	if entries[0].FeedCachePDA != wantPDA.String() {
		t.Errorf("feed_cache_pda = %s, want %s", entries[0].FeedCachePDA, wantPDA)
	}
}

// TestSponsoredFeedAccount locks the sponsored-account derivation against the
// real devnet SOL/USD account. If this breaks, the derivation (program id /
// seed order / shard encoding) drifted and the catalogue would hand out wrong
// `pyth_account`s.
func TestSponsoredFeedAccount(t *testing.T) {
	feedID := decodeMust(t, "ef0d8b6fda2ceba41da15d4095d1da392a0d2f8ed0c6c7bc0f4cfac8c280b56d")
	const wantSolUSD = "7UVimffxr9ow1uXYxsr4LHAcV58mLzhmwaeKvJ1pjLiE"
	got, err := SponsoredFeedAccount(feedID, SponsoredShard0)
	if err != nil {
		t.Fatalf("SponsoredFeedAccount: %v", err)
	}
	if got.String() != wantSolUSD {
		t.Fatalf("sponsored SOL/USD shard0 = %s, want %s", got, wantSolUSD)
	}
}

func TestParseCatalogSponsoredAccount(t *testing.T) {
	entries, err := parseCatalog([]byte(sampleCatalog), testProgramID(t))
	if err != nil {
		t.Fatalf("parseCatalog: %v", err)
	}
	feedID := decodeMust(t, entries[0].FeedIDHex)
	want, err := SponsoredFeedAccount(feedID, SponsoredShard0)
	if err != nil {
		t.Fatal(err)
	}
	if entries[0].SponsoredAccount != want.String() {
		t.Errorf("sponsored_account = %s, want %s", entries[0].SponsoredAccount, want)
	}
}

func TestCatalogHTTP(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v2/price_feeds" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		_, _ = w.Write([]byte(sampleCatalog))
	}))
	defer ts.Close()

	svc := &Service{
		programID:  testProgramID(t),
		hermesURL:  ts.URL,
		httpClient: ts.Client(),
	}
	entries, err := svc.Catalog(context.Background(), "sol", "crypto")
	if err != nil {
		t.Fatalf("Catalog: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(entries))
	}
}

func decodeMust(t *testing.T, hexStr string) [32]byte {
	t.Helper()
	b, err := decodeFeedID(hexStr)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
