package oraclerelay

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/gagliardetto/solana-go"
)

// DefaultHermesURL is Pyth's hosted Hermes endpoint (the off-chain price API).
const DefaultHermesURL = "https://hermes.pyth.network"

// pythPushOracleID is the Pyth Push Oracle program that the sponsored ("shard")
// price feed accounts are derived under. The accounts themselves are
// PriceUpdateV2 owned by the receiver; only the ADDRESS derivation uses this
// program. Confirmed empirically against the live devnet SOL/USD account
// (see catalog_test.go).
var pythPushOracleID = solana.MustPublicKeyFromBase58("pythWSnswVUd12oZpeFP8e9CVaEqJg25g1Vtc2biRsT")

// SponsoredShard0 is the default Pyth sponsored shard (the always-fresh feeds).
const SponsoredShard0 uint16 = 0

// SponsoredFeedAccount derives the sponsored Pyth price feed account for a feed
// id + shard. Seeds: [shard as u16 LE, feed_id], under the Pyth Push Oracle
// program. Shard 0 is the default sponsored shard. This is the account a
// developer points `refresh_feed` / a feed registration at.
func SponsoredFeedAccount(feedID [32]byte, shard uint16) (solana.PublicKey, error) {
	shardLE := []byte{byte(shard), byte(shard >> 8)}
	addr, _, err := solana.FindProgramAddress([][]byte{shardLE, feedID[:]}, pythPushOracleID)
	return addr, err
}

// CatalogEntry is one discoverable Pyth feed plus the on-chain accounts a
// KIND_ORACLE rule would reference for it. Lets a developer find any Pyth feed
// and both the adapter `FeedCache` (what the rule reads) and the sponsored Pyth
// source account (what keeps it fresh), fully self-service.
type CatalogEntry struct {
	FeedIDHex     string `json:"feed_id_hex"`
	Symbol        string `json:"symbol"`
	AssetType     string `json:"asset_type"`
	Base          string `json:"base"`
	QuoteCurrency string `json:"quote_currency"`
	FeedCachePDA  string `json:"feed_cache_pda"`
	// SponsoredAccount is the Pyth sponsored (shard 0) price feed account for
	// this feed — the `pyth_account` to register a feed with. Empty if the
	// derivation fails (never expected for a valid 32-byte feed id).
	SponsoredAccount string `json:"sponsored_account,omitempty"`
}

// hermesPriceFeed mirrors one element of Hermes `/v2/price_feeds`.
type hermesPriceFeed struct {
	ID         string `json:"id"`
	Attributes struct {
		AssetType     string `json:"asset_type"`
		Base          string `json:"base"`
		QuoteCurrency string `json:"quote_currency"`
		Symbol        string `json:"symbol"`
	} `json:"attributes"`
}

// Catalog fetches the Pyth feed catalog from Hermes (optionally filtered by a
// free-text `query` and `assetType`) and annotates each feed with its FeedCache
// PDA under the configured adapter program.
func (svc *Service) Catalog(ctx context.Context, query, assetType string) ([]CatalogEntry, error) {
	u := svc.hermesURL + "/v2/price_feeds"
	q := url.Values{}
	if query != "" {
		q.Set("query", query)
	}
	if assetType != "" {
		q.Set("asset_type", assetType)
	}
	if enc := q.Encode(); enc != "" {
		u += "?" + enc
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	resp, err := svc.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("hermes catalog: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("hermes catalog non-2xx: %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return nil, fmt.Errorf("read hermes catalog: %w", err)
	}
	return parseCatalog(body, svc.programID)
}

// parseCatalog decodes the Hermes response and derives each feed's FeedCache
// PDA. Pure (no I/O) so it is unit-tested directly.
func parseCatalog(body []byte, programID solana.PublicKey) ([]CatalogEntry, error) {
	var feeds []hermesPriceFeed
	if err := json.Unmarshal(body, &feeds); err != nil {
		return nil, fmt.Errorf("decode hermes catalog: %w", err)
	}
	out := make([]CatalogEntry, 0, len(feeds))
	for _, f := range feeds {
		idHex := strings.ToLower(strings.TrimPrefix(f.ID, "0x"))
		b, err := hex.DecodeString(idHex)
		if err != nil || len(b) != 32 {
			// Skip malformed ids rather than failing the whole catalog.
			continue
		}
		var feedID [32]byte
		copy(feedID[:], b)
		pda, _, err := FeedCachePDA(programID, feedID)
		if err != nil {
			continue
		}
		sponsored := ""
		if sa, serr := SponsoredFeedAccount(feedID, SponsoredShard0); serr == nil {
			sponsored = sa.String()
		}
		out = append(out, CatalogEntry{
			FeedIDHex:        idHex,
			Symbol:           f.Attributes.Symbol,
			AssetType:        f.Attributes.AssetType,
			Base:             f.Attributes.Base,
			QuoteCurrency:    f.Attributes.QuoteCurrency,
			FeedCachePDA:     pda.String(),
			SponsoredAccount: sponsored,
		})
	}
	return out, nil
}
