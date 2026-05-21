package oraclemonitor

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/shinkalabs/andromeda-gateway/internal/oraclerelay"
)

// DefaultHermesURL is Pyth's hosted Hermes endpoint (the off-chain price API).
const DefaultHermesURL = "https://hermes.pyth.network"

// HermesClient reads live Pyth prices from Hermes (off-chain, free) and
// normalises them to the canonical decimal-1e8 scale the on-chain rule uses.
// Implements LatestPriceProvider.
type HermesClient struct {
	baseURL    string
	httpClient *http.Client
}

// NewHermesClient returns a client for the given Hermes base URL (defaults to
// the hosted endpoint).
func NewHermesClient(baseURL string) *HermesClient {
	if baseURL == "" {
		baseURL = DefaultHermesURL
	}
	return &HermesClient{
		baseURL:    strings.TrimRight(baseURL, "/"),
		httpClient: &http.Client{Timeout: 15 * time.Second},
	}
}

type hermesLatestResponse struct {
	Parsed []hermesParsedFeed `json:"parsed"`
}

type hermesParsedFeed struct {
	ID    string `json:"id"`
	Price struct {
		Price       string `json:"price"`
		Expo        int32  `json:"expo"`
		PublishTime int64  `json:"publish_time"`
	} `json:"price"`
}

// LatestPrices fetches the live price for each feed id and returns a map keyed
// by the lowercase 32-byte feed id hex (no 0x), values in canonical decimal-1e8.
// Feeds Hermes omits are simply absent (the monitor skips them this tick).
func (c *HermesClient) LatestPrices(ctx context.Context, feedIDsHex []string) (map[string]int64, error) {
	if len(feedIDsHex) == 0 {
		return map[string]int64{}, nil
	}
	q := url.Values{}
	for _, id := range feedIDsHex {
		q.Add("ids[]", strings.TrimPrefix(strings.ToLower(strings.TrimSpace(id)), "0x"))
	}
	q.Set("parsed", "true")
	u := c.baseURL + "/v2/updates/price/latest?" + q.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("hermes latest: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("hermes latest non-2xx: %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return nil, fmt.Errorf("read hermes latest: %w", err)
	}
	return parseLatest(body)
}

// parseLatest decodes the Hermes response and normalises each feed's price to
// canonical decimal-1e8 with the SAME logic the on-chain adapter uses
// (oraclerelay.ToCanonicalI64), so the monitor's decision aligns with what the
// on-chain dispatch will see. Pure (no I/O) — unit-tested directly. Malformed,
// negative, or positive-exponent feeds (the adapter rejects expo > 0) are
// skipped rather than failing the whole batch.
func parseLatest(body []byte) (map[string]int64, error) {
	var resp hermesLatestResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("decode hermes latest: %w", err)
	}
	out := make(map[string]int64, len(resp.Parsed))
	for _, f := range resp.Parsed {
		idHex := strings.ToLower(strings.TrimPrefix(f.ID, "0x"))
		raw, err := strconv.ParseInt(f.Price.Price, 10, 64)
		if err != nil || raw < 0 {
			continue
		}
		if f.Price.Expo > 0 {
			continue // the adapter rejects positive exponents
		}
		canon, err := oraclerelay.ToCanonicalI64(raw, f.Price.Expo)
		if err != nil {
			continue
		}
		out[idHex] = canon
	}
	return out, nil
}
