package lifi

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
)

// Quote calls GET /quote and returns the full Step (price + estimate +
// transactionRequest). The integrator + fee are injected here so the gateway
// caller never sets them. The same call backs both the dry preview (/quote,
// which ignores transactionRequest) and prepare (/prepare, which keeps it).
func (c *Client) Quote(ctx context.Context, p QuoteParams) (*Step, error) {
	q := url.Values{}
	q.Set("fromChain", p.FromChain)
	q.Set("toChain", p.ToChain)
	q.Set("fromToken", p.FromToken)
	q.Set("toToken", p.ToToken)
	q.Set("fromAmount", p.FromAmount)
	q.Set("fromAddress", p.FromAddress)
	if p.ToAddress != "" {
		q.Set("toAddress", p.ToAddress)
	}
	if p.SlippageBps > 0 {
		// LI.FI slippage is a decimal fraction (0.005 = 0.5%).
		q.Set("slippage", slippageDecimal(p.SlippageBps))
	}
	if c.integrator != "" {
		q.Set("integrator", c.integrator)
	}
	if fee := c.FeeDecimal(); fee != "" {
		q.Set("fee", fee)
	}

	body, err := c.get(ctx, "quote", "/quote", q)
	if err != nil {
		return nil, err
	}
	var step Step
	if err := json.Unmarshal(body, &step); err != nil {
		return nil, fmt.Errorf("decode quote: %w", err)
	}
	return &step, nil
}

// slippageDecimal is exported via QuoteParams.SlippageBps; this helper keeps the
// formatting in one place for reuse/testing.
func slippageDecimal(bps int) string {
	return strconv.FormatFloat(float64(bps)/10000, 'f', -1, 64)
}
