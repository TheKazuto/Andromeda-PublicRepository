package lifi

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"sync"
	"time"
)

// RPCCache holds the chainId → public RPC URL map derived from GET /chains.
// The broadcast layer reads it so the operator needs zero RPC config to start;
// SOLANA_RPC_URL / EVM_RPC_URLS_JSON overrides take priority at the call site.
type RPCCache struct {
	mu        sync.RWMutex
	byChainID map[int][]string
	loadedAt  time.Time
}

func newRPCCache() *RPCCache {
	return &RPCCache{byChainID: make(map[int][]string)}
}

// RPCsFor returns the cached RPC URLs for a chain id (nil if unknown).
func (c *RPCCache) RPCsFor(chainID int) []string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	urls := c.byChainID[chainID]
	out := make([]string, len(urls))
	copy(out, urls)
	return out
}

// Loaded reports whether the cache has been populated at least once.
func (c *RPCCache) Loaded() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return !c.loadedAt.IsZero()
}

func (c *RPCCache) set(chains []Chain) {
	m := make(map[int][]string, len(chains))
	for _, ch := range chains {
		if len(ch.Metamask.RPCUrls) > 0 {
			m[ch.ID] = ch.Metamask.RPCUrls
		}
	}
	c.mu.Lock()
	c.byChainID = m
	c.loadedAt = time.Now()
	c.mu.Unlock()
}

// RPC exposes the client's RPC cache (one per client).
func (c *Client) RPC() *RPCCache {
	c.rpcOnce.Do(func() { c.rpcCache = newRPCCache() })
	return c.rpcCache
}

// Chains calls GET /chains for the given chain types ("EVM", "SVM"; empty =
// LI.FI default) and refreshes the RPC cache as a side effect.
func (c *Client) Chains(ctx context.Context, chainTypes string) ([]byte, error) {
	q := url.Values{}
	if chainTypes != "" {
		q.Set("chainTypes", chainTypes)
	}
	body, err := c.get(ctx, "chains", "/chains", q)
	if err != nil {
		return nil, err
	}
	var parsed chainsResponse
	if err := json.Unmarshal(body, &parsed); err == nil && len(parsed.Chains) > 0 {
		c.RPC().set(parsed.Chains)
	}
	return body, nil
}

// RefreshChains loads /chains and updates the RPC cache. Used at boot and by the
// periodic refresher; errors are returned for the caller to log (non-fatal).
func (c *Client) RefreshChains(ctx context.Context) error {
	_, err := c.Chains(ctx, "EVM,SVM,MVM,UTXO")
	return err
}

// Tokens proxies GET /tokens (optionally filtered by chains, a CSV of chain
// ids/keys). The body is returned verbatim — the gateway forwards it.
func (c *Client) Tokens(ctx context.Context, chains string) ([]byte, error) {
	q := url.Values{}
	if chains != "" {
		q.Set("chains", chains)
	}
	return c.get(ctx, "tokens", "/tokens", q)
}

// Status calls GET /status and returns the normalized subset.
func (c *Client) Status(ctx context.Context, txHash, fromChain, toChain string) (*Status, error) {
	q := url.Values{}
	q.Set("txHash", txHash)
	if fromChain != "" {
		q.Set("fromChain", fromChain)
	}
	if toChain != "" {
		q.Set("toChain", toChain)
	}
	body, err := c.get(ctx, "status", "/status", q)
	if err != nil {
		return nil, err
	}
	var st Status
	if err := json.Unmarshal(body, &st); err != nil {
		return nil, fmt.Errorf("decode status: %w", err)
	}
	return &st, nil
}
