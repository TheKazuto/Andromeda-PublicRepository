package api

import (
	"strconv"
	"strings"
	"sync"
	"time"
)

// quoteCacheMaxEntries bounds the per-replica quote cache so a flood of distinct
// pairs can never grow it without limit. With a short TTL the live set stays
// small; this is just a hard ceiling.
const quoteCacheMaxEntries = 5000

// quoteCache is a tiny in-process TTL cache for normalized quote previews.
//
// It is per-replica (no Redis): a preview is display-only and short-lived, so a
// per-pod cache is enough to absorb repeated identical quotes — a frontend
// re-quoting on each keystroke, an agent re-checking a price, a popular pair
// many users quote at once — without hammering LI.FI or tripping its rate limit.
//
// Only the normalized preview (price, fees, amounts) is cached. The
// transactionRequest is NEVER cached: prepare always fetches a fresh route and
// builds the tx on the spot, and minAmountOut + the intent's short expiry guard
// the actual execution. The worst case is a preview a few seconds stale, never a
// swap at a stale price.
type quoteCache struct {
	mu      sync.Mutex
	entries map[string]quoteCacheEntry
	ttl     time.Duration
	max     int
}

type quoteCacheEntry struct {
	view      quoteView
	expiresAt time.Time
}

func newQuoteCache(ttl time.Duration, max int) *quoteCache {
	return &quoteCache{
		entries: make(map[string]quoteCacheEntry),
		ttl:     ttl,
		max:     max,
	}
}

// get returns the cached preview for key when present and not expired.
func (c *quoteCache) get(key string) (quoteView, bool) {
	if c == nil {
		return quoteView{}, false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.entries[key]
	if !ok {
		return quoteView{}, false
	}
	if time.Now().After(e.expiresAt) {
		delete(c.entries, key)
		return quoteView{}, false
	}
	return e.view, true
}

// put stores a preview under key with the configured TTL. When the cache is at
// capacity it first sweeps expired entries; if still full of fresh ones it skips
// caching rather than grow unbounded.
func (c *quoteCache) put(key string, view quoteView) {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.entries) >= c.max {
		c.evictExpiredLocked()
		if len(c.entries) >= c.max {
			return
		}
	}
	c.entries[key] = quoteCacheEntry{view: view, expiresAt: time.Now().Add(c.ttl)}
}

// evictExpiredLocked drops every expired entry. The caller holds the lock.
func (c *quoteCache) evictExpiredLocked() {
	now := time.Now()
	for k, e := range c.entries {
		if now.After(e.expiresAt) {
			delete(c.entries, k)
		}
	}
}

// quoteCacheKey builds the cache key from every input that changes the quote
// result. The integrator + fee are constant per process (injected by the LI.FI
// client) so they are not part of the key. The unit separator (\x1f) never
// appears in a chain id, token address/symbol or wallet address, so the join is
// unambiguous.
func quoteCacheKey(req quoteRequest) string {
	return strings.Join([]string{
		req.FromChain,
		req.ToChain,
		req.FromToken,
		req.ToToken,
		req.FromAmount,
		req.FromAddress,
		req.ToAddress,
		strconv.Itoa(req.SlippageBps),
	}, "\x1f")
}
