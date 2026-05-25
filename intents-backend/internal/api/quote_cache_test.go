package api

import (
	"testing"
	"time"
)

func TestQuoteCacheHitMiss(t *testing.T) {
	c := newQuoteCache(time.Minute, 100)
	key := "k1"

	if _, ok := c.get(key); ok {
		t.Fatal("expected miss on empty cache")
	}
	c.put(key, quoteView{AmountOut: "123"})
	got, ok := c.get(key)
	if !ok {
		t.Fatal("expected hit after put")
	}
	if got.AmountOut != "123" {
		t.Errorf("AmountOut = %q, want 123", got.AmountOut)
	}
}

func TestQuoteCacheExpiry(t *testing.T) {
	c := newQuoteCache(10*time.Millisecond, 100)
	c.put("k", quoteView{AmountOut: "1"})
	if _, ok := c.get("k"); !ok {
		t.Fatal("expected hit before expiry")
	}
	time.Sleep(20 * time.Millisecond)
	if _, ok := c.get("k"); ok {
		t.Error("expected miss after TTL elapsed")
	}
}

func TestQuoteCacheNilSafe(t *testing.T) {
	var c *quoteCache // disabled cache
	if _, ok := c.get("k"); ok {
		t.Error("nil cache must always miss")
	}
	c.put("k", quoteView{}) // must not panic
}

func TestQuoteCacheCapacity(t *testing.T) {
	c := newQuoteCache(time.Minute, 2)
	c.put("a", quoteView{})
	c.put("b", quoteView{})
	c.put("c", quoteView{}) // at capacity, all fresh → skipped
	if _, ok := c.get("c"); ok {
		t.Error("entry beyond capacity (all fresh) must be skipped, not stored")
	}
	if _, ok := c.get("a"); !ok {
		t.Error("existing entry must survive a rejected insert")
	}
}

func TestQuoteCacheKeyDistinguishesInputs(t *testing.T) {
	base := quoteRequest{
		FromChain: "SOL", ToChain: "SOL", FromToken: "USDC", ToToken: "SOL",
		FromAmount: "1000000", FromAddress: "addr", ToAddress: "", SlippageBps: 50,
	}
	k1 := quoteCacheKey(base)

	if quoteCacheKey(base) != k1 {
		t.Error("same inputs must yield the same key")
	}

	variants := []func(*quoteRequest){
		func(r *quoteRequest) { r.FromAmount = "2000000" },
		func(r *quoteRequest) { r.ToToken = "BONK" },
		func(r *quoteRequest) { r.SlippageBps = 100 },
		func(r *quoteRequest) { r.FromAddress = "other" },
		func(r *quoteRequest) { r.ToAddress = "dest" },
	}
	for i, mut := range variants {
		v := base
		mut(&v)
		if quoteCacheKey(v) == k1 {
			t.Errorf("variant %d must produce a different key", i)
		}
	}
}
