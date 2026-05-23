package oraclemonitor

import (
	"fmt"
	"testing"
	"time"
)

func TestParseLatest(t *testing.T) {
	body := []byte(`{
	  "parsed": [
	    {"id":"ef0d8b6fda2ceba41da15d4095d1da392a0d2f8ed0c6c7bc0f4cfac8c280b56d",
	     "price":{"price":"8574000000","conf":"1000000","expo":-8,"publish_time":1700000000}},
	    {"id":"0xFF61491A931112DDF1BD8147CD1B641375F79F5825126D665480874634FD0ACE",
	     "price":{"price":"250000","conf":"10","expo":-5,"publish_time":1700000001}},
	    {"id":"aa00000000000000000000000000000000000000000000000000000000000001",
	     "price":{"price":"-5","conf":"0","expo":-8,"publish_time":1700000002}},
	    {"id":"bb00000000000000000000000000000000000000000000000000000000000002",
	     "price":{"price":"100","conf":"0","expo":2,"publish_time":1700000003}},
	    {"id":"cc00000000000000000000000000000000000000000000000000000000000003",
	     "price":{"price":"notanumber","conf":"0","expo":-8,"publish_time":1700000004}}
	  ]
	}`)
	got, err := parseLatest(body, time.Now(), 0) // lag guard disabled
	if err != nil {
		t.Fatalf("parseLatest: %v", err)
	}

	// expo -8 → identity (decimal 1e8).
	if v := got["ef0d8b6fda2ceba41da15d4095d1da392a0d2f8ed0c6c7bc0f4cfac8c280b56d"]; v != 8574000000 {
		t.Fatalf("SOL/USD canonical = %d, want 8574000000", v)
	}
	// expo -5 → ×1000, and the 0x-prefixed uppercase id is normalised lowercase.
	if v := got["ff61491a931112ddf1bd8147cd1b641375f79f5825126d665480874634fd0ace"]; v != 250_000_000 {
		t.Fatalf("ETH/USD canonical = %d, want 250000000", v)
	}
	// negative price, positive exponent, and malformed price are all skipped.
	if len(got) != 2 {
		t.Fatalf("expected 2 usable feeds, got %d: %v", len(got), got)
	}
}

func TestParseLatestEmpty(t *testing.T) {
	got, err := parseLatest([]byte(`{"parsed":[]}`), time.Now(), 0)
	if err != nil {
		t.Fatalf("parseLatest empty: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("expected empty map, got %v", got)
	}
}

func TestParseLatestMalformedJSON(t *testing.T) {
	if _, err := parseLatest([]byte(`not json`), time.Now(), 0); err == nil {
		t.Fatal("expected error on malformed JSON")
	}
}

// F3 lag guard: a price older than the budget is dropped (so the monitor skips
// that trigger this tick); a fresh one is kept.
func TestParseLatestLagGuard(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	fresh := now.Unix() - 10
	stale := now.Unix() - 100
	body := []byte(fmt.Sprintf(`{
	  "parsed": [
	    {"id":"aa00000000000000000000000000000000000000000000000000000000000001",
	     "price":{"price":"100000000","conf":"0","expo":-8,"publish_time":%d}},
	    {"id":"bb00000000000000000000000000000000000000000000000000000000000002",
	     "price":{"price":"200000000","conf":"0","expo":-8,"publish_time":%d}}
	  ]
	}`, fresh, stale))

	got, err := parseLatest(body, now, 60) // 60s budget
	if err != nil {
		t.Fatalf("parseLatest: %v", err)
	}
	if _, ok := got["aa00000000000000000000000000000000000000000000000000000000000001"]; !ok {
		t.Fatal("fresh feed should be kept")
	}
	if _, ok := got["bb00000000000000000000000000000000000000000000000000000000000002"]; ok {
		t.Fatal("stale feed should be dropped by the lag guard")
	}
}
