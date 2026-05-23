package humanfmt

import (
	"math/big"
	"testing"
)

func mustBig(t *testing.T, s string) *big.Int {
	t.Helper()
	n, ok := new(big.Int).SetString(s, 10)
	if !ok {
		t.Fatalf("bad big.Int literal: %q", s)
	}
	return n
}

// TestFormatAmountPlain mirrors ika-backend/src/format/amount.test.ts so the
// two implementations stay byte-identical.
func TestFormatAmountPlain(t *testing.T) {
	cases := []struct {
		raw      string
		decimals int
		want     string
	}{
		{"0", 9, "0"},
		{"0", 0, "0"},
		{"1500000000", 9, "1.5"},
		{"1000000000", 9, "1"},
		{"1", 9, "0.000000001"},
		{"123456789", 8, "1.23456789"},
		{"300000000000", 8, "3000"},
		{"300050000000", 8, "3000.5"},
		{"1234567", 0, "1234567"},
		{"100", 2, "1"},
		{"101", 2, "1.01"},
		{"110", 2, "1.1"},
		{"123456789012345678901234567890", 18, "123456789012.34567890123456789"},
	}
	for _, c := range cases {
		got, err := FormatAmountPlain(mustBig(t, c.raw), c.decimals)
		if err != nil {
			t.Fatalf("FormatAmountPlain(%s, %d) unexpected error: %v", c.raw, c.decimals, err)
		}
		if got != c.want {
			t.Errorf("FormatAmountPlain(%s, %d) = %q, want %q", c.raw, c.decimals, got, c.want)
		}
	}
}

func TestFormatAmountPlainErrors(t *testing.T) {
	if _, err := FormatAmountPlain(big.NewInt(-1), 9); err == nil {
		t.Error("expected error for negative raw")
	}
	if _, err := FormatAmountPlain(big.NewInt(1), -1); err == nil {
		t.Error("expected error for negative decimals")
	}
	if _, err := FormatAmountPlain(big.NewInt(1), MaxDecimals+1); err == nil {
		t.Error("expected error for decimals > MaxDecimals")
	}
	if _, err := FormatAmountPlain(nil, 9); err == nil {
		t.Error("expected error for nil raw")
	}
}

func TestFormatAmountDecoration(t *testing.T) {
	cases := []struct {
		raw      string
		decimals int
		opts     Options
		want     string
	}{
		{"300000000000", 8, Options{Group: true}, "3,000"},
		{"123456789012345", 8, Options{Group: true}, "1,234,567.89012345"},
		{"999", 0, Options{Group: true}, "999"},
		{"1000", 0, Options{Group: true}, "1,000"},
		{"1500000000", 9, Options{Symbol: "ETH"}, "1.5 ETH"},
		{"300050000000", 8, Options{Group: true, Symbol: "USD"}, "3,000.5 USD"},
		{"1500000000", 9, Options{}, "1.5"},
	}
	for _, c := range cases {
		got, err := FormatAmount(mustBig(t, c.raw), c.decimals, c.opts)
		if err != nil {
			t.Fatalf("FormatAmount(%s, %d, %+v) unexpected error: %v", c.raw, c.decimals, c.opts, err)
		}
		if got != c.want {
			t.Errorf("FormatAmount(%s, %d, %+v) = %q, want %q", c.raw, c.decimals, c.opts, got, c.want)
		}
	}
}
