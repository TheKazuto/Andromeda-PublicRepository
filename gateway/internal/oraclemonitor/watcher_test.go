package oraclemonitor

import "testing"

func TestInBand(t *testing.T) {
	const (
		x   = int64(100_00000000) // $100 in 1e8
		y   = int64(150_00000000) // $150 in 1e8
		big = int64(1_000_000_00000000)
	)
	tests := []struct {
		name     string
		price    int64
		min, max int64
		hystBps  int
		want     bool
	}{
		// No hysteresis — plain band membership.
		{"in band", 80_00000000, 0, x, 0, true},
		{"at max edge", x, 0, x, 0, true},
		{"at min edge", 0, 0, x, 0, true},
		{"above max", 120_00000000, 0, x, 0, false},
		{"below min", 140_00000000, y, big, 0, false},

		// Stop-loss band [0, X] with 1% hysteresis: fire only clearly below X.
		{"stoploss just below X (within margin) → no fire", 99_50000000, 0, x, 100, false},
		{"stoploss well below X → fire", 95_00000000, 0, x, 100, true},
		{"stoploss exactly at effMax", 99_00000000, 0, x, 100, true},

		// Take-profit band [Y, BIG] with 1% hysteresis: fire only clearly above Y.
		{"takeprofit just above Y (within margin) → no fire", 150_50000000, y, big, 100, false},
		{"takeprofit well above Y → fire", 160_00000000, y, big, 100, true},

		// Hysteresis wider than the band → fall back to the raw band.
		{"hyst wider than band falls back", x, x - 1, x + 1, 10000, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := inBand(tt.price, tt.min, tt.max, tt.hystBps); got != tt.want {
				t.Fatalf("inBand(%d,[%d,%d],%dbps) = %v, want %v",
					tt.price, tt.min, tt.max, tt.hystBps, got, tt.want)
			}
		})
	}
}

func TestInBandMemecoinScale(t *testing.T) {
	// Memecoin band around $0.00001234 (canonical 1e8 = 1234). Tiny absolute
	// values: hysteresis margin (value/10000*bps) rounds to ~0, so it behaves
	// like the raw band — the monitor still fires inside it.
	const lo, hi = int64(1000), int64(1500)
	if !inBand(1234, lo, hi, 100) {
		t.Fatal("expected memecoin price inside band to fire")
	}
	if inBand(1600, lo, hi, 100) {
		t.Fatal("expected memecoin price above band to not fire")
	}
	// Sub-1e8 prices canonicalise to 0 (see oraclerelay TestToCanonicalExtremes):
	// a stop-loss "fire at/below 0" is band [0,0] and fires only at 0.
	if !inBand(0, 0, 0, 0) {
		t.Fatal("expected price 0 to be inside band [0,0]")
	}
	if inBand(1, 0, 0, 0) {
		t.Fatal("expected price 1 to be outside band [0,0]")
	}
}

func TestInBandNoOverflowLargePrice(t *testing.T) {
	// $9,000,000 in 1e8 = 9e14; *10000 would overflow int64, so inBand must
	// divide first. Just assert it does not panic and behaves sanely.
	hi := int64(9_000_000_00000000)
	if !inBand(hi/2, 0, hi, 100) {
		t.Fatal("expected mid price to be in band for large band with hysteresis")
	}
	if inBand(hi, 0, hi, 100) {
		t.Fatal("expected price at raw max to be outside the hysteresis-shrunk band")
	}
}
