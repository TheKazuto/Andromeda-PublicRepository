package oraclerelay

import "testing"

func TestDeviatesBeyondBPS(t *testing.T) {
	tests := []struct {
		name   string
		last   int64
		now    int64
		maxBPS int
		want   bool
	}{
		{"no change", 100_000, 100_000, 2000, false},
		{"small move within band (1%)", 100_000, 101_000, 2000, false},
		{"exactly at band (20%) not beyond", 100_000, 120_000, 2000, false},
		{"just beyond band", 100_000, 120_001, 2000, true},
		{"big crash beyond band", 100_000, 50_000, 2000, true},
		{"guard disabled (maxBPS=0)", 100_000, 1, 0, false},
		{"no baseline (last<=0)", 0, 999_999, 2000, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := deviatesBeyondBPS(tt.last, tt.now, tt.maxBPS); got != tt.want {
				t.Fatalf("deviatesBeyondBPS(%d,%d,%d) = %v, want %v",
					tt.last, tt.now, tt.maxBPS, got, tt.want)
			}
		})
	}
}
