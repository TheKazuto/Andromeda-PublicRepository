package oraclerelay

import (
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
)

// Mirrors the Rust SBF normalisation drift test
// (`contracts/sbf-tests/tests/pyth_adapter.rs::normalizer_mirror`). Any
// divergence here means the crank would log a different canonical value than
// the on-chain program writes.
func TestToCanonicalI64(t *testing.T) {
	cases := []struct {
		value int64
		expo  int32
		want  int64
		err   bool
	}{
		{8_498_246_831, -8, 8_498_246_831, false}, // SOL/USD fixture: identity
		{100, -5, 100_000, false},                 // commodities: scale up 10^3
		{8_498_246_831, -9, 849_824_683, false},   // scale down, truncating
		{100_000_000, -8, 100_000_000, false},     // 1.0 USD → 1e8
		{9_223_372_036_854_775_807, 0, 0, true},   // i64::MAX << overflow
	}
	for _, c := range cases {
		got, err := ToCanonicalI64(c.value, c.expo)
		if c.err {
			if err == nil {
				t.Errorf("ToCanonicalI64(%d,%d): expected overflow error", c.value, c.expo)
			}
			continue
		}
		if err != nil {
			t.Errorf("ToCanonicalI64(%d,%d): unexpected err %v", c.value, c.expo, err)
			continue
		}
		if got != c.want {
			t.Errorf("ToCanonicalI64(%d,%d) = %d, want %d", c.value, c.expo, got, c.want)
		}
	}
}

// TestToCanonicalExtremes locks the normalisation behaviour at the edges the
// happy-path test doesn't cover: memecoin-scale tiny prices (large negative
// exponents that truncate at the 1e8 grid, possibly to zero), high-value
// assets, the u64 confidence path, and overflow. Mirrors the on-chain program,
// so any divergence means the crank/monitor would disagree with the dispatch.
func TestToCanonicalExtremes(t *testing.T) {
	i64cases := []struct {
		name  string
		value int64
		expo  int32
		want  int64
		err   bool
	}{
		// Memecoin priced ~$0.00001234 with expo -12 → 12340000 / 10^4 = 1234
		// (canonical 1e8 = $0.00001234). Exact at this scale.
		{"memecoin expo-12 exact", 12_340_000, -12, 1234, false},
		// Memecoin so small it falls below the 1e8 grid → truncates to 0. This
		// is the precision boundary devs must know about: a price under
		// 1e-8 USD canonicalises to 0, so a band must account for it.
		{"sub-1e8 truncates to zero", 1, -12, 0, false},
		// Partial truncation toward zero (not rounding).
		{"expo-12 truncates toward zero", 123_499, -12, 12, false},
		// High-value asset: BTC ~$100,000 at expo-8 → identity, fits in i64.
		{"btc 100k expo-8 identity", 10_000_000_000_000, -8, 10_000_000_000_000, false},
		// expo-6 feed → scale up 10^2.
		{"expo-6 scale up", 500, -6, 50_000, false},
		// Zero price stays zero.
		{"zero", 0, -8, 0, false},
		// Overflow: a value whose ×scale exceeds i64::MAX.
		{"overflow expo-7", 9_223_372_036_854_775_807, -7, 0, true},
	}
	for _, c := range i64cases {
		t.Run("i64/"+c.name, func(t *testing.T) {
			got, err := ToCanonicalI64(c.value, c.expo)
			if c.err {
				if err == nil {
					t.Fatalf("ToCanonicalI64(%d,%d): expected overflow error", c.value, c.expo)
				}
				return
			}
			if err != nil {
				t.Fatalf("ToCanonicalI64(%d,%d): unexpected err %v", c.value, c.expo, err)
			}
			if got != c.want {
				t.Fatalf("ToCanonicalI64(%d,%d) = %d, want %d", c.value, c.expo, got, c.want)
			}
		})
	}

	u64cases := []struct {
		name  string
		value uint64
		expo  int32
		want  uint64
		err   bool
	}{
		{"conf expo-8 identity", 250_000, -8, 250_000, false},
		{"conf expo-10 truncates", 123_456_789, -10, 1_234_567, false},
		{"conf expo-12 to zero", 99, -12, 0, false},
		{"conf overflow", 18_446_744_073_709_551_615, 0, 0, true},
	}
	for _, c := range u64cases {
		t.Run("u64/"+c.name, func(t *testing.T) {
			got, err := ToCanonicalU64(c.value, c.expo)
			if c.err {
				if err == nil {
					t.Fatalf("ToCanonicalU64(%d,%d): expected overflow error", c.value, c.expo)
				}
				return
			}
			if err != nil {
				t.Fatalf("ToCanonicalU64(%d,%d): unexpected err %v", c.value, c.expo, err)
			}
			if got != c.want {
				t.Fatalf("ToCanonicalU64(%d,%d) = %d, want %d", c.value, c.expo, got, c.want)
			}
		})
	}
}

// Parses the live-captured fixture and asserts the canonical view matches
// `feed_cache_v1_solusd.bin` byte-for-byte — the same assertion the Rust SBF
// happy-path makes, proving Go and Rust agree on offsets + normalisation.
func TestParseAndNormaliseFixture(t *testing.T) {
	root := repoRoot(t)
	puBytes, err := os.ReadFile(filepath.Join(root, "fixtures", "pyth", "pyth_price_update_v2_solusd.bin"))
	if err != nil {
		t.Skipf("fixture not found: %v", err)
	}
	canon, err := os.ReadFile(filepath.Join(root, "fixtures", "pyth", "feed_cache_v1_solusd.bin"))
	if err != nil {
		t.Skipf("fixture not found: %v", err)
	}

	pu, err := ParsePriceUpdateV2(puBytes)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	cp, err := ToCanonicalI64(pu.Price, pu.Exponent)
	if err != nil {
		t.Fatalf("canonical price: %v", err)
	}
	cc, err := ToCanonicalU64(pu.Conf, pu.Exponent)
	if err != nil {
		t.Fatalf("canonical conf: %v", err)
	}

	got := BuildCanonicalView(pu.FeedID, cp, cc, pu.PublishTime)
	if hex.EncodeToString(got[:]) != hex.EncodeToString(canon) {
		t.Errorf("canonical view drift:\n got %x\nwant %x", got, canon)
	}
}

// repoRoot walks up from the test's CWD (gateway/internal/oraclerelay) to the
// monorepo root that holds `fixtures/`.
func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 8; i++ {
		if _, err := os.Stat(filepath.Join(dir, "fixtures", "pyth")); err == nil {
			return dir
		}
		dir = filepath.Dir(dir)
	}
	t.Skip("fixtures/ not found from test CWD")
	return ""
}
