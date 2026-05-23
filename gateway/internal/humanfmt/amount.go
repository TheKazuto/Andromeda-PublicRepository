// Package humanfmt renders raw integer amounts (base units) as human-readable
// decimal strings.
//
// The PLAIN output (FormatAmountPlain, no options) is the canonical decimal
// shift shared byte-for-byte with the ika-backend (TypeScript
// `src/format/amount.ts`) and the on-chain challenge templates (Rust) that
// render signed human messages. Ported from clear-msig
// `programs/clear-wallet/src/utils/message.rs::push_decimal_u64`.
//
// Do NOT change the plain shape without updating those mirrors + fixtures
// (Update 6 M2). The Options (group separator, symbol) are display-only
// decorations that NEVER enter a signed message, challenge, or hash.
package humanfmt

import (
	"fmt"
	"math/big"
	"strings"
)

// MaxDecimals caps the decimal shift. u128 base units fit in ≤ 39 digits.
const MaxDecimals = 38

// ValueDecimals1e8 is the canonical decimal shift for monetary values in signed
// human messages (oracle price bounds, USD spending caps — all carried in 1e8
// base units). MUST mirror byte-for-byte VALUE_DECIMALS_1E8 (Rust auth crate),
// the same constant in the TS challenge mirror and the Python fixture generator.
// Changing it is an ABI break (Update 6 M2b).
const ValueDecimals1e8 = 8

// FormatU64Shifted renders an unsigned base-unit amount as a plain decimal
// shifted by `decimals`. Errors are impossible for a valid `decimals` and a
// non-negative input, so they are dropped for ergonomic call sites.
func FormatU64Shifted(v uint64, decimals int) string {
	s, _ := FormatAmountPlain(new(big.Int).SetUint64(v), decimals)
	return s
}

// FormatI64Shifted renders a signed base-unit amount as a plain decimal shifted
// by `decimals` ("-" prefix for negatives). Used for oracle price bounds (i64).
func FormatI64Shifted(v int64, decimals int) string {
	n := big.NewInt(v)
	if n.Sign() < 0 {
		s, _ := FormatAmountPlain(new(big.Int).Abs(n), decimals)
		return "-" + s
	}
	s, _ := FormatAmountPlain(n, decimals)
	return s
}

// Options carry display-only decoration. They never affect the canonical
// plain output and must not be used when computing a signed message.
type Options struct {
	// Symbol, when non-empty, is appended as " <symbol>" (e.g. "USD", "ETH").
	Symbol string
	// Group inserts ',' every 3 digits in the integer part (en locale).
	Group bool
}

// FormatAmountPlain renders raw shifted by `decimals` places, trimming trailing
// fractional zeros and omitting the decimal point for exact integers. `raw`
// must be non-negative. This is the canonical, cross-language output.
func FormatAmountPlain(raw *big.Int, decimals int) (string, error) {
	if decimals < 0 || decimals > MaxDecimals {
		return "", fmt.Errorf("humanfmt: decimals must be in [0, %d], got %d", MaxDecimals, decimals)
	}
	if raw == nil {
		return "", fmt.Errorf("humanfmt: raw must not be nil")
	}
	if raw.Sign() < 0 {
		return "", fmt.Errorf("humanfmt: raw must be non-negative")
	}
	if decimals == 0 {
		return raw.String(), nil
	}

	scale := new(big.Int).Exp(big.NewInt(10), big.NewInt(int64(decimals)), nil)
	intPart := new(big.Int)
	frac := new(big.Int)
	intPart.QuoRem(raw, scale, frac)
	if frac.Sign() == 0 {
		return intPart.String(), nil
	}

	// Zero-pad the fraction to `decimals` digits, then trim trailing zeros.
	fracStr := frac.String()
	if len(fracStr) < decimals {
		fracStr = strings.Repeat("0", decimals-len(fracStr)) + fracStr
	}
	fracStr = strings.TrimRight(fracStr, "0")
	return intPart.String() + "." + fracStr, nil
}

// FormatAmount applies display-only decoration over the canonical plain shift.
func FormatAmount(raw *big.Int, decimals int, opts Options) (string, error) {
	s, err := FormatAmountPlain(raw, decimals)
	if err != nil {
		return "", err
	}
	if opts.Group {
		if dot := strings.IndexByte(s, '.'); dot == -1 {
			s = groupInteger(s)
		} else {
			s = groupInteger(s[:dot]) + s[dot:]
		}
	}
	if opts.Symbol != "" {
		s = s + " " + opts.Symbol
	}
	return s, nil
}

// groupInteger inserts ',' every 3 digits from the right of an all-digits
// string (no sign, no decimal point).
func groupInteger(intStr string) string {
	n := len(intStr)
	if n <= 3 {
		return intStr
	}
	var b strings.Builder
	b.Grow(n + n/3)
	pre := n % 3
	if pre > 0 {
		b.WriteString(intStr[:pre])
		b.WriteByte(',')
	}
	for i := pre; i < n; i += 3 {
		b.WriteString(intStr[i : i+3])
		if i+3 < n {
			b.WriteByte(',')
		}
	}
	return b.String()
}
