package lifi

import (
	"math/big"
	"strings"
)

// PrepareInputParams is a thin alias kept for the swap layer's readability;
// prepare and quote share the same parameter shape.
type PrepareInputParams = QuoteParams

// TransactionFeeUSD sums every LI.FI fee cost (which already includes the
// Andromeda integrator fee) into a single display value. No breakdown leaks to
// the caller — no hidden charges.
func (e Estimate) TransactionFeeUSD() string {
	return sumUSD(amountsUSD(e.FeeCosts))
}

// NativeFeeEstimate sums the gas costs in the chain's native base units
// (lamports / wei) — the balance the dWallet must hold (gas is not sponsored).
func (e Estimate) NativeFeeEstimate() string {
	return sumBaseUnits(amounts(e.GasCosts))
}

// NativeFeeUSD is the display USD value of the native gas.
func (e Estimate) NativeFeeUSD() string {
	return sumUSD(amountsUSD(e.GasCosts))
}

// RequiresAtaCreation is a best-effort flag: LI.FI surfaces Solana token-account
// rent as a cost item named after "rent"/"account". When unsure it returns
// false; the broadcast still pays it from the dWallet — the flag only lets the
// caller pre-check SOL balance.
func (e Estimate) RequiresAtaCreation() bool {
	for _, group := range [][]CostItem{e.GasCosts, e.FeeCosts} {
		for _, it := range group {
			name := strings.ToLower(it.Name)
			if strings.Contains(name, "rent") || strings.Contains(name, "account creation") || strings.Contains(name, "ata") {
				return true
			}
		}
	}
	return false
}

// IncludedTools lists the DEX/bridge tools the route hops through.
func (s Step) IncludedTools() []string {
	if len(s.IncludedSteps) == 0 {
		return nil
	}
	out := make([]string, 0, len(s.IncludedSteps))
	for _, st := range s.IncludedSteps {
		if st.Tool != "" {
			out = append(out, st.Tool)
		}
	}
	return out
}

func amounts(items []CostItem) []string {
	out := make([]string, 0, len(items))
	for _, it := range items {
		if it.Amount != "" {
			out = append(out, it.Amount)
		}
	}
	return out
}

func amountsUSD(items []CostItem) []string {
	out := make([]string, 0, len(items))
	for _, it := range items {
		if it.AmountUSD != "" {
			out = append(out, it.AmountUSD)
		}
	}
	return out
}

// sumBaseUnits sums integer base-unit amounts exactly with big.Int.
func sumBaseUnits(values []string) string {
	total := new(big.Int)
	for _, a := range values {
		n, ok := new(big.Int).SetString(strings.TrimSpace(a), 10)
		if !ok {
			continue
		}
		total.Add(total, n)
	}
	return total.String()
}

// sumUSD sums decimal USD strings with big.Float (display-only preview value,
// never a signed amount).
func sumUSD(values []string) string {
	total := new(big.Float).SetPrec(64)
	for _, a := range values {
		f, _, err := big.ParseFloat(strings.TrimSpace(a), 10, 64, big.ToNearestEven)
		if err != nil {
			continue
		}
		total.Add(total, f)
	}
	return total.Text('f', 6)
}
