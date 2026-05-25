package api

import "github.com/shinkalabs/andromeda-intents/internal/lifi"

// preAlphaNotice surfaces the devnet warning so an agent never treats a quote as
// production value.
const preAlphaNotice = "pre-alpha on Solana devnet — not for real value; state reset at Alpha 1"

// quoteView is the normalized preview the gateway returns to the caller. Fees
// are unified into a single transactionFeeUsd (Andromeda integrator fee + LI.FI
// fees), kept separate from nativeFeeEstimate (the on-chain gas the dWallet must
// be able to pay; gas is NOT sponsored for swaps).
type quoteView struct {
	Tool          string `json:"tool"`
	FromChainID   int    `json:"fromChainId"`
	ToChainID     int    `json:"toChainId"`
	FromToken     string `json:"fromToken"`
	ToToken       string `json:"toToken"`
	FromAmount    string `json:"fromAmount"`
	AmountOut     string `json:"amountOut"`
	AmountOutMin  string `json:"amountOutMin"`
	FromAmountUSD string `json:"fromAmountUsd,omitempty"`
	ToAmountUSD   string `json:"toAmountUsd,omitempty"`

	TransactionFeeUSD   string `json:"transactionFeeUsd"`
	NativeFeeEstimate   string `json:"nativeFeeEstimate"`
	NativeFeeUSD        string `json:"nativeFeeUsd,omitempty"`
	RequiresAtaCreation bool   `json:"requiresAtaCreation"`

	ExecutionDurationSeconds int      `json:"executionDurationSeconds,omitempty"`
	IncludedTools            []string `json:"includedTools,omitempty"`

	Notice string `json:"notice"`
}

func normalizeQuote(step *lifi.Step) quoteView {
	est := step.Estimate
	return quoteView{
		Tool:                     step.Tool,
		FromChainID:              step.Action.FromChainID,
		ToChainID:                step.Action.ToChainID,
		FromToken:                step.Action.FromToken.Symbol,
		ToToken:                  step.Action.ToToken.Symbol,
		FromAmount:               est.FromAmount,
		AmountOut:                est.ToAmount,
		AmountOutMin:             est.ToAmountMin,
		FromAmountUSD:            est.FromAmountUSD,
		ToAmountUSD:              est.ToAmountUSD,
		TransactionFeeUSD:        est.TransactionFeeUSD(),
		NativeFeeEstimate:        est.NativeFeeEstimate(),
		NativeFeeUSD:             est.NativeFeeUSD(),
		RequiresAtaCreation:      est.RequiresAtaCreation(),
		ExecutionDurationSeconds: est.ExecutionTime,
		IncludedTools:            step.IncludedTools(),
		Notice:                   preAlphaNotice,
	}
}
