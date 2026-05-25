package lifi

import "encoding/json"

// QuoteParams are the inputs the intents-backend forwards to LI.FI GET /quote.
// The integrator + fee fields are injected by the client (never by the caller),
// so they are intentionally absent here.
type QuoteParams struct {
	FromChain   string // LI.FI chain id/key (e.g. "SOL", "1")
	ToChain     string
	FromToken   string
	ToToken     string
	FromAmount  string // base units, decimal string
	FromAddress string // the dWallet address on the source chain
	ToAddress   string // optional; defaults to FromAddress
	SlippageBps int    // optional; 0 = LI.FI default
}

// Step is the LI.FI quote/route object. Only the fields the intents-backend
// reads are typed; the raw transactionRequest is kept as RawMessage because its
// shape differs between EVM (object) and Solana (object with base64 `data`).
type Step struct {
	ID                 string          `json:"id"`
	Type               string          `json:"type"`
	Tool               string          `json:"tool"`
	Action             Action          `json:"action"`
	Estimate           Estimate        `json:"estimate"`
	TransactionRequest json.RawMessage `json:"transactionRequest,omitempty"`
	IncludedSteps      []IncludedStep  `json:"includedSteps,omitempty"`
}

type Action struct {
	FromChainID int     `json:"fromChainId"`
	ToChainID   int     `json:"toChainId"`
	FromToken   Token   `json:"fromToken"`
	ToToken     Token   `json:"toToken"`
	FromAmount  string  `json:"fromAmount"`
	FromAddress string  `json:"fromAddress"`
	ToAddress   string  `json:"toAddress"`
	Slippage    float64 `json:"slippage"`
}

type Estimate struct {
	FromAmount      string     `json:"fromAmount"`
	ToAmount        string     `json:"toAmount"`
	ToAmountMin     string     `json:"toAmountMin"`
	ApprovalAddress string     `json:"approvalAddress"`
	FromAmountUSD   string     `json:"fromAmountUSD"`
	ToAmountUSD     string     `json:"toAmountUSD"`
	FeeCosts        []CostItem `json:"feeCosts"`
	GasCosts        []CostItem `json:"gasCosts"`
	ExecutionTime   int        `json:"executionDuration"`
}

type CostItem struct {
	Name      string `json:"name"`
	Amount    string `json:"amount"`
	AmountUSD string `json:"amountUSD"`
	Token     Token  `json:"token"`
	Included  bool   `json:"included"`
}

type IncludedStep struct {
	Type string `json:"type"`
	Tool string `json:"tool"`
}

type Token struct {
	Address  string `json:"address"`
	ChainID  int    `json:"chainId"`
	Symbol   string `json:"symbol"`
	Decimals int    `json:"decimals"`
	Name     string `json:"name"`
}

// Chain is one entry of GET /chains. metamask.rpcUrls feeds the broadcast RPC
// cache so the operator needs no provider config to start.
type Chain struct {
	ID          int      `json:"id"`
	Key         string   `json:"key"`
	Name        string   `json:"name"`
	ChainType   string   `json:"chainType"` // "EVM" | "SVM"
	NativeToken Token    `json:"nativeToken"`
	Metamask    Metamask `json:"metamask"`
}

type Metamask struct {
	RPCUrls []string `json:"rpcUrls"`
}

type chainsResponse struct {
	Chains []Chain `json:"chains"`
}

// Status is the normalized subset of GET /status the gateway consumes.
type Status struct {
	Status    string `json:"status"` // PENDING | DONE | FAILED | NOT_FOUND | INVALID
	Substatus string `json:"substatus"`
}
