// Package api holds the intents-backend HTTP handlers. Every route here is
// internal: the gateway is the only caller (X-Internal-Key) and owns all
// multi-tenant auth, rate-limit, quota and billing.
package api

import "github.com/go-playground/validator/v10"

var validate = validator.New()

// quoteRequest is the dry preview body. Amounts are base units (decimal string)
// so there is no float anywhere in the money path.
type quoteRequest struct {
	FromChain   string `json:"fromChain" validate:"required"`
	ToChain     string `json:"toChain" validate:"required"`
	FromToken   string `json:"fromToken" validate:"required"`
	ToToken     string `json:"toToken" validate:"required"`
	FromAmount  string `json:"fromAmount" validate:"required,numeric"`
	FromAddress string `json:"fromAddress" validate:"required"`
	ToAddress   string `json:"toAddress" validate:"omitempty"`
	SlippageBps int    `json:"slippageBps" validate:"omitempty,min=0,max=5000"`
}

// prepareRequest builds the unsigned swap tx. Same fields as quote; the gateway
// adds the dWallet identity via FromAddress and supplies chainKind hints.
type prepareRequest struct {
	quoteRequest
	// ChainKind is any registered ChainAdapter key ("solana", "evm", and any
	// family added in later phases). The handler cross-checks it against
	// swap.Service.IsKindRegistered so the public surface always matches the
	// actual code — no enum drift between DTO and registry.
	ChainKind string `json:"chainKind" validate:"required"`
}

// deriveRequest re-derives the signing material from a persisted unsignedTx, so
// the gateway can re-validate the snapshot before signing.
type deriveRequest struct {
	ChainKind     string `json:"chainKind" validate:"required"`
	UnsignedTxB64 string `json:"unsignedTxB64" validate:"required"`
}

// finalizeRequest inserts the dWallet signature into the prepared tx and
// broadcasts it.
type finalizeRequest struct {
	ChainKind string `json:"chainKind" validate:"required"`
	// UnsignedTxB64 is the exact snapshot the gateway persisted at prepare time.
	UnsignedTxB64 string `json:"unsignedTxB64" validate:"required"`
	// SignatureB64 is the raw signature produced by ika-backend /v1/dwallet/sign.
	SignatureB64 string `json:"signatureB64" validate:"required"`
	// SignerPubkeyHex is the curve public key whose signature slot must be
	// filled (the dWallet's Solana/Ed25519 key for the MVP).
	SignerPubkeyHex string `json:"signerPubkeyHex" validate:"required"`
	// ChainID is the numeric chain id used to resolve the broadcast RPC.
	ChainID int `json:"chainId" validate:"required"`
}
