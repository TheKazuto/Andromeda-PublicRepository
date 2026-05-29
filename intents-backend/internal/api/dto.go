// Package api holds the intents-backend HTTP handlers. Every route here is
// internal: the gateway is the only caller (X-Internal-Key) and owns all
// multi-tenant auth, rate-limit, quota and billing.
package api

import "github.com/go-playground/validator/v10"

var validate = newValidate()

// newValidate builds the package validator with the money-aware custom rules.
// Registered once at init; the *Validate is safe for concurrent use.
func newValidate() *validator.Validate {
	v := validator.New()
	// Error ignored on purpose: RegisterValidation only fails on an empty tag
	// or nil func, both impossible with these literals.
	_ = v.RegisterValidation("baseunit", validateBaseUnit)
	return v
}

// validateBaseUnit accepts a base-unit amount: a non-negative integer written
// as ASCII digits only (no sign, no decimal point, no exponent, no spaces).
// `numeric` was too loose — it accepts "-100" and "1.5", which are never valid
// base units and silently break SetString downstream. Capped at 80 digits
// (uint256 max is 78) to reject absurd payloads cheaply.
func validateBaseUnit(fl validator.FieldLevel) bool {
	s := fl.Field().String()
	if s == "" || len(s) > 80 {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// quoteRequest is the dry preview body. Amounts are base units (decimal string)
// so there is no float anywhere in the money path.
type quoteRequest struct {
	FromChain   string `json:"fromChain" validate:"required"`
	ToChain     string `json:"toChain" validate:"required"`
	FromToken   string `json:"fromToken" validate:"required"`
	ToToken     string `json:"toToken" validate:"required"`
	FromAmount  string `json:"fromAmount" validate:"required,baseunit"`
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
	UnsignedTxB64 string `json:"unsignedTxB64" validate:"required,base64"`
}

// finalizeRequest inserts the dWallet signature into the prepared tx and
// broadcasts it.
type finalizeRequest struct {
	ChainKind string `json:"chainKind" validate:"required"`
	// UnsignedTxB64 is the exact snapshot the gateway persisted at prepare time.
	UnsignedTxB64 string `json:"unsignedTxB64" validate:"required,base64"`
	// SignatureB64 is the raw signature produced by ika-backend /v1/dwallet/sign.
	SignatureB64 string `json:"signatureB64" validate:"required,base64"`
	// SignerPubkeyHex is the curve public key whose signature slot must be
	// filled (the dWallet's Solana/Ed25519 key for the MVP).
	SignerPubkeyHex string `json:"signerPubkeyHex" validate:"required,hexadecimal"`
	// ChainID is the numeric chain id used to resolve the broadcast RPC.
	ChainID int `json:"chainId" validate:"required,gt=0"`
}
