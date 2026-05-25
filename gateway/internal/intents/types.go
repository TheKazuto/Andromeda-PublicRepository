package intents

import (
	"context"
	"encoding/json"
	"time"
)

// Intent status values. Mirror the CHECK constraint in 034_intents.sql.
const (
	StatusPrepared         = "PREPARED"
	StatusAuthorizing      = "AUTHORIZING"
	StatusApproving        = "APPROVING"
	StatusSigning          = "SIGNING"
	StatusBroadcasting     = "BROADCASTING"
	StatusSubmitted        = "SUBMITTED"
	StatusBroadcastUnknown = "BROADCAST_UNKNOWN"
	StatusSubmittedUnknown = "SUBMITTED_UNKNOWN"
	StatusConfirmed        = "CONFIRMED"
	StatusSettled          = "SETTLED"
	StatusFailed           = "FAILED"
	StatusExpired          = "EXPIRED"
	StatusCancelled        = "CANCELLED"
)

// prepareReuest is the public body of POST /v1/intents/swap/prepare. It carries
// the dWallet identity (so submit needs only {intentId, passphrase}) plus the
// swap parameters. The client gets the identity fields from ika.dwallet.create.
type prepareRequest struct {
	// dWallet identity.
	DwalletAddress       string `json:"dwalletAddress" validate:"required"`
	DwalletPublicKeyHex  string `json:"dwalletPublicKeyHex" validate:"required"` // curve pubkey (sign + finalize signer)
	OwnerPubkeyHex       string `json:"ownerPubkeyHex" validate:"required,len=64"`
	InitAuthorityHashHex string `json:"initAuthorityHashHex" validate:"required,len=64"`
	IkaCurve             uint16 `json:"ikaCurve" validate:"max=2"`
	// ChainNativeAddress is the dWallet's address on the destination chain.
	// Required for EVM (the 0x address); for Solana it is derived from the
	// public key and may be omitted.
	ChainNativeAddress string `json:"chainNativeAddress" validate:"omitempty"`

	// Swap.
	ChainKind string `json:"chainKind" validate:"required,oneof=solana evm"`
	FromChain string `json:"fromChain" validate:"required"`
	ToChain   string `json:"toChain" validate:"required"`
	FromToken string `json:"fromToken" validate:"required"`
	ToToken   string `json:"toToken" validate:"required"`
	// ToAddress is the recipient on the destination chain. Optional for
	// same-chain (defaults to the dWallet); REQUIRED for cross-chain and must be
	// the user's OWN dWallet address on toChain (the swap is custody-free — a
	// wrong address just sends the user's funds where they asked).
	ToAddress   string `json:"toAddress" validate:"omitempty"`
	FromAmount  string `json:"fromAmount" validate:"required,numeric"`
	SlippageBps int    `json:"slippageBps" validate:"omitempty,min=0,max=5000"`
}

// submitRequest is the public body of POST /v1/intents/swap/submit.
type submitRequest struct {
	IntentID   string `json:"intentId" validate:"required,uuid"`
	Passphrase string `json:"passphrase" validate:"required,min=12"`
}

// prepareResponse is what the gateway returns from prepare.
type prepareResponse struct {
	IntentID          string          `json:"intentId"`
	Status            string          `json:"status"`
	ChainKind         string          `json:"chainKind"`
	AmountOut         string          `json:"amountOut"`
	AmountOutMin      string          `json:"amountOutMin"`
	TransactionFeeUSD string          `json:"transactionFeeUsd"`
	NativeFeeEstimate string          `json:"nativeFeeEstimate"`
	MessageDigestHex  string          `json:"messageDigestHex"`
	ExpiresAt         time.Time       `json:"expiresAt"`
	Route             json.RawMessage `json:"route"`
	Notice            string          `json:"notice"`
}

// submitResponse is what submit returns.
type submitResponse struct {
	IntentID string `json:"intentId"`
	Status   string `json:"status"`
	TxHash   string `json:"txHash,omitempty"`
}

// statusResponse is what GET /v1/intents/status/{intentId} returns.
type statusResponse struct {
	IntentID   string    `json:"intentId"`
	Status     string    `json:"status"`
	ChainKind  string    `json:"chainKind"`
	FromToken  string    `json:"fromToken"`
	ToToken    string    `json:"toToken"`
	FromAmount string    `json:"fromAmount"`
	AmountOut  string    `json:"amountOut,omitempty"`
	TxHash     string    `json:"txHash,omitempty"`
	UpdatedAt  time.Time `json:"updatedAt"`
}

// Intent is the persisted record (the subset the orchestrator reads/writes).
type Intent struct {
	ID                 string
	UserID             string
	APIKeyID           string
	ChainKind          string
	FromChain          string
	ToChain            string
	FromToken          string
	ToToken            string
	FromAmount         string
	QuotedAmountOut    string
	QuotedAmountOutMin string

	IkaDwalletAddress    string
	DwalletPublicKeyHex  string
	OwnerPubkeyHex       string
	InitAuthorityHashHex string
	IkaCurve             uint16
	ChainNativeAddress   string
	ChainID              string // numeric LI.FI id (string for the table)
	ChainIDNum           int
	SignChainID          string

	Status                  string
	SignScheme              uint16
	SignMessageHex          string // preprocessedHex
	MessageDigestHex        string
	MessageMetadataHex      string
	IkaMsgMetadataDigestHex string
	PolicyMetadataDigestHex string
	UnsignedTxB64           string
	UnsignedTxHash          string
	RouteSnapshot           json.RawMessage
	RiskSnapshot            json.RawMessage

	ApprovalTxSig    string
	ApprovalSlot     uint64
	PresignSessionID string
	SwapTxHash       string

	// EVM nonce safety + ERC20 two-step approve.
	EVMNonce                uint64
	ApproveUnsignedTxB64    string
	ApproveMessageHex       string
	ApproveMessageDigestHex string
	ApproveTxHash           string

	ExpiresAt time.Time
	UpdatedAt time.Time
}

// AuditEvent is the orchestrator's audit envelope; a bridge in the api package
// adapts it to the concrete audit.Recorder (same pattern as future-sign/oracle).
type AuditEvent struct {
	APIKeyID     string
	EventType    string
	ResourceType string
	ResourceID   string
	Actor        string
	Payload      map[string]any
}

// AuditAppender is satisfied by the api-package bridge over audit.Recorder.
type AuditAppender interface {
	Append(ctx context.Context, ev AuditEvent) error
}
