// Package oraclemonitor implements the managed Pyth price-trigger keeper
// (PYTH_FULL_COVERAGE_PLAN.md F7.5).
//
// A dev arms a price trigger: a pre-built `request_signature` payload plus the
// price band that must hold for it to fire. A leader-elected worker reads the
// live Pyth price off-chain from Hermes (free) and, when the band is satisfied,
// fires the gas-sponsored `request_signature`. The on-chain KIND_ORACLE
// dispatch re-validates the real price on-chain, so the monitor is an
// UNTRUSTED trigger: it can only release a pre-committed message when the
// on-chain rule would already pass — it can never forge a signature. This keeps
// the wallet-agnostic promise (the dev/user needs no SOL nor Solana presence)
// while the security stays anchored on-chain.
package oraclemonitor

import (
	"context"
	"encoding/json"
	"time"

	"github.com/google/uuid"
)

// Status is the lifecycle state of a price trigger.
type Status string

const (
	StatusArmed     Status = "armed"
	StatusFiring    Status = "firing"
	StatusFired     Status = "fired"
	StatusExpired   Status = "expired"
	StatusCancelled Status = "cancelled"
	StatusFailed    Status = "failed"
)

// PriceTrigger is the durable representation of an armed price trigger.
type PriceTrigger struct {
	ID             uuid.UUID `json:"id"`
	APIKeyID       uuid.UUID `json:"apiKeyId"`
	Cluster        string    `json:"cluster"`
	DWalletAddress string    `json:"dwalletAddress"`
	FeedCachePDA   string    `json:"feedCachePda"`
	PythFeedIDHex  string    `json:"pythFeedIdHex"`
	// Min1e8/Max1e8 are the canonical decimal-1e8 price band (mirrors the
	// on-chain rule). The monitor fires when the live price is within [min,max].
	Min1e8        int64 `json:"min1e8"`
	Max1e8        int64 `json:"max1e8"`
	HysteresisBps int   `json:"hysteresisBps"`

	Status    Status    `json:"status"`
	CreatedAt time.Time `json:"createdAt"`
	ExpiresAt time.Time `json:"expiresAt"`

	FiredAt      *time.Time `json:"firedAt,omitempty"`
	TxSignature  *string    `json:"txSignature,omitempty"`
	LastCheckAt  *time.Time `json:"lastCheckAt,omitempty"`
	LastPrice1e8 *int64     `json:"lastPrice1e8,omitempty"`
	FailureCount int        `json:"failureCount"`
	LastError    *string    `json:"lastError,omitempty"`

	// RequestSignaturePayload is the pre-built request_signature submit body the
	// worker fires when the band is satisfied. Never returned via the API (it
	// carries the exact message the dev pre-committed to sign).
	RequestSignaturePayload json.RawMessage `json:"-"`
}

// CreateRequest is the API-level request to arm a price trigger.
type CreateRequest struct {
	DWalletAddress string `json:"dwalletAddress" validate:"required,solana_pubkey"`
	FeedCachePDA   string `json:"feedCachePda" validate:"required,solana_pubkey"`
	PythFeedIDHex  string `json:"pythFeedIdHex" validate:"required,hex_len=32"`
	// Min1e8/Max1e8 form the price band the monitor watches. Must mirror the
	// on-chain rule's band; min <= max. Use 0 for an open lower bound (stop-loss
	// "fire below X" → band [0, X]) and a large value for take-profit.
	Min1e8        int64 `json:"min1e8"`
	Max1e8        int64 `json:"max1e8"`
	HysteresisBps int   `json:"hysteresisBps" validate:"min=0,max=10000"`

	ExpiresInSeconds int `json:"expiresInSeconds" validate:"min=0,max=2592000"`

	// RequestSignaturePayload is the body the worker POSTs to the
	// request_signature fire path. The dev pre-builds and supplies it so the
	// gateway never invents what gets signed. Its dwallet_address must match
	// DWalletAddress (checked at create time).
	RequestSignaturePayload json.RawMessage `json:"requestSignaturePayload" validate:"required"`
}

// Firer fires a stored request_signature payload (gas-sponsored, with
// refresh-on-sign) and returns the landed Solana tx signature. It also
// validates a payload without sending (used at arm time). Implemented by
// policy.Service and wired in main — declared here so this package does not
// import policy (avoids an import cycle, same pattern as policy.OracleRefresher).
type Firer interface {
	FireRequestSignature(ctx context.Context, payload json.RawMessage) (txSignature string, err error)
	// ValidateRequestSignaturePayload decodes + validates a payload with the
	// authoritative schema, without sending. Returns an error if malformed.
	ValidateRequestSignaturePayload(payload json.RawMessage) error
}

// Metrics is the minimal Prometheus surface the monitor emits. Lets this
// package stay free of a direct prometheus dependency (nil-safe: a nil Metrics
// disables emission). Implemented by *metrics.Metrics.
type Metrics interface {
	RecordOracleTriggerFire(result string) // result: fired|failed
	RecordOracleTriggerExpired(n int)
	RecordOracleMonitorError(stage string) // stage: tick|hermes|claim|reap
}

// LatestPriceProvider returns the live canonical decimal-1e8 price for each
// requested 32-byte Pyth feed id (hex, no 0x). Keyed by feed id hex in the
// returned map; missing feeds are simply absent (the monitor skips them this
// tick rather than failing the whole batch). Implemented by the Hermes client.
type LatestPriceProvider interface {
	LatestPrices(ctx context.Context, feedIDsHex []string) (map[string]int64, error)
}
