// Package futuresign implements the off-chain orchestrator for Ika
// future-sign triggers (Andromeda Features Roadmap §2).
//
// Devs arm a trigger that watches an off-chain or on-chain condition.
// When the condition fires, the gateway calls
// /v1/dwallet/future-sign/complete/submit on the ika-backend, captures
// the raw signature, and fans the result out via the existing webhook
// pipeline. Andromeda never builds or signs partial-user signatures —
// those are produced by the dev client and supplied at arming time.
package futuresign

import (
	"encoding/json"
	"time"

	"github.com/google/uuid"
)

// TriggerType is the watcher loop that handles a trigger.
type TriggerType string

const (
	TriggerTypeOraclePyth        TriggerType = "oracle_pyth"
	TriggerTypeOracleSwitchboard TriggerType = "oracle_switchboard"
	TriggerTypeSolanaEvent       TriggerType = "solana_event"
	TriggerTypeSlotTime          TriggerType = "slot_time"
	TriggerTypeExternalWebhook   TriggerType = "external_webhook"
)

// IsKnown returns true for trigger types this build supports.
func (t TriggerType) IsKnown() bool {
	switch t {
	case TriggerTypeOraclePyth, TriggerTypeOracleSwitchboard,
		TriggerTypeSolanaEvent, TriggerTypeSlotTime, TriggerTypeExternalWebhook:
		return true
	}
	return false
}

// Status is the lifecycle state of a trigger.
type Status string

const (
	StatusArmed     Status = "armed"
	StatusFiring    Status = "firing"
	StatusFired     Status = "fired"
	StatusExpired   Status = "expired"
	StatusCancelled Status = "cancelled"
	StatusFailed    Status = "failed"
)

// Trigger is the durable representation of an armed future-sign.
type Trigger struct {
	ID               uuid.UUID       `json:"id"`
	APIKeyID         uuid.UUID       `json:"apiKeyId"`
	PartialSigCapID  string          `json:"partialSigCapId"`
	DWalletAddress   string          `json:"dwalletAddress"`
	PolicyProgramID  *string         `json:"policyProgramId,omitempty"`
	TriggerType      TriggerType     `json:"triggerType"`
	Condition        json.RawMessage `json:"condition"`
	WebhookURL       string          `json:"webhookUrl"`
	Status           Status          `json:"status"`
	CreatedAt        time.Time       `json:"createdAt"`
	ExpiresAt        time.Time       `json:"expiresAt"`
	FiredAt          *time.Time      `json:"firedAt,omitempty"`
	SignatureHex     *string         `json:"signatureHex,omitempty"`
	LastCheckSlot    *int64          `json:"lastCheckSlot,omitempty"`
	LastCheckAt      *time.Time      `json:"lastCheckAt,omitempty"`
	FailureCount     int             `json:"failureCount"`
	LastError        *string         `json:"lastError,omitempty"`
	CompletePayload  json.RawMessage `json:"-"` // never returned via API
}

// CreateRequest is the API-level request to arm a trigger.
type CreateRequest struct {
	PartialSigCapID  string          `json:"partialSigCapId"`
	DWalletAddress   string          `json:"dwalletAddress"`
	PolicyProgramID  *string         `json:"policyProgramId,omitempty"`
	TriggerType      TriggerType     `json:"triggerType"`
	Condition        json.RawMessage `json:"condition"`
	WebhookURL       string          `json:"webhookUrl"`
	ExpiresInSeconds int             `json:"expiresInSeconds"`
	// CompletePayload is the body the watcher will POST to the ika-backend at
	// `/v1/dwallet/future-sign/complete/submit` when the trigger fires. The
	// dev pre-builds and pre-signs the partial-user-sig client-side and supplies
	// it here.
	CompletePayload json.RawMessage `json:"completePayload"`
}

// ConditionSlotTime is the schema for `slot_time` triggers.
type ConditionSlotTime struct {
	TriggerAtSlot int64 `json:"triggerAtSlot"`
}

// ConditionExternalWebhook is the schema for `external_webhook` triggers.
type ConditionExternalWebhook struct {
	CallbackURL         string `json:"callbackUrl"`
	PollIntervalSeconds int    `json:"pollIntervalSeconds"`
	// Optional bearer token the gateway sends on the poll request.
	BearerToken string `json:"bearerToken,omitempty"`
}
