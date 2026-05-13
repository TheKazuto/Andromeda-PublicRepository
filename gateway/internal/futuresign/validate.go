package futuresign

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/shinkalabs/andromeda-gateway/internal/netsafety"
)

// validateCondition enforces type-specific shape rules at arming time so
// invalid triggers never reach the watcher (where they would otherwise fail
// minutes/hours later with `invalid condition`). Returns a sanitised error
// message suitable for the response body — never echo raw upstream errors.
//
// The url guard is passed in so external_webhook callbackUrl is checked at
// register time (mirrors the existing webhookUrl check).
func validateCondition(ctx context.Context, triggerType TriggerType, raw json.RawMessage, guard *netsafety.Validator) error {
	if len(raw) == 0 || string(raw) == "{}" {
		// Slot-time and external-webhook MUST have a body. Oracle/Solana-event
		// triggers also need at least one field — empty conditions are never
		// useful and indicate a client bug.
		return fmt.Errorf("condition is required for trigger_type=%s", triggerType)
	}

	switch triggerType {
	case TriggerTypeSlotTime:
		var c ConditionSlotTime
		if err := json.Unmarshal(raw, &c); err != nil {
			return fmt.Errorf("condition must match slot_time schema: %s", err)
		}
		if c.TriggerAtSlot <= 0 {
			return fmt.Errorf("condition.triggerAtSlot must be > 0")
		}
		return nil

	case TriggerTypeExternalWebhook:
		var c ConditionExternalWebhook
		if err := json.Unmarshal(raw, &c); err != nil {
			return fmt.Errorf("condition must match external_webhook schema: %s", err)
		}
		if c.CallbackURL == "" {
			return fmt.Errorf("condition.callbackUrl is required")
		}
		if guard != nil {
			if err := guard.ValidateRegister(ctx, c.CallbackURL); err != nil {
				// Sanitised — do not leak which guard rule tripped.
				return fmt.Errorf("condition.callbackUrl is not allowed by security policy")
			}
		}
		if c.PollIntervalSeconds < 0 {
			return fmt.Errorf("condition.pollIntervalSeconds must be >= 0")
		}
		return nil

	case TriggerTypeSolanaEvent, TriggerTypeOraclePyth, TriggerTypeOracleSwitchboard:
		// Watcher loops for these are not yet wired (see watcher.go). Accept
		// any non-empty JSON object so existing clients can still arm them,
		// but require at least one field so a stray `{}` is caught at create
		// time rather than days later.
		var probe map[string]json.RawMessage
		if err := json.Unmarshal(raw, &probe); err != nil {
			return fmt.Errorf("condition must be a JSON object: %s", err)
		}
		if len(probe) == 0 {
			return fmt.Errorf("condition must have at least one field for trigger_type=%s", triggerType)
		}
		return nil

	default:
		// Defensive: unreachable because IsKnown() is checked upstream.
		return fmt.Errorf("unsupported trigger_type=%s", triggerType)
	}
}
