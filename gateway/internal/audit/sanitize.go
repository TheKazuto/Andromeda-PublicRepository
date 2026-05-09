package audit

// Audit log payload sanitization. Audit entries become signed, immutable
// hash-chain records — anything that lands in the payload column lives
// forever in plain text. Even when the gateway and the operators are
// trustworthy, having to scrub PII / secrets out of the audit log later is
// costly and risky (the chain breaks the moment the entry hash is altered).
//
// We therefore enforce an allowlist instead of a blocklist: the canonical
// set of payload keys we know are safe to persist for each event type.
// Anything outside the list is dropped before the record is hashed and
// signed. Long string values are clamped so a misbehaving caller cannot
// blow up the audit table with multi-megabyte payloads.

// maxStringValueBytes caps a single string field. The audit chain is for
// "did this happen, by whom, against what" — not full request bodies.
const maxStringValueBytes = 512

// maxPayloadKeys caps total fan-out per record.
const maxPayloadKeys = 32

// globalAllowlist applies to every event type. Keep it tight — a key only
// belongs here if its presence is universally safe (no PII, no secrets,
// no large values).
var globalAllowlist = map[string]struct{}{
	"id":              {},
	"actor":           {},
	"reason":          {},
	"tenant_id":       {},
	"request_id":      {},
	"trace_id":        {},
	"version":         {},
	"duration_ms":     {},
	"cu_consumed":     {},
	"status":          {},
	"previous_status": {},
	"next_status":     {},
}

// perEventAllowlist extends the global set with event-specific keys. When
// the event_type is not in this map, only globalAllowlist applies (which
// is the safe default for events introduced after this file).
var perEventAllowlist = map[string]map[string]struct{}{
	EventAPIKeyCreated: keys("name", "scopes", "ip_allowlist"),
	EventAPIKeyRevoked: keys("name"),

	EventSubscriptionAssign: keys("plan_code", "billing_cycle"),

	EventDWalletDKGSubmitted: keys("dwallet_address", "scheme", "tx_signature"),
	EventDWalletSignSubmit:   keys("dwallet_address", "scheme", "tx_signature", "operation"),
	EventDWalletSignComplete: keys("dwallet_address", "tx_signature"),
	EventDWalletPresignDone:  keys("dwallet_address", "tx_signature"),

	EventPolicyDeployed:         keys("policy_id", "dwallet_address", "tx_signature"),
	EventPolicyUpdated:          keys("policy_id", "dwallet_address", "tx_signature", "operation"),
	EventPolicyPaused:           keys("policy_id", "dwallet_address"),
	EventPolicyResumed:          keys("policy_id", "dwallet_address"),
	EventPolicyRevoked:          keys("policy_id", "dwallet_address"),
	EventPolicyRequestApproved:  keys("policy_id", "dwallet_address", "request_id"),
	EventPolicyRequestRejected:  keys("policy_id", "dwallet_address", "request_id", "reason"),
	EventPolicySimulateExecuted: keys("policy_id", "dwallet_address", "outcome"),

	EventRecoveryPrimaryUsed:   keys("dwallet_address", "policy_id", "tx_signature", "scheme"),
	EventRecoveryQuorumUsed:    keys("dwallet_address", "policy_id", "tx_signature", "session_address", "members_used"),
	EventRecoveryPolicyChanged: keys("dwallet_address", "policy_id", "operation"),

	EventFutureSignArmed:  keys("trigger_type", "dwallet_address", "expires_at"),
	EventFutureSignFired:  keys("trigger_type", "dwallet_address", "tx_signature"),
	EventFutureSignExpire: keys("trigger_type", "dwallet_address"),
	EventFutureSignCancel: keys("trigger_type", "dwallet_address"),

	EventWebhookEndpointCreate: keys("url", "events"),
	EventWebhookEndpointUpdate: keys("url", "events", "active"),
	EventWebhookEndpointDelete: keys("url"),
	EventWebhookDeliveryRetry:  keys("url", "attempt", "outcome"),

	EventIdempotencyReplayed: keys("idempotency_key", "route"),
}

// sanitizePayload returns a copy of `in` filtered to the allowlist for
// `eventType`. Long string values are truncated; nested structures are
// allowed through (top-level only — depth-1 maps stay as-is) so payloads
// like `{"events": ["foo", "bar"]}` keep working.
func sanitizePayload(eventType string, in map[string]any) map[string]any {
	if in == nil {
		return map[string]any{}
	}
	allowed := map[string]struct{}{}
	for k := range globalAllowlist {
		allowed[k] = struct{}{}
	}
	for k := range perEventAllowlist[eventType] {
		allowed[k] = struct{}{}
	}
	out := make(map[string]any, len(in))
	count := 0
	for k, v := range in {
		if count >= maxPayloadKeys {
			break
		}
		if _, ok := allowed[k]; !ok {
			continue
		}
		out[k] = clampValue(v)
		count++
	}
	return out
}

// clampValue truncates strings beyond maxStringValueBytes, leaves numbers /
// bools / nil untouched, and recurses into slices/maps one level deep so
// `events: ["a", "b"]` gets the same treatment.
func clampValue(v any) any {
	switch t := v.(type) {
	case string:
		if len(t) > maxStringValueBytes {
			return t[:maxStringValueBytes] + "…"
		}
		return t
	case []any:
		out := make([]any, 0, len(t))
		for i, item := range t {
			if i >= 64 {
				break
			}
			out = append(out, clampValue(item))
		}
		return out
	case map[string]any:
		out := make(map[string]any, len(t))
		i := 0
		for k, vv := range t {
			if i >= 16 {
				break
			}
			out[k] = clampValue(vv)
			i++
		}
		return out
	default:
		return t
	}
}

// keys is a tiny constructor so the perEventAllowlist literal stays
// readable.
func keys(items ...string) map[string]struct{} {
	out := make(map[string]struct{}, len(items))
	for _, k := range items {
		out[k] = struct{}{}
	}
	return out
}
