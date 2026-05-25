package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/google/uuid"

	"github.com/shinkalabs/andromeda-gateway/internal/audit"
	"github.com/shinkalabs/andromeda-gateway/internal/futuresign"
	"github.com/shinkalabs/andromeda-gateway/internal/intents"
	"github.com/shinkalabs/andromeda-gateway/internal/oraclemonitor"
	"github.com/shinkalabs/andromeda-gateway/internal/policy"
	"github.com/shinkalabs/andromeda-gateway/internal/webhooks"
)

// This file holds the small adapters that let the satellite packages
// (webhooks, future-sign, audit) talk to each other without importing the
// concrete audit.Recorder or knowing how the api package resolves the
// authenticated tenant from a request.

// futureSignAuditBridge adapts audit.Recorder to futuresign.AuditAppender.
type futureSignAuditBridge struct{ rec *audit.Recorder }

func (b *futureSignAuditBridge) Append(ctx context.Context, ev futuresign.AuditEvent) error {
	_, err := b.rec.Append(ctx, audit.Event{
		APIKeyID:     ev.APIKeyID,
		EventType:    ev.EventType,
		ResourceType: ev.ResourceType,
		ResourceID:   ev.ResourceID,
		Actor:        ev.Actor,
		Payload:      ev.Payload,
	})
	return err
}

// oracleMonitorAuditBridge adapts audit.Recorder to oraclemonitor.AuditAppender.
type oracleMonitorAuditBridge struct{ rec *audit.Recorder }

func (b *oracleMonitorAuditBridge) Append(ctx context.Context, ev oraclemonitor.AuditEvent) error {
	_, err := b.rec.Append(ctx, audit.Event{
		APIKeyID:     ev.APIKeyID,
		EventType:    ev.EventType,
		ResourceType: ev.ResourceType,
		ResourceID:   ev.ResourceID,
		Actor:        ev.Actor,
		Payload:      ev.Payload,
	})
	return err
}

// webhookAuditBridge adapts audit.Recorder to webhooks.AuditAppender,
// translating the webhooks-local event struct to the audit envelope.
type webhookAuditBridge struct{ rec *audit.Recorder }

func (b *webhookAuditBridge) Append(ctx context.Context, ev webhooks.AuditEvent) error {
	_, err := b.rec.Append(ctx, audit.Event{
		APIKeyID:     ev.APIKeyID,
		EventType:    ev.EventType,
		ResourceType: ev.ResourceType,
		ResourceID:   ev.ResourceID,
		Actor:        ev.Actor,
		Payload:      ev.Payload,
	})
	return err
}

// apiKeyIDFromRequest is the bridge function passed to idempotency: it pulls
// the authenticated API key id from the request context populated by
// requireAPIKey. Empty string means the middleware treats the request as
// anonymous (idempotency still works, just scoped per route).
func apiKeyIDFromRequest(r *http.Request) string {
	a := authFrom(r)
	if a == nil || a.APIKey == nil {
		return ""
	}
	return a.APIKey.ID
}

// userIDFromRequest pulls the authenticated tenant (user) id from context.
// Empty when unauthenticated. Used by the intents orchestrator for tenant
// isolation + as the X-Andromeda-User-Id forwarded to engines.
func userIDFromRequest(r *http.Request) string {
	a := authFrom(r)
	if a == nil || a.User == nil {
		return ""
	}
	return a.User.ID
}

// NewIntentsAuditBridge adapts the concrete audit.Recorder to the intents
// orchestrator's AuditAppender interface, so main can wire it without the
// intents package importing audit.Recorder. Returns nil when rec is nil.
func NewIntentsAuditBridge(rec *audit.Recorder) intents.AuditAppender {
	if rec == nil {
		return nil
	}
	return &intentsAuditBridge{rec: rec}
}

// intentsAuditBridge adapts audit.Recorder to intents.AuditAppender.
type intentsAuditBridge struct{ rec *audit.Recorder }

func (b *intentsAuditBridge) Append(ctx context.Context, ev intents.AuditEvent) error {
	apiKeyUUID, err := uuid.Parse(ev.APIKeyID)
	if err != nil {
		return fmt.Errorf("intents audit: invalid api_key_id: %w", err)
	}
	_, err = b.rec.Append(ctx, audit.Event{
		APIKeyID:     apiKeyUUID,
		EventType:    ev.EventType,
		ResourceType: ev.ResourceType,
		ResourceID:   ev.ResourceID,
		Actor:        ev.Actor,
		Payload:      ev.Payload,
	})
	return err
}

// resolveAPIKeyID is the satellite-package resolver: webhooks and audit need
// the api_key_id as a uuid.UUID, not a string. Errors when the request was
// not authenticated.
func resolveAPIKeyID(r *http.Request) (uuid.UUID, error) {
	a := authFrom(r)
	if a == nil || a.APIKey == nil {
		return uuid.Nil, fmt.Errorf("missing API key in context")
	}
	return uuid.Parse(a.APIKey.ID)
}

// resolveAPIKeyIDString returns the api_key_id as a raw string. Used by the
// PolicyEngine v3 audit wiring, which keeps the id as the canonical string
// form (matches the resource_id column).
func resolveAPIKeyIDString(r *http.Request) (string, error) {
	a := authFrom(r)
	if a == nil || a.APIKey == nil {
		return "", fmt.Errorf("missing API key in context")
	}
	return a.APIKey.ID, nil
}

// policyEngineAuditBridge adapts audit.Recorder to policy.AuditAppender,
// translating the PolicyEngine-local event struct to the canonical audit
// envelope. Action strings ("init", "rule.add", "rule.items.add",
// "request-signature", etc.) are mapped to the closest EventPolicy* constant.
type policyEngineAuditBridge struct{ rec *audit.Recorder }

func (b policyEngineAuditBridge) AppendPolicyEngineEvent(ctx context.Context, ev policy.PolicyEngineAuditEvent) error {
	apiKeyUUID, err := uuid.Parse(ev.APIKeyID)
	if err != nil {
		return fmt.Errorf("policy engine audit: invalid api_key_id: %w", err)
	}
	payload := map[string]any{
		"action":       ev.Action,
		"engine":       ev.Engine,
		"dwallet":      ev.DWallet,
		"tx_signature": ev.TxSignature,
	}
	if ev.ExtraJSON != "" {
		var extra map[string]any
		if err := json.Unmarshal([]byte(ev.ExtraJSON), &extra); err == nil {
			for k, v := range extra {
				payload[k] = v
			}
		} else {
			payload["extra_raw"] = ev.ExtraJSON
		}
	}
	eventType := audit.EventPolicyUpdated
	switch ev.Action {
	case "init":
		eventType = audit.EventPolicyDeployed
	case "request-signature":
		eventType = audit.EventPolicyRequestApproved
	}
	_, err = b.rec.Append(ctx, audit.Event{
		APIKeyID:     apiKeyUUID,
		EventType:    eventType,
		ResourceType: audit.ResourcePolicy,
		ResourceID:   ev.Engine,
		Actor:        "api_key:" + ev.APIKeyID,
		Payload:      payload,
	})
	return err
}
