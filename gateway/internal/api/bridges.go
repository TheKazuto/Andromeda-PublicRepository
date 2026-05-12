package api

import (
	"context"
	"fmt"
	"net/http"

	"github.com/google/uuid"

	"github.com/shinkalabs/andromeda-gateway/internal/audit"
	"github.com/shinkalabs/andromeda-gateway/internal/futuresign"
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
