package webhooks

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/google/uuid"
)

// PublisherMetrics is the minimum metrics surface the publisher uses. Lets
// us record `publish_failures_total{event_type=...}` without importing the
// gateway metrics package directly. Nil-safe via the Recorder() helper.
type PublisherMetrics interface {
	RecordPublishFailure(eventType string)
}

// Publisher fans an event out to all active endpoints owned by api_key_id.
// Called from policy hooks, future-sign trigger fires, recovery flows, and
// the on-chain Solana log listener.
type Publisher struct {
	store   *Store
	metrics PublisherMetrics
}

func NewPublisher(s *Store) *Publisher { return &Publisher{store: s} }

// WithMetrics wires the metrics recorder. Returning *Publisher keeps the
// existing fluent main.go wiring style.
func (p *Publisher) WithMetrics(m PublisherMetrics) *Publisher {
	p.metrics = m
	return p
}

func (p *Publisher) recordFailure(eventType string) {
	if p.metrics != nil {
		p.metrics.RecordPublishFailure(eventType)
	}
}

// Publish enqueues one delivery per registered endpoint that subscribes to
// `eventType` (or has no subscription filter, which means "all events").
// Returns the number of endpoints fanned out to.
//
// The same `eventID` is used in BOTH the payload body (`id` field) AND the
// `event_id` column of every enqueued delivery — so subscribers can use
// the `X-Andromeda-Event-Id` header (or `payload.id`) as a stable
// deduplication key across retries. Retries reuse the same delivery row;
// they never mint a fresh event_id.
func (p *Publisher) Publish(ctx context.Context, apiKeyID uuid.UUID, eventType string, payload any) (int, error) {
	eventID := uuid.New()
	body, err := json.Marshal(map[string]any{
		"id":      eventID.String(),
		"type":    eventType,
		"data":    payload,
		"created": fmtNowISO(),
	})
	if err != nil {
		p.recordFailure(eventType)
		return 0, fmt.Errorf("publish marshal: %w", err)
	}
	endpoints, err := p.store.GetActiveEndpointsForEvent(ctx, apiKeyID, eventType)
	if err != nil {
		p.recordFailure(eventType)
		return 0, err
	}
	count := 0
	for _, ep := range endpoints {
		if err := p.store.EnqueueDelivery(ctx, ep.ID, eventType, eventID, body); err != nil {
			p.recordFailure(eventType)
			return count, err
		}
		count++
	}
	return count, nil
}

func fmtNowISO() string {
	return nowFn().UTC().Format("2006-01-02T15:04:05.000000000Z07:00")
}
