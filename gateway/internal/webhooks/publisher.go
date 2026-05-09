package webhooks

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/google/uuid"
)

// Publisher fans an event out to all active endpoints owned by api_key_id.
// Called from policy hooks, future-sign trigger fires, recovery flows, and
// the on-chain Solana log listener.
type Publisher struct {
	store *Store
}

func NewPublisher(s *Store) *Publisher { return &Publisher{store: s} }

// Publish enqueues one delivery per registered endpoint that subscribes to
// `eventType` (or has no subscription filter, which means "all events").
// Returns the number of endpoints fanned out to.
func (p *Publisher) Publish(ctx context.Context, apiKeyID uuid.UUID, eventType string, payload any) (int, error) {
	body, err := json.Marshal(map[string]any{
		"id":      uuid.New().String(),
		"type":    eventType,
		"data":    payload,
		"created": fmtNowISO(),
	})
	if err != nil {
		return 0, fmt.Errorf("publish marshal: %w", err)
	}
	endpoints, err := p.store.GetActiveEndpointsForEvent(ctx, apiKeyID, eventType)
	if err != nil {
		return 0, err
	}
	count := 0
	for _, ep := range endpoints {
		if err := p.store.EnqueueDelivery(ctx, ep.ID, eventType, uuid.New(), body); err != nil {
			return count, err
		}
		count++
	}
	return count, nil
}

func fmtNowISO() string {
	return nowFn().UTC().Format("2006-01-02T15:04:05.000000000Z07:00")
}
