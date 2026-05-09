// Package webhooks in the backend ships only the writer half of the
// system: a Publisher that fans an event out to active endpoints by
// inserting rows into webhook_deliveries. The dispatcher (the worker
// that POSTs to customer URLs) lives in the gateway, where the per-
// tenant routing and retry policy already live.
//
// This split keeps backend's notification pipeline self-contained
// (quota / pricing workers fire events here) while keeping the
// HTTP delivery worker close to the tenant routing on the gateway.
package webhooks

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Publisher writes webhook_deliveries rows; the gateway-side dispatcher
// claims them with SKIP LOCKED and POSTs to the registered URL.
type Publisher struct {
	pool *pgxpool.Pool
}

func NewPublisher(pool *pgxpool.Pool) *Publisher { return &Publisher{pool: pool} }

// Publish enqueues one delivery per active endpoint registered for
// `apiKeyID` that subscribes to `eventType` (or has no event filter,
// which means "all events"). Returns the number of endpoints fanned
// out to.
func (p *Publisher) Publish(ctx context.Context, apiKeyID uuid.UUID, eventType string, payload any) (int, error) {
	body, err := json.Marshal(map[string]any{
		"id":      uuid.New().String(),
		"type":    eventType,
		"data":    payload,
		"created": time.Now().UTC().Format("2006-01-02T15:04:05.000000000Z07:00"),
	})
	if err != nil {
		return 0, fmt.Errorf("publish marshal: %w", err)
	}

	rows, err := p.pool.Query(ctx, `
		SELECT id FROM webhook_endpoints
		WHERE api_key_id = $1 AND active = true
		  AND ($2 = ANY(events) OR cardinality(events) = 0)`,
		apiKeyID, eventType)
	if err != nil {
		return 0, fmt.Errorf("list endpoints: %w", err)
	}
	defer rows.Close()

	count := 0
	for rows.Next() {
		var endpointID uuid.UUID
		if err := rows.Scan(&endpointID); err != nil {
			return count, err
		}
		if _, err := p.pool.Exec(ctx, `
			INSERT INTO webhook_deliveries (endpoint_id, event_type, event_id, payload)
			VALUES ($1, $2, $3, $4)`,
			endpointID, eventType, uuid.New(), body); err != nil {
			return count, fmt.Errorf("enqueue delivery: %w", err)
		}
		count++
	}
	return count, rows.Err()
}
