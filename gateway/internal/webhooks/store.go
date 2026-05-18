package webhooks

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Endpoint mirrors the webhook_endpoints row.
type Endpoint struct {
	ID            uuid.UUID  `json:"id"`
	APIKeyID      uuid.UUID  `json:"api_key_id"`
	URL           string     `json:"url"`
	Secret        string     `json:"-"`
	Events        []string   `json:"events"`
	Active        bool       `json:"active"`
	CreatedAt     time.Time  `json:"created_at"`
	LastSuccessAt *time.Time `json:"last_success_at,omitempty"`
	LastFailureAt *time.Time `json:"last_failure_at,omitempty"`
	FailureCount  int        `json:"failure_count"`
}

// Delivery mirrors the webhook_deliveries row (without the full payload
// when listed from the API for log brevity).
type Delivery struct {
	ID                 uuid.UUID       `json:"id"`
	EndpointID         uuid.UUID       `json:"endpoint_id"`
	EventType          string          `json:"event_type"`
	EventID            uuid.UUID       `json:"event_id"`
	Payload            json.RawMessage `json:"payload,omitempty"`
	Status             string          `json:"status"`
	Attempts           int             `json:"attempts"`
	NextAttemptAt      time.Time       `json:"next_attempt_at"`
	LastResponseStatus *int            `json:"last_response_status,omitempty"`
	LastResponseBody   *string         `json:"last_response_body,omitempty"`
	CreatedAt          time.Time       `json:"created_at"`
	DeliveredAt        *time.Time      `json:"delivered_at,omitempty"`
}

type Store struct {
	pool *pgxpool.Pool
}

func NewStore(pool *pgxpool.Pool) *Store {
	return &Store{pool: pool}
}

var ErrEndpointNotFound = errors.New("webhook endpoint not found")

func (s *Store) CreateEndpoint(ctx context.Context, apiKeyID uuid.UUID, url, secret string, events []string) (*Endpoint, error) {
	row := s.pool.QueryRow(ctx, `
		INSERT INTO webhook_endpoints (api_key_id, url, secret, events)
		VALUES ($1, $2, $3, $4)
		RETURNING id, api_key_id, url, secret, events, active, created_at,
		          last_success_at, last_failure_at, failure_count
	`, apiKeyID, url, secret, events)
	return scanEndpoint(row)
}

func (s *Store) ListEndpoints(ctx context.Context, apiKeyID uuid.UUID) ([]*Endpoint, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, api_key_id, url, secret, events, active, created_at,
		       last_success_at, last_failure_at, failure_count
		FROM webhook_endpoints WHERE api_key_id = $1 ORDER BY created_at DESC
	`, apiKeyID)
	if err != nil {
		return nil, fmt.Errorf("list endpoints: %w", err)
	}
	defer rows.Close()
	out := []*Endpoint{}
	for rows.Next() {
		ep, err := scanEndpoint(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, ep)
	}
	return out, rows.Err()
}

type EndpointPatch struct {
	URL    *string
	Events *[]string
	Active *bool
}

func (s *Store) UpdateEndpoint(ctx context.Context, apiKeyID, id uuid.UUID, patch EndpointPatch) (*Endpoint, error) {
	row := s.pool.QueryRow(ctx, `
		UPDATE webhook_endpoints
		SET url    = COALESCE($3, url),
		    events = COALESCE($4, events),
		    active = COALESCE($5, active)
		WHERE id = $1 AND api_key_id = $2
		RETURNING id, api_key_id, url, secret, events, active, created_at,
		          last_success_at, last_failure_at, failure_count
	`, id, apiKeyID, patch.URL, patch.Events, patch.Active)
	ep, err := scanEndpoint(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrEndpointNotFound
	}
	return ep, err
}

func (s *Store) DeleteEndpoint(ctx context.Context, apiKeyID, id uuid.UUID) error {
	tag, err := s.pool.Exec(ctx, `DELETE FROM webhook_endpoints WHERE id = $1 AND api_key_id = $2`, id, apiKeyID)
	if err != nil {
		return fmt.Errorf("delete endpoint: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrEndpointNotFound
	}
	return nil
}

func (s *Store) GetActiveEndpointsForEvent(ctx context.Context, apiKeyID uuid.UUID, eventType string) ([]*Endpoint, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, api_key_id, url, secret, events, active, created_at,
		       last_success_at, last_failure_at, failure_count
		FROM webhook_endpoints
		WHERE api_key_id = $1 AND active = true
		  AND ($2 = ANY(events) OR cardinality(events) = 0)
	`, apiKeyID, eventType)
	if err != nil {
		return nil, fmt.Errorf("query active endpoints: %w", err)
	}
	defer rows.Close()
	out := []*Endpoint{}
	for rows.Next() {
		ep, err := scanEndpoint(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, ep)
	}
	return out, rows.Err()
}

func (s *Store) EnqueueDelivery(ctx context.Context, endpointID uuid.UUID, eventType string, eventID uuid.UUID, payload json.RawMessage) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO webhook_deliveries (endpoint_id, event_type, event_id, payload)
		VALUES ($1, $2, $3, $4)
	`, endpointID, eventType, eventID, payload)
	if err != nil {
		return fmt.Errorf("enqueue delivery: %w", err)
	}
	return nil
}

// ClaimDeliveries picks up to `limit` pending deliveries and atomically marks
// them in_flight via SKIP LOCKED. The claim carries a lease: claim_deadline
// = now() + leaseSeconds. A separate RecoverStuck sweep reverts any
// in_flight row whose deadline has passed (crashed dispatcher).
//
// `claimOwner` identifies the replica that took the lease — informational
// only, never used for authorization (the deadline is the authority).
func (s *Store) ClaimDeliveries(ctx context.Context, limit int, leaseSeconds int, claimOwner string) ([]*Delivery, error) {
	if leaseSeconds <= 0 {
		leaseSeconds = 60
	}
	rows, err := s.pool.Query(ctx, `
		WITH picked AS (
			SELECT id FROM webhook_deliveries
			WHERE status = 'pending' AND next_attempt_at <= now()
			ORDER BY next_attempt_at
			FOR UPDATE SKIP LOCKED
			LIMIT $1
		)
		UPDATE webhook_deliveries d
		SET status         = 'in_flight',
		    attempts       = attempts + 1,
		    claimed_at     = now(),
		    claim_deadline = now() + ($2::int * INTERVAL '1 second'),
		    claim_owner    = $3
		FROM picked WHERE d.id = picked.id
		RETURNING d.id, d.endpoint_id, d.event_type, d.event_id, d.payload,
		          d.status, d.attempts, d.next_attempt_at,
		          d.last_response_status, d.last_response_body, d.created_at, d.delivered_at
	`, limit, leaseSeconds, claimOwner)
	if err != nil {
		return nil, fmt.Errorf("claim deliveries: %w", err)
	}
	defer rows.Close()
	out := []*Delivery{}
	for rows.Next() {
		d := &Delivery{}
		if err := rows.Scan(&d.ID, &d.EndpointID, &d.EventType, &d.EventID, &d.Payload,
			&d.Status, &d.Attempts, &d.NextAttemptAt,
			&d.LastResponseStatus, &d.LastResponseBody, &d.CreatedAt, &d.DeliveredAt); err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

// RequeueWithDelay puts an in_flight delivery back into `pending` with
// next_attempt_at = now() + delay. Used by the dispatcher when the
// per-destination rate limit denied this attempt — the row stays at the
// same `attempts` count and the worker pool will try again later.
//
// Lease metadata is cleared so the recovery sweeper doesn't accidentally
// double-requeue.
func (s *Store) RequeueWithDelay(ctx context.Context, id uuid.UUID, delay time.Duration) error {
	if delay <= 0 {
		delay = time.Second
	}
	_, err := s.pool.Exec(ctx, `
		UPDATE webhook_deliveries
		SET status = 'pending',
		    attempts = GREATEST(attempts - 1, 0),
		    claimed_at = NULL,
		    claim_deadline = NULL,
		    claim_owner = NULL,
		    next_attempt_at = now() + ($2::int * INTERVAL '1 millisecond')
		WHERE id = $1 AND status = 'in_flight'
	`, id, int(delay/time.Millisecond))
	if err != nil {
		return fmt.Errorf("requeue with delay: %w", err)
	}
	return nil
}

// RecoverStuck reverts in_flight rows whose lease expired back to pending
// so the next dispatcher tick reclaims them. Returns the number of rows
// recovered. Designed for periodic invocation (every 30s); cheap thanks
// to idx_webhook_deliveries_lease_expired.
func (s *Store) RecoverStuck(ctx context.Context) (int64, error) {
	tag, err := s.pool.Exec(ctx, `
		UPDATE webhook_deliveries
		SET status         = 'pending',
		    claimed_at     = NULL,
		    claim_deadline = NULL,
		    claim_owner    = NULL,
		    next_attempt_at = now()
		WHERE status = 'in_flight'
		  AND claim_deadline IS NOT NULL
		  AND claim_deadline < now()
	`)
	if err != nil {
		return 0, fmt.Errorf("recover stuck deliveries: %w", err)
	}
	return tag.RowsAffected(), nil
}

func (s *Store) MarkDelivered(ctx context.Context, id uuid.UUID, status int, body string) error {
	_, err := s.pool.Exec(ctx, `
		UPDATE webhook_deliveries
		SET status = 'delivered', delivered_at = now(),
		    last_response_status = $2, last_response_body = $3,
		    claimed_at = NULL, claim_deadline = NULL, claim_owner = NULL
		WHERE id = $1
	`, id, status, truncateBody(body))
	if err != nil {
		return err
	}
	_, _ = s.pool.Exec(ctx, `
		UPDATE webhook_endpoints SET last_success_at = now(), failure_count = 0
		WHERE id = (SELECT endpoint_id FROM webhook_deliveries WHERE id = $1)
	`, id)
	return nil
}

func (s *Store) MarkFailed(ctx context.Context, id uuid.UUID, status int, body string, nextAttempt time.Time, dead bool) error {
	finalStatus := "pending"
	if dead {
		finalStatus = "dead_letter"
	}
	_, err := s.pool.Exec(ctx, `
		UPDATE webhook_deliveries
		SET status = $4, last_response_status = $2, last_response_body = $3, next_attempt_at = $5,
		    claimed_at = NULL, claim_deadline = NULL, claim_owner = NULL
		WHERE id = $1
	`, id, status, truncateBody(body), finalStatus, nextAttempt)
	if err != nil {
		return err
	}
	_, _ = s.pool.Exec(ctx, `
		UPDATE webhook_endpoints SET last_failure_at = now(), failure_count = failure_count + 1
		WHERE id = (SELECT endpoint_id FROM webhook_deliveries WHERE id = $1)
	`, id)
	return nil
}

func (s *Store) RetryDeadLetter(ctx context.Context, apiKeyID, id uuid.UUID) error {
	tag, err := s.pool.Exec(ctx, `
		UPDATE webhook_deliveries d
		SET status = 'pending', next_attempt_at = now()
		FROM webhook_endpoints e
		WHERE d.id = $1 AND e.id = d.endpoint_id AND e.api_key_id = $2
		  AND d.status = 'dead_letter'
	`, id, apiKeyID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrEndpointNotFound
	}
	return nil
}

func (s *Store) ListDeliveries(ctx context.Context, apiKeyID uuid.UUID, endpointID *uuid.UUID, status string, limit int) ([]*Delivery, error) {
	if limit > 200 {
		limit = 200
	}
	if limit <= 0 {
		limit = 50
	}
	rows, err := s.pool.Query(ctx, `
		SELECT d.id, d.endpoint_id, d.event_type, d.event_id, d.payload,
		       d.status, d.attempts, d.next_attempt_at,
		       d.last_response_status, d.last_response_body, d.created_at, d.delivered_at
		FROM webhook_deliveries d
		JOIN webhook_endpoints  e ON e.id = d.endpoint_id
		WHERE e.api_key_id = $1
		  AND ($2::uuid IS NULL OR d.endpoint_id = $2)
		  AND ($3::text  IS NULL OR d.status     = $3::webhook_delivery_status)
		ORDER BY d.created_at DESC LIMIT $4
	`, apiKeyID, endpointID, nullIfEmpty(status), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*Delivery{}
	for rows.Next() {
		d := &Delivery{}
		if err := rows.Scan(&d.ID, &d.EndpointID, &d.EventType, &d.EventID, &d.Payload,
			&d.Status, &d.Attempts, &d.NextAttemptAt,
			&d.LastResponseStatus, &d.LastResponseBody, &d.CreatedAt, &d.DeliveredAt); err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

// CountDLQ returns the number of webhook deliveries currently in the
// dead_letter status. Used by the metrics scraper to expose
// gateway_webhook_dlq_depth so ops can alert when DLQ piles up.
func (s *Store) CountDLQ(ctx context.Context) (int64, error) {
	var n int64
	err := s.pool.QueryRow(ctx,
		`SELECT COUNT(*)::bigint FROM webhook_deliveries WHERE status = 'dead_letter'`).
		Scan(&n)
	if err != nil {
		return 0, fmt.Errorf("count dlq: %w", err)
	}
	return n, nil
}

// BacklogSnapshot is the lightweight projection the metrics scraper
// pulls every 15s to expose webhook queue health. Counts and ages cover
// only `pending` (ready for next attempt) and `in_flight` (claimed by a
// dispatcher) rows — DLQ has its own dedicated gauge.
type BacklogSnapshot struct {
	Pending             int64
	InFlight            int64
	OldestPendingAgeSec float64
	OldestInFlightAgeSec float64
}

// BacklogSnapshot returns counts and oldest-age (seconds) for webhook
// deliveries in `pending` and `in_flight` status. A single round-trip;
// the conditional EXTRACT keeps the ages NULL-safe when a status is
// empty.
func (s *Store) BacklogSnapshot(ctx context.Context) (BacklogSnapshot, error) {
	var snap BacklogSnapshot
	err := s.pool.QueryRow(ctx, `
		SELECT
		  COUNT(*) FILTER (WHERE status = 'pending' AND next_attempt_at <= now())                       AS pending_ready,
		  COUNT(*) FILTER (WHERE status = 'in_flight')                                                   AS in_flight,
		  COALESCE(EXTRACT(EPOCH FROM (now() - MIN(next_attempt_at) FILTER (WHERE status = 'pending' AND next_attempt_at <= now()))), 0)::float8 AS oldest_pending_age,
		  COALESCE(EXTRACT(EPOCH FROM (now() - MIN(next_attempt_at) FILTER (WHERE status = 'in_flight'))), 0)::float8                            AS oldest_in_flight_age
		FROM webhook_deliveries
	`).Scan(&snap.Pending, &snap.InFlight, &snap.OldestPendingAgeSec, &snap.OldestInFlightAgeSec)
	if err != nil {
		return snap, fmt.Errorf("backlog snapshot: %w", err)
	}
	return snap, nil
}

func scanEndpoint(row pgx.Row) (*Endpoint, error) {
	ep := &Endpoint{}
	err := row.Scan(&ep.ID, &ep.APIKeyID, &ep.URL, &ep.Secret, &ep.Events, &ep.Active,
		&ep.CreatedAt, &ep.LastSuccessAt, &ep.LastFailureAt, &ep.FailureCount)
	if err != nil {
		return nil, err
	}
	return ep, nil
}

func truncateBody(s string) string {
	if len(s) > 4096 {
		return s[:4096]
	}
	return s
}

func nullIfEmpty(s string) any {
	if s == "" {
		return nil
	}
	return s
}
