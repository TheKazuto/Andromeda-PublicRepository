package futuresign

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

// ErrNotFound is returned when a trigger is missing or not owned by the caller.
var ErrNotFound = errors.New("trigger not found")

// Store persists triggers to Postgres.
type Store struct {
	pool *pgxpool.Pool
}

// NewStore returns a Store backed by the supplied pool.
func NewStore(pool *pgxpool.Pool) *Store { return &Store{pool: pool} }

// Create inserts a new armed trigger and returns it.
func (s *Store) Create(ctx context.Context, apiKeyID uuid.UUID, req CreateRequest) (*Trigger, error) {
	if req.ExpiresInSeconds < 60 {
		return nil, fmt.Errorf("expiresInSeconds must be >= 60")
	}
	if !req.TriggerType.IsKnown() {
		return nil, fmt.Errorf("unknown trigger_type: %s", req.TriggerType)
	}
	expires := time.Now().UTC().Add(time.Duration(req.ExpiresInSeconds) * time.Second)
	id := uuid.New()
	cond := req.Condition
	if len(cond) == 0 {
		cond = json.RawMessage("{}")
	}
	complete := req.CompletePayload
	if len(complete) == 0 {
		complete = json.RawMessage("{}")
	}
	row := s.pool.QueryRow(ctx, `
		INSERT INTO future_sign_triggers
			(id, api_key_id, partial_sig_cap_id, dwallet_address, policy_program_id,
			 trigger_type, condition, webhook_url, status, expires_at, complete_payload)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 'armed', $9, $10)
		RETURNING created_at
	`, id, apiKeyID, req.PartialSigCapID, req.DWalletAddress, req.PolicyProgramID,
		req.TriggerType, string(cond), req.WebhookURL, expires, string(complete))
	var createdAt time.Time
	if err := row.Scan(&createdAt); err != nil {
		return nil, fmt.Errorf("insert trigger: %w", err)
	}
	return &Trigger{
		ID:              id,
		APIKeyID:        apiKeyID,
		PartialSigCapID: req.PartialSigCapID,
		DWalletAddress:  req.DWalletAddress,
		PolicyProgramID: req.PolicyProgramID,
		TriggerType:     req.TriggerType,
		Condition:       cond,
		WebhookURL:      req.WebhookURL,
		Status:          StatusArmed,
		CreatedAt:       createdAt,
		ExpiresAt:       expires,
		CompletePayload: complete,
	}, nil
}

// Get returns a trigger if it belongs to the caller.
func (s *Store) Get(ctx context.Context, apiKeyID, id uuid.UUID) (*Trigger, error) {
	row := s.pool.QueryRow(ctx, selectColumns+`
		FROM future_sign_triggers
		WHERE id = $1 AND api_key_id = $2
	`, id, apiKeyID)
	t, err := scanTrigger(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	return t, err
}

// List returns the most recent triggers for the calling tenant.
func (s *Store) List(ctx context.Context, apiKeyID uuid.UUID, limit int) ([]*Trigger, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	rows, err := s.pool.Query(ctx, selectColumns+`
		FROM future_sign_triggers
		WHERE api_key_id = $1
		ORDER BY created_at DESC
		LIMIT $2
	`, apiKeyID, limit)
	if err != nil {
		return nil, fmt.Errorf("list triggers: %w", err)
	}
	defer rows.Close()
	var out []*Trigger
	for rows.Next() {
		t, err := scanTrigger(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// Cancel transitions an armed trigger to cancelled. Idempotent on already-fired
// triggers (returns ErrNotFound when nothing changes).
func (s *Store) Cancel(ctx context.Context, apiKeyID, id uuid.UUID) error {
	tag, err := s.pool.Exec(ctx, `
		UPDATE future_sign_triggers
		SET status = 'cancelled'
		WHERE id = $1 AND api_key_id = $2 AND status = 'armed'
	`, id, apiKeyID)
	if err != nil {
		return fmt.Errorf("cancel trigger: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// ClaimDueArmed atomically transitions the next due armed trigger to 'firing'
// using SELECT FOR UPDATE SKIP LOCKED so concurrent watcher workers never
// double-fire the same trigger. Returns nil, nil when nothing is due.
func (s *Store) ClaimDueArmed(ctx context.Context, kinds []TriggerType, now time.Time) (*Trigger, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("claim begin: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	row := tx.QueryRow(ctx, selectColumns+`
		FROM future_sign_triggers
		WHERE status = 'armed' AND expires_at > $1 AND trigger_type = ANY($2::future_sign_trigger_type[])
		ORDER BY created_at ASC
		FOR UPDATE SKIP LOCKED
		LIMIT 1
	`, now, kindsToTextArray(kinds))
	t, err := scanTrigger(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	if _, err := tx.Exec(ctx, `
		UPDATE future_sign_triggers
		SET status = 'firing', last_check_at = $1
		WHERE id = $2
	`, now, t.ID); err != nil {
		return nil, fmt.Errorf("claim update: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("claim commit: %w", err)
	}
	t.Status = StatusFiring
	checked := now
	t.LastCheckAt = &checked
	return t, nil
}

// MarkFired records a successful fire and stores the captured raw signature.
func (s *Store) MarkFired(ctx context.Context, id uuid.UUID, signatureHex string) error {
	now := time.Now().UTC()
	tag, err := s.pool.Exec(ctx, `
		UPDATE future_sign_triggers
		SET status = 'fired', fired_at = $1, signature_hex = $2
		WHERE id = $3 AND status IN ('armed', 'firing')
	`, now, signatureHex, id)
	if err != nil {
		return fmt.Errorf("mark fired: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// MaxRetryCount is the circuit-breaker bound for transient failures. Once a
// trigger has failed this many times consecutively, MarkFailed promotes it
// to terminal `failed` state instead of bouncing it back to `armed`. Without
// this bound a misconfigured callbackUrl would cause the watcher to keep
// hammering the URL (and potentially leaking a bearer token) until expiry.
const MaxRetryCount = 10

// MarkArmedChecked records a benign "not yet ready" outcome for a claimed
// trigger and bounces it back to 'armed' WITHOUT incrementing
// failure_count. Use this for normal polling outcomes that are not real
// failures:
//
//   - slot_time trigger whose target slot hasn't been reached.
//   - external_webhook returning {shouldFire: false} (or a 3xx the watcher
//     refuses to follow).
//
// Real failures (callback unreachable, bad JSON, SSRF reject, ika completer
// error) must still go through MarkFailed so the circuit breaker can fire.
func (s *Store) MarkArmedChecked(ctx context.Context, id uuid.UUID) error {
	now := time.Now().UTC()
	tag, err := s.pool.Exec(ctx, `
		UPDATE future_sign_triggers
		SET status = 'armed', last_check_at = $1
		WHERE id = $2 AND status = 'firing'
	`, now, id)
	if err != nil {
		return fmt.Errorf("mark armed checked: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// MarkFailed bumps failure_count and records the error. While failure_count
// is below MaxRetryCount the trigger goes back to 'armed' so the watcher
// retries on the next tick. After the threshold is reached the trigger
// transitions to terminal 'failed' to break the retry loop early.
func (s *Store) MarkFailed(ctx context.Context, id uuid.UUID, reason string) error {
	tag, err := s.pool.Exec(ctx, `
		UPDATE future_sign_triggers
		SET status = CASE
		      WHEN failure_count + 1 >= $3 THEN 'failed'::future_sign_trigger_status
		      ELSE 'armed'::future_sign_trigger_status
		    END,
		    failure_count = failure_count + 1,
		    last_error = $1
		WHERE id = $2 AND status = 'firing'
	`, reason, id, MaxRetryCount)
	if err != nil {
		return fmt.Errorf("mark failed: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// ExpiredTrigger identifies a trigger that transitioned to expired, with the
// owning tenant so callers can fan out future_sign.expired to the right
// endpoints (the webhook Publisher scopes deliveries by api_key_id).
type ExpiredTrigger struct {
	ID       uuid.UUID
	APIKeyID uuid.UUID
}

// ExpireOverdue marks all armed triggers past expires_at as expired and returns
// each transitioned trigger together with its owning api_key_id, so callers fan
// out future_sign.expired to the owning tenant (publishing with uuid.Nil would
// match no endpoint and silently drop the event).
func (s *Store) ExpireOverdue(ctx context.Context, now time.Time) ([]ExpiredTrigger, error) {
	rows, err := s.pool.Query(ctx, `
		UPDATE future_sign_triggers
		SET status = 'expired'
		WHERE status = 'armed' AND expires_at <= $1
		RETURNING id, api_key_id
	`, now)
	if err != nil {
		return nil, fmt.Errorf("expire overdue: %w", err)
	}
	defer rows.Close()
	var out []ExpiredTrigger
	for rows.Next() {
		var e ExpiredTrigger
		if err := rows.Scan(&e.ID, &e.APIKeyID); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// ----- internal -----

const selectColumns = `
SELECT id, api_key_id, partial_sig_cap_id, dwallet_address, policy_program_id,
       trigger_type, condition, webhook_url, status, created_at, expires_at,
       fired_at, signature_hex, last_check_slot, last_check_at, failure_count,
       last_error, complete_payload
`

type rowScanner interface {
	Scan(dest ...any) error
}

func scanTrigger(s rowScanner) (*Trigger, error) {
	var t Trigger
	var conditionRaw, completeRaw string
	var triggerType string
	var status string
	if err := s.Scan(
		&t.ID, &t.APIKeyID, &t.PartialSigCapID, &t.DWalletAddress, &t.PolicyProgramID,
		&triggerType, &conditionRaw, &t.WebhookURL, &status, &t.CreatedAt, &t.ExpiresAt,
		&t.FiredAt, &t.SignatureHex, &t.LastCheckSlot, &t.LastCheckAt, &t.FailureCount,
		&t.LastError, &completeRaw,
	); err != nil {
		return nil, err
	}
	t.TriggerType = TriggerType(triggerType)
	t.Status = Status(status)
	t.Condition = json.RawMessage(conditionRaw)
	t.CompletePayload = json.RawMessage(completeRaw)
	return &t, nil
}

func kindsToTextArray(kinds []TriggerType) []string {
	out := make([]string, len(kinds))
	for i, k := range kinds {
		out[i] = string(k)
	}
	return out
}
