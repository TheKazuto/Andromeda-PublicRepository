package oraclemonitor

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
var ErrNotFound = errors.New("price trigger not found")

// MaxRetryCount is the circuit-breaker bound for transient fire failures. Once
// a trigger has failed this many times, MarkFailed promotes it to terminal
// `failed` instead of bouncing back to `armed`, so a permanently failing
// trigger (e.g. a stale rules_generation) stops burning gas on retries.
const MaxRetryCount = 10

// MaxArmedPerTenant caps how many triggers a single API key can hold armed per
// cluster. Defence against a tenant (or a leaked key) arming thousands of
// triggers to bloat the worker scan and drain the gas sponsor on fire. A soft
// cap (a tiny race may let it overshoot by one) on top of the per-arm quota +
// rate limit.
const MaxArmedPerTenant = 100

// Store persists price triggers to Postgres.
type Store struct {
	pool *pgxpool.Pool
}

// NewStore returns a Store backed by the supplied pool.
func NewStore(pool *pgxpool.Pool) *Store { return &Store{pool: pool} }

const selectColumns = `
SELECT id, api_key_id, cluster, dwallet_address, feed_cache_pda, pyth_feed_id_hex,
       min_1e8, max_1e8, hysteresis_bps, request_signature_payload,
       status, created_at, expires_at, fired_at, tx_signature, last_check_at,
       last_price_1e8, failure_count, last_error
`

type rowScanner interface {
	Scan(dest ...any) error
}

func scanTrigger(s rowScanner) (*PriceTrigger, error) {
	var t PriceTrigger
	var status, payloadRaw string
	if err := s.Scan(
		&t.ID, &t.APIKeyID, &t.Cluster, &t.DWalletAddress, &t.FeedCachePDA, &t.PythFeedIDHex,
		&t.Min1e8, &t.Max1e8, &t.HysteresisBps, &payloadRaw,
		&status, &t.CreatedAt, &t.ExpiresAt, &t.FiredAt, &t.TxSignature, &t.LastCheckAt,
		&t.LastPrice1e8, &t.FailureCount, &t.LastError,
	); err != nil {
		return nil, err
	}
	t.Status = Status(status)
	t.RequestSignaturePayload = json.RawMessage(payloadRaw)
	return &t, nil
}

// Create inserts a new armed price trigger and returns it.
func (s *Store) Create(ctx context.Context, apiKeyID uuid.UUID, cluster string, req CreateRequest) (*PriceTrigger, error) {
	if req.Min1e8 < 0 {
		return nil, fmt.Errorf("min1e8 must be >= 0")
	}
	if req.Min1e8 > req.Max1e8 {
		return nil, fmt.Errorf("min1e8 must be <= max1e8")
	}
	if req.ExpiresInSeconds < 60 {
		return nil, fmt.Errorf("expiresInSeconds must be >= 60")
	}
	payload := req.RequestSignaturePayload
	if len(payload) == 0 {
		payload = json.RawMessage("{}")
	}
	expires := time.Now().UTC().Add(time.Duration(req.ExpiresInSeconds) * time.Second)
	id := uuid.New()

	// Count + insert in one tx so the per-tenant armed cap is enforced against
	// a consistent snapshot (soft cap; READ COMMITTED may allow a 1-row
	// overshoot under concurrent arms, which is acceptable for anti-abuse).
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("begin create: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var armed int
	if err := tx.QueryRow(ctx, `
		SELECT count(*) FROM oracle_price_triggers
		WHERE api_key_id = $1 AND cluster = $2 AND status = 'armed'
	`, apiKeyID, cluster).Scan(&armed); err != nil {
		return nil, fmt.Errorf("count armed triggers: %w", err)
	}
	if armed >= MaxArmedPerTenant {
		return nil, fmt.Errorf("too many armed triggers (max %d); cancel some first", MaxArmedPerTenant)
	}

	var createdAt time.Time
	if err := tx.QueryRow(ctx, `
		INSERT INTO oracle_price_triggers
			(id, api_key_id, cluster, dwallet_address, feed_cache_pda, pyth_feed_id_hex,
			 min_1e8, max_1e8, hysteresis_bps, request_signature_payload,
			 status, expires_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,'armed',$11)
		RETURNING created_at
	`, id, apiKeyID, cluster, req.DWalletAddress, req.FeedCachePDA, req.PythFeedIDHex,
		req.Min1e8, req.Max1e8, req.HysteresisBps, string(payload), expires).Scan(&createdAt); err != nil {
		return nil, fmt.Errorf("insert price trigger: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("commit create: %w", err)
	}
	return &PriceTrigger{
		ID:                      id,
		APIKeyID:                apiKeyID,
		Cluster:                 cluster,
		DWalletAddress:          req.DWalletAddress,
		FeedCachePDA:            req.FeedCachePDA,
		PythFeedIDHex:           req.PythFeedIDHex,
		Min1e8:                  req.Min1e8,
		Max1e8:                  req.Max1e8,
		HysteresisBps:           req.HysteresisBps,
		Status:                  StatusArmed,
		CreatedAt:               createdAt,
		ExpiresAt:               expires,
		RequestSignaturePayload: payload,
	}, nil
}

// Get returns a trigger if it belongs to the caller.
func (s *Store) Get(ctx context.Context, apiKeyID, id uuid.UUID) (*PriceTrigger, error) {
	row := s.pool.QueryRow(ctx, selectColumns+`
		FROM oracle_price_triggers WHERE id = $1 AND api_key_id = $2
	`, id, apiKeyID)
	t, err := scanTrigger(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	return t, err
}

// List returns the most recent triggers for the calling tenant.
func (s *Store) List(ctx context.Context, apiKeyID uuid.UUID, limit int) ([]*PriceTrigger, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	rows, err := s.pool.Query(ctx, selectColumns+`
		FROM oracle_price_triggers WHERE api_key_id = $1
		ORDER BY created_at DESC LIMIT $2
	`, apiKeyID, limit)
	if err != nil {
		return nil, fmt.Errorf("list price triggers: %w", err)
	}
	defer rows.Close()
	var out []*PriceTrigger
	for rows.Next() {
		t, err := scanTrigger(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// Cancel transitions an armed trigger to cancelled (idempotent: ErrNotFound
// when nothing changes — already fired/cancelled).
func (s *Store) Cancel(ctx context.Context, apiKeyID, id uuid.UUID) error {
	tag, err := s.pool.Exec(ctx, `
		UPDATE oracle_price_triggers SET status = 'cancelled'
		WHERE id = $1 AND api_key_id = $2 AND status = 'armed'
	`, id, apiKeyID)
	if err != nil {
		return fmt.Errorf("cancel price trigger: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// ListActiveArmed returns armed, unexpired triggers for the cluster (bounded
// batch) so the worker can fetch the live prices and evaluate the bands.
func (s *Store) ListActiveArmed(ctx context.Context, cluster string, limit int, now time.Time) ([]*PriceTrigger, error) {
	if limit <= 0 || limit > 1000 {
		limit = 500
	}
	rows, err := s.pool.Query(ctx, selectColumns+`
		FROM oracle_price_triggers
		WHERE cluster = $1 AND status = 'armed' AND expires_at > $2
		ORDER BY created_at ASC LIMIT $3
	`, cluster, now, limit)
	if err != nil {
		return nil, fmt.Errorf("list active armed: %w", err)
	}
	defer rows.Close()
	var out []*PriceTrigger
	for rows.Next() {
		t, err := scanTrigger(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// CountArmed returns how many triggers are currently armed for the cluster.
// Used by the metrics scraper to publish the armed-triggers gauge.
func (s *Store) CountArmed(ctx context.Context, cluster string) (int, error) {
	var n int
	err := s.pool.QueryRow(ctx, `
		SELECT count(*) FROM oracle_price_triggers
		WHERE cluster = $1 AND status = 'armed'
	`, cluster).Scan(&n)
	if err != nil {
		return 0, fmt.Errorf("count armed: %w", err)
	}
	return n, nil
}

// ClaimByID atomically transitions a specific armed trigger to 'firing'. Returns
// true only if THIS call won the claim — the status guard means concurrent
// workers (or a re-scan within the same tick) never double-fire. Records the
// observed price for traceability.
func (s *Store) ClaimByID(ctx context.Context, id uuid.UUID, observedPrice1e8 int64) (bool, error) {
	tag, err := s.pool.Exec(ctx, `
		UPDATE oracle_price_triggers
		SET status = 'firing', last_check_at = now(), last_price_1e8 = $2
		WHERE id = $1 AND status = 'armed'
	`, id, observedPrice1e8)
	if err != nil {
		return false, fmt.Errorf("claim price trigger: %w", err)
	}
	return tag.RowsAffected() == 1, nil
}

// MarkFired records a successful fire and the landed tx signature.
func (s *Store) MarkFired(ctx context.Context, id uuid.UUID, txSignature string) error {
	tag, err := s.pool.Exec(ctx, `
		UPDATE oracle_price_triggers
		SET status = 'fired', fired_at = now(), tx_signature = $2
		WHERE id = $1 AND status = 'firing'
	`, id, txSignature)
	if err != nil {
		return fmt.Errorf("mark fired: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// MarkFailed bumps failure_count and records the (sanitised) error. Below
// MaxRetryCount the trigger returns to 'armed' to retry next tick; at the
// threshold it becomes terminal 'failed'.
func (s *Store) MarkFailed(ctx context.Context, id uuid.UUID, reason string) error {
	tag, err := s.pool.Exec(ctx, `
		UPDATE oracle_price_triggers
		SET status = CASE
		        WHEN failure_count + 1 >= $3 THEN 'failed'::oracle_price_trigger_status
		        ELSE 'armed'::oracle_price_trigger_status
		    END,
		    failure_count = failure_count + 1,
		    last_error = $2
		WHERE id = $1 AND status = 'firing'
	`, id, sanitize(reason), MaxRetryCount)
	if err != nil {
		return fmt.Errorf("mark failed: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// RecordCheck stores the latest observed price + check time for armed triggers
// the worker evaluated but did not fire (not yet in band). Pure observability;
// never changes status.
func (s *Store) RecordCheck(ctx context.Context, id uuid.UUID, price1e8 int64) error {
	_, err := s.pool.Exec(ctx, `
		UPDATE oracle_price_triggers SET last_check_at = now(), last_price_1e8 = $2
		WHERE id = $1 AND status = 'armed'
	`, id, price1e8)
	if err != nil {
		return fmt.Errorf("record check: %w", err)
	}
	return nil
}

// ReapStuckFiring rescues triggers stuck in 'firing' (the worker crashed
// between ClaimByID and MarkFired/MarkFailed) by moving them to terminal
// 'failed'. It deliberately does NOT re-arm them: a crash may have happened
// AFTER the request_signature tx was already sent, so re-arming could
// double-sign. Surfacing as 'failed' (observable, no retry) is the safe choice.
// `olderThan` should be well past a normal fire (e.g. now-5m). Returns the
// reaped ids.
func (s *Store) ReapStuckFiring(ctx context.Context, olderThan time.Time) ([]uuid.UUID, error) {
	rows, err := s.pool.Query(ctx, `
		UPDATE oracle_price_triggers
		SET status = 'failed',
		    last_error = 'stuck in firing (worker interrupted); not retried to avoid double-sign'
		WHERE status = 'firing' AND last_check_at < $1
		RETURNING id
	`, olderThan)
	if err != nil {
		return nil, fmt.Errorf("reap stuck firing: %w", err)
	}
	defer rows.Close()
	var ids []uuid.UUID
	for rows.Next() {
		var id uuid.UUID
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

// ExpireOverdue marks armed triggers past expires_at as expired and returns
// their ids so callers can fan out webhooks.
func (s *Store) ExpireOverdue(ctx context.Context, now time.Time) ([]uuid.UUID, error) {
	rows, err := s.pool.Query(ctx, `
		UPDATE oracle_price_triggers SET status = 'expired'
		WHERE status = 'armed' AND expires_at <= $1
		RETURNING id
	`, now)
	if err != nil {
		return nil, fmt.Errorf("expire overdue: %w", err)
	}
	defer rows.Close()
	var ids []uuid.UUID
	for rows.Next() {
		var id uuid.UUID
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

// sanitize trims and caps an error before persisting to the tenant-readable row.
func sanitize(s string) string {
	if len(s) > 500 {
		s = s[:500]
	}
	return s
}
