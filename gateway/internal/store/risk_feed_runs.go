package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// GetFeedRunState returns the ingestion state for a feed URL.
// Returns nil if not found (not an error).
func (s *pgStore) GetFeedRunState(ctx context.Context, feedURL string) (*RiskFeedRunState, error) {
	if err := validateInput(feedURL, "feedUrl"); err != nil {
		return nil, err
	}

	q := `
		SELECT feed_url, last_success_at, last_error_at, last_error_msg, entries_upserted, content_hash, updated_at
		FROM risk_feed_runs
		WHERE feed_url = $1
		LIMIT 1
	`

	var state RiskFeedRunState
	row := s.pool.QueryRow(ctx, q, feedURL)
	err := row.Scan(&state.FeedURL, &state.LastSuccessAt, &state.LastErrorAt, &state.LastErrorMsg,
		&state.EntriesUpserted, &state.ContentHash, &state.UpdatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, mapErr(err)
	}

	return &state, nil
}

// UpsertFeedRunState updates the ingestion state for a feed (idempotent).
func (s *pgStore) UpsertFeedRunState(ctx context.Context, state *RiskFeedRunState) error {
	if err := validateInput(state.FeedURL, "feedUrl"); err != nil {
		return err
	}

	// M2: Use COALESCE to avoid zeroing baseline entry count on error.
	// Only update entries_upserted on success (when state.EntriesUpserted > 0);
	// preserve old value on error.
	q := `
		INSERT INTO risk_feed_runs
			(feed_url, last_success_at, last_error_at, last_error_msg, entries_upserted, content_hash, updated_at)
		VALUES
			($1, $2, $3, NULLIF($4, ''), $5, NULLIF($6, ''), now())
		ON CONFLICT (feed_url) DO UPDATE SET
			last_success_at = COALESCE(EXCLUDED.last_success_at, risk_feed_runs.last_success_at),
			last_error_at = EXCLUDED.last_error_at,
			last_error_msg = COALESCE(NULLIF(EXCLUDED.last_error_msg, ''), risk_feed_runs.last_error_msg),
			entries_upserted = CASE
				WHEN EXCLUDED.entries_upserted > 0 THEN EXCLUDED.entries_upserted
				ELSE risk_feed_runs.entries_upserted
			END,
			content_hash = CASE
				WHEN EXCLUDED.entries_upserted > 0 THEN COALESCE(EXCLUDED.content_hash, risk_feed_runs.content_hash)
				ELSE risk_feed_runs.content_hash
			END,
			updated_at = now()
	`

	_, err := s.pool.Exec(ctx, q,
		state.FeedURL, state.LastSuccessAt, state.LastErrorAt, state.LastErrorMsg,
		state.EntriesUpserted, state.ContentHash,
	)
	return mapErr(err)
}

// ClaimDueFeedRuns claims feed runs due for execution using SELECT...FOR UPDATE SKIP LOCKED.
// Returns up to limit feeds that either:
//   - Have never been run (last_success_at IS NULL), or
//   - Are overdue (last_success_at < now - interval)
//
// Each claimed feed updates updated_at to prevent concurrent claims (SKIP LOCKED).
func (s *pgStore) ClaimDueFeedRuns(ctx context.Context, now time.Time, interval time.Duration, limit int) ([]*FeedRunLease, error) {
	if limit <= 0 {
		return nil, nil
	}

	leaseExp := now.Add(interval)
	leaseToken := generateLeaseID()

	// Select feeds due for execution: never run OR last_success_at is older than interval.
	// FOR UPDATE SKIP LOCKED ensures no two replicas claim the same feed.
	// We use interval (typically 2x tick) as the due threshold.
	q := `
		WITH due AS (
			SELECT feed_url
			FROM risk_feed_runs
			WHERE last_success_at IS NULL
			   OR last_success_at < now() - $1::interval
			ORDER BY COALESCE(last_success_at, updated_at) ASC
			LIMIT $2
			FOR UPDATE SKIP LOCKED
		)
		UPDATE risk_feed_runs
		SET updated_at = now()
		WHERE feed_url IN (SELECT feed_url FROM due)
		RETURNING feed_url
	`

	rows, err := s.pool.Query(ctx, q, formatInterval(interval), limit)
	if err != nil {
		return nil, mapErr(err)
	}
	defer rows.Close()

	var leases []*FeedRunLease
	for rows.Next() {
		var feedURL string
		if err := rows.Scan(&feedURL); err != nil {
			return nil, mapErr(err)
		}
		leases = append(leases, &FeedRunLease{
			FeedURL:  feedURL,
			LeaseID:  leaseToken,
			LeaseExp: leaseExp,
		})
	}
	if err := rows.Err(); err != nil {
		return nil, mapErr(err)
	}

	return leases, nil
}

// formatInterval converts Go duration to PostgreSQL interval format.
func formatInterval(d time.Duration) string {
	secs := int64(d.Seconds())
	return fmt.Sprintf("%d seconds", secs)
}

// SeedFeedRuns ensures all configured feeds exist in the database.
// Called at boot to guarantee ClaimDueFeedRuns has feeds to work with.
func (s *pgStore) SeedFeedRuns(ctx context.Context, feedURLs []string) error {
	if len(feedURLs) == 0 {
		return nil
	}

	// Upsert each feed: INSERT ... ON CONFLICT (feed_url) DO NOTHING
	// This ensures feeds exist without overwriting existing state.
	q := `
		INSERT INTO risk_feed_runs (feed_url, updated_at)
		VALUES ($1, now())
		ON CONFLICT (feed_url) DO NOTHING
	`

	for _, feedURL := range feedURLs {
		if err := validateInput(feedURL, "feedUrl"); err != nil {
			return err
		}
		_, err := s.pool.Exec(ctx, q, feedURL)
		if err != nil {
			return mapErr(err)
		}
	}
	return nil
}

// generateLeaseID generates a unique lease token for deduplication across replicas.
func generateLeaseID() string {
	return uuid.NewString()
}
