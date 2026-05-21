package oraclerelay

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ErrNotFound is returned when a feed row is missing.
var ErrNotFound = errors.New("oracle feed not found")

// Store persists oracle feeds + refresh log to Postgres.
type Store struct {
	pool *pgxpool.Pool
}

// NewStore returns a Store backed by the supplied pool.
func NewStore(pool *pgxpool.Pool) *Store { return &Store{pool: pool} }

const feedColumns = `id, label, cluster, pyth_feed_id_hex, feed_cache_pda, pyth_account,
	pyth_account_kind, refresh_interval_s, paused, last_publish_time, last_tx_signature, last_error`

func scanFeed(row pgx.Row) (*Feed, error) {
	var f Feed
	err := row.Scan(&f.ID, &f.Label, &f.Cluster, &f.PythFeedIDHex, &f.FeedCachePDA,
		&f.PythAccount, &f.PythAccountKind, &f.RefreshInterval, &f.Paused,
		&f.LastPublishTime, &f.LastTxSignature, &f.LastError)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return &f, nil
}

// Upsert inserts a feed or updates the mutable columns when (cluster,
// pyth_feed_id_hex) already exists. Returns the row id.
func (s *Store) Upsert(ctx context.Context, f Feed) (string, error) {
	var id string
	err := s.pool.QueryRow(ctx, `
		INSERT INTO oracle_feeds
			(label, cluster, pyth_feed_id_hex, feed_cache_pda, pyth_account, pyth_account_kind, refresh_interval_s)
		VALUES ($1,$2,$3,$4,$5,$6,$7)
		ON CONFLICT (cluster, pyth_feed_id_hex) DO UPDATE SET
			label = EXCLUDED.label,
			feed_cache_pda = EXCLUDED.feed_cache_pda,
			pyth_account = EXCLUDED.pyth_account,
			pyth_account_kind = EXCLUDED.pyth_account_kind,
			refresh_interval_s = EXCLUDED.refresh_interval_s,
			updated_at = now()
		RETURNING id`,
		f.Label, f.Cluster, f.PythFeedIDHex, f.FeedCachePDA, f.PythAccount,
		f.PythAccountKind, f.RefreshInterval).Scan(&id)
	if err != nil {
		return "", fmt.Errorf("upsert oracle feed: %w", err)
	}
	return id, nil
}

// ListActive returns non-paused feeds for the cluster.
func (s *Store) ListActive(ctx context.Context, cluster string) ([]Feed, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+feedColumns+`
		FROM oracle_feeds WHERE cluster = $1 AND paused = FALSE
		ORDER BY created_at ASC`, cluster)
	if err != nil {
		return nil, fmt.Errorf("list active feeds: %w", err)
	}
	defer rows.Close()
	var out []Feed
	for rows.Next() {
		f, err := scanFeed(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *f)
	}
	return out, rows.Err()
}

// List returns all feeds for the cluster (admin view).
func (s *Store) List(ctx context.Context, cluster string) ([]Feed, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+feedColumns+`
		FROM oracle_feeds WHERE cluster = $1 ORDER BY created_at ASC`, cluster)
	if err != nil {
		return nil, fmt.Errorf("list feeds: %w", err)
	}
	defer rows.Close()
	var out []Feed
	for rows.Next() {
		f, err := scanFeed(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *f)
	}
	return out, rows.Err()
}

// GetByID returns one feed.
func (s *Store) GetByID(ctx context.Context, id string) (*Feed, error) {
	return scanFeed(s.pool.QueryRow(ctx, `SELECT `+feedColumns+`
		FROM oracle_feeds WHERE id = $1`, id))
}

// SetPaused flips the paused flag.
func (s *Store) SetPaused(ctx context.Context, id string, paused bool) error {
	tag, err := s.pool.Exec(ctx, `UPDATE oracle_feeds SET paused = $2, updated_at = now() WHERE id = $1`, id, paused)
	if err != nil {
		return fmt.Errorf("set paused: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// Delete removes a feed row (the on-chain FeedCache PDA is left intact).
func (s *Store) Delete(ctx context.Context, id string) error {
	tag, err := s.pool.Exec(ctx, `DELETE FROM oracle_feeds WHERE id = $1`, id)
	if err != nil {
		return fmt.Errorf("delete feed: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// RecordRefresh writes the feed's latest state and appends a log row in one tx.
// On success it also advances last_publish_time so the next tick can skip
// unchanged feeds.
func (s *Store) RecordRefresh(ctx context.Context, feedID string, o RefreshOutcome) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if o.Result == resultSuccess {
		if _, err := tx.Exec(ctx, `UPDATE oracle_feeds SET
				last_publish_time = COALESCE($2, last_publish_time),
				last_tx_signature = $3,
				last_error = NULL,
				updated_at = now()
			WHERE id = $1`, feedID, o.PublishTime, nullString(o.TxSignature)); err != nil {
			return fmt.Errorf("update feed (success): %w", err)
		}
	} else if o.Result == resultError {
		if _, err := tx.Exec(ctx, `UPDATE oracle_feeds SET last_error = $2, updated_at = now()
			WHERE id = $1`, feedID, nullString(o.Err)); err != nil {
			return fmt.Errorf("update feed (error): %w", err)
		}
	}

	if _, err := tx.Exec(ctx, `INSERT INTO oracle_feed_refresh_log
			(feed_id, tx_signature, pyth_publish_time, price_q64, conf_q64, result, error)
		VALUES ($1,$2,$3,$4,$5,$6,$7)`,
		feedID, nullString(o.TxSignature), o.PublishTime, o.PriceCanon, o.ConfCanon,
		o.Result, nullString(o.Err)); err != nil {
		return fmt.Errorf("insert refresh log: %w", err)
	}

	return tx.Commit(ctx)
}

func nullString(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

var _ = time.Now
