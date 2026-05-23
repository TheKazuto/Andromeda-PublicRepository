package store

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
)

// GetBlocklistEntry checks if a destination is in the global blocklist.
// Returns (nil, nil) if not found — absence is the common case and not an error.
func (s *pgStore) GetBlocklistEntry(ctx context.Context, destination string) (*RiskBlocklistEntry, error) {
	if err := validateInput(destination, "destination"); err != nil {
		return nil, err
	}

	var err error
	destination, err = NormalizeAddress(destination)
	if err != nil {
		return nil, err
	}

	q := `
		SELECT destination, source, category, license, fetched_at, content_hash, created_at, updated_at
		FROM risk_blocklist
		WHERE destination = $1
		LIMIT 1
	`

	var entry RiskBlocklistEntry
	row := s.pool.QueryRow(ctx, q, destination)
	err = row.Scan(&entry.Destination, &entry.Source, &entry.Category, &entry.License,
		&entry.FetchedAt, &entry.ContentHash, &entry.CreatedAt, &entry.UpdatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, mapErr(err)
	}

	return &entry, nil
}

// UpsertBlocklistEntry adds or updates a blocklist entry (idempotent on destination).
func (s *pgStore) UpsertBlocklistEntry(ctx context.Context, entry *RiskBlocklistEntry) error {
	if err := validateInput(entry.Destination, "destination"); err != nil {
		return err
	}
	if err := validateInput(entry.Source, "source"); err != nil {
		return err
	}
	if err := validateInput(entry.Category, "category"); err != nil {
		return err
	}

	var err error
	entry.Destination, err = NormalizeAddress(entry.Destination)
	if err != nil {
		return err
	}

	q := `
		INSERT INTO risk_blocklist
			(destination, source, category, license, fetched_at, content_hash, created_at, updated_at)
		VALUES
			($1, $2, $3, NULLIF($4, ''), $5, NULLIF($6, ''), COALESCE($7, now()), COALESCE($8, now()))
		ON CONFLICT (destination) DO UPDATE SET
			source = EXCLUDED.source,
			category = EXCLUDED.category,
			license = COALESCE(EXCLUDED.license, risk_blocklist.license),
			fetched_at = EXCLUDED.fetched_at,
			content_hash = COALESCE(EXCLUDED.content_hash, risk_blocklist.content_hash),
			updated_at = now()
	`

	_, err = s.pool.Exec(ctx, q,
		entry.Destination, entry.Source, entry.Category, entry.License,
		entry.FetchedAt, entry.ContentHash, nullableTime(entry.CreatedAt), nullableTime(entry.UpdatedAt),
	)
	return mapErr(err)
}

// DeleteBlocklistEntry removes an entry from the blocklist.
func (s *pgStore) DeleteBlocklistEntry(ctx context.Context, destination string) error {
	if err := validateInput(destination, "destination"); err != nil {
		return err
	}

	var err error
	destination, err = NormalizeAddress(destination)
	if err != nil {
		return err
	}

	_, err = s.pool.Exec(ctx,
		`DELETE FROM risk_blocklist WHERE destination = $1`,
		destination,
	)
	return mapErr(err)
}

// ListBlocklistBySource returns all blocklist entries from a specific source.
// Accepts optional limit (max 500 for DoS protection); returns up to that many entries.
// Empty result is not an error.
func (s *pgStore) ListBlocklistBySource(ctx context.Context, source string, limit int) ([]*RiskBlocklistEntry, error) {
	if err := validateInput(source, "source"); err != nil {
		return nil, err
	}
	if limit <= 0 || limit > 500 {
		limit = 500
	}

	q := `
		SELECT destination, source, category, license, fetched_at, content_hash, created_at, updated_at
		FROM risk_blocklist
		WHERE source = $1
		ORDER BY created_at DESC
		LIMIT $2
	`

	rows, err := s.pool.Query(ctx, q, source, limit)
	if err != nil {
		return nil, mapErr(err)
	}
	defer rows.Close()

	var entries []*RiskBlocklistEntry
	for rows.Next() {
		var entry RiskBlocklistEntry
		if err = rows.Scan(&entry.Destination, &entry.Source, &entry.Category, &entry.License,
			&entry.FetchedAt, &entry.ContentHash, &entry.CreatedAt, &entry.UpdatedAt); err != nil {
			return nil, mapErr(err)
		}
		entries = append(entries, &entry)
	}

	return entries, mapErr(rows.Err())
}

// DeleteBlocklistBySource removes all entries from a specific source (for feed refresh).
func (s *pgStore) DeleteBlocklistBySource(ctx context.Context, source string) error {
	if err := validateInput(source, "source"); err != nil {
		return err
	}

	_, err := s.pool.Exec(ctx,
		`DELETE FROM risk_blocklist WHERE source = $1`,
		source,
	)
	return mapErr(err)
}
