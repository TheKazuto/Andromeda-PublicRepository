package store

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
)

// GetDestHistoryEntry returns the history record for a dWalletâ†’destination pair.
// Returns (nil, nil) if not found â€” absence is the common case and not an error.
func (s *pgStore) GetDestHistoryEntry(ctx context.Context, dwalletAddress, destination string) (*DestHistoryEntry, error) {
	if err := validateInput(dwalletAddress, "dwalletAddress"); err != nil {
		return nil, err
	}
	if err := validateInput(destination, "destination"); err != nil {
		return nil, err
	}

	var err error
	dwalletAddress, err = NormalizeAddress(dwalletAddress)
	if err != nil {
		return nil, err
	}
	destination, err = NormalizeAddress(destination)
	if err != nil {
		return nil, err
	}

	q := `
		SELECT id, dwallet_address, destination, first_used_at, count
		FROM dest_history
		WHERE dwallet_address = $1 AND destination = $2
		LIMIT 1
	`

	var entry DestHistoryEntry
	row := s.pool.QueryRow(ctx, q, dwalletAddress, destination)
	err = row.Scan(&entry.ID, &entry.DwalletAddress, &entry.Destination, &entry.FirstUsedAt, &entry.Count)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, mapErr(err)
	}

	return &entry, nil
}

// RecordDestinationUsage adds or increments the history entry for a destination used by a dWallet.
// Idempotent: calling multiple times for the same pair increments the count.
func (s *pgStore) RecordDestinationUsage(ctx context.Context, dwalletAddress, destination string) error {
	if err := validateInput(dwalletAddress, "dwalletAddress"); err != nil {
		return err
	}
	if err := validateInput(destination, "destination"); err != nil {
		return err
	}

	var err error
	dwalletAddress, err = NormalizeAddress(dwalletAddress)
	if err != nil {
		return err
	}
	destination, err = NormalizeAddress(destination)
	if err != nil {
		return err
	}

	q := `
		INSERT INTO dest_history
			(dwallet_address, destination, first_used_at, count)
		VALUES
			($1, $2, now(), 1)
		ON CONFLICT (dwallet_address, destination) DO UPDATE SET
			count = dest_history.count + 1
	`

	_, err = s.pool.Exec(ctx, q, dwalletAddress, destination)
	return mapErr(err)
}

// ListDestHistoryByDwallet returns all destination history entries for a dWallet.
// Accepts optional limit (max 500 for DoS protection); returns up to that many entries.
// Empty result is not an error.
func (s *pgStore) ListDestHistoryByDwallet(ctx context.Context, dwalletAddress string, limit int) ([]*DestHistoryEntry, error) {
	if err := validateInput(dwalletAddress, "dwalletAddress"); err != nil {
		return nil, err
	}

	var err error
	dwalletAddress, err = NormalizeAddress(dwalletAddress)
	if err != nil {
		return nil, err
	}
	if limit <= 0 || limit > 500 {
		limit = 500
	}

	q := `
		SELECT id, dwallet_address, destination, first_used_at, count
		FROM dest_history
		WHERE dwallet_address = $1
		ORDER BY first_used_at DESC
		LIMIT $2
	`

	rows, err := s.pool.Query(ctx, q, dwalletAddress, limit)
	if err != nil {
		return nil, mapErr(err)
	}
	defer rows.Close()

	var entries []*DestHistoryEntry
	for rows.Next() {
		var entry DestHistoryEntry
		if err = rows.Scan(&entry.ID, &entry.DwalletAddress, &entry.Destination, &entry.FirstUsedAt, &entry.Count); err != nil {
			return nil, mapErr(err)
		}
		entries = append(entries, &entry)
	}

	return entries, mapErr(rows.Err())
}
