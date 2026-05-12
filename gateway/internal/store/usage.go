package store

import (
	"context"
	"fmt"
	"time"
)

// GetUsageReport aggregates consumption events for a single user over a
// time window. Returns three views in a single call (totals + daily +
// per-route top list) so the dashboard renders in one round-trip.
//
// The window is half-open: events with occurred_at >= since AND < until.
// `routeLimit` is the cap on TopRoutes; pass <=0 for the default of 10.
//
// Daily buckets come from date_trunc('day', occurred_at) at the database's
// timezone — the store is configured for UTC, so days align with UTC.
func (s *pgStore) GetUsageReport(ctx context.Context, userID string, since, until time.Time, routeLimit int) (*UsageReport, error) {
	if userID == "" {
		return nil, ErrNotFound
	}
	if !since.Before(until) {
		return nil, errInvalid("since must be before until")
	}
	if routeLimit <= 0 {
		routeLimit = 10
	}
	if routeLimit > 100 {
		routeLimit = 100
	}

	report := &UsageReport{
		Since:     since.UTC(),
		Until:     until.UTC(),
		Daily:     []UsageDailyBucket{},
		TopRoutes: []UsageRouteBucket{},
	}

	// 1. Totals — single query
	if err := s.pool.QueryRow(ctx, `
        SELECT COALESCE(SUM(cost_tokens), 0)::bigint,
               COALESCE(COUNT(*), 0)::bigint
        FROM usage_events
        WHERE user_id = $1
          AND occurred_at >= $2
          AND occurred_at <  $3`,
		userID, report.Since, report.Until).
		Scan(&report.Tokens, &report.Calls); err != nil {
		return nil, fmt.Errorf("usage totals: %w", err)
	}

	// 2. Daily buckets
	dailyRows, err := s.pool.Query(ctx, `
        SELECT date_trunc('day', occurred_at)::timestamptz AS day,
               SUM(cost_tokens)::bigint                    AS tokens,
               COUNT(*)::bigint                            AS calls
        FROM usage_events
        WHERE user_id = $1
          AND occurred_at >= $2
          AND occurred_at <  $3
        GROUP BY day
        ORDER BY day ASC`,
		userID, report.Since, report.Until)
	if err != nil {
		return nil, fmt.Errorf("usage daily: %w", err)
	}
	defer dailyRows.Close()
	for dailyRows.Next() {
		var b UsageDailyBucket
		if err := dailyRows.Scan(&b.Date, &b.Tokens, &b.Calls); err != nil {
			return nil, err
		}
		report.Daily = append(report.Daily, b)
	}
	if err := dailyRows.Err(); err != nil {
		return nil, err
	}

	// 3. Top routes (by tokens) — capped at routeLimit
	routeRows, err := s.pool.Query(ctx, `
        SELECT route_key,
               SUM(cost_tokens)::bigint AS tokens,
               COUNT(*)::bigint         AS calls
        FROM usage_events
        WHERE user_id = $1
          AND occurred_at >= $2
          AND occurred_at <  $3
        GROUP BY route_key
        ORDER BY tokens DESC, calls DESC
        LIMIT $4`,
		userID, report.Since, report.Until, routeLimit)
	if err != nil {
		return nil, fmt.Errorf("usage top routes: %w", err)
	}
	defer routeRows.Close()
	for routeRows.Next() {
		var rb UsageRouteBucket
		if err := routeRows.Scan(&rb.RouteKey, &rb.Tokens, &rb.Calls); err != nil {
			return nil, err
		}
		report.TopRoutes = append(report.TopRoutes, rb)
	}
	if err := routeRows.Err(); err != nil {
		return nil, err
	}

	return report, nil
}

func (s *pgStore) InsertUsageEvent(ctx context.Context, e UsageEvent) error {
	_, err := s.pool.Exec(ctx, `
        INSERT INTO usage_events
            (user_id, api_key_id, subscription_id, route_key, cost_tokens,
             status_code, latency_ms, request_id, occurred_at)
        VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
		e.UserID, e.APIKeyID, e.SubscriptionID, e.RouteKey, e.CostTokens,
		e.StatusCode, e.LatencyMs, e.RequestID, e.OccurredAt)
	return err
}
