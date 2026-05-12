package store

import (
	"context"
	"embed"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

//go:embed migrations/*.sql
var migrationFS embed.FS

type pgStore struct {
	pool *pgxpool.Pool
}

// NewPostgres opens a pool, pings, and runs migrations.
func NewPostgres(ctx context.Context, dsn string) (Store, error) {
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("parse dsn: %w", err)
	}
	cfg.MaxConns = 20
	cfg.MinConns = 2
	cfg.MaxConnLifetime = 30 * time.Minute
	cfg.MaxConnIdleTime = 5 * time.Minute

	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("open pool: %w", err)
	}
	pingCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := pool.Ping(pingCtx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("ping db: %w", err)
	}

	s := &pgStore{pool: pool}
	if err := s.migrate(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("migrate: %w", err)
	}
	return s, nil
}

func (s *pgStore) Close() { s.pool.Close() }

func (s *pgStore) Pool() *pgxpool.Pool { return s.pool }

// ---------- migrations ----------

func (s *pgStore) migrate(ctx context.Context) error {
	if _, err := s.pool.Exec(ctx, `
        CREATE TABLE IF NOT EXISTS schema_migrations (
            version    int PRIMARY KEY,
            applied_at timestamptz NOT NULL DEFAULT now()
        )`); err != nil {
		return err
	}

	entries, err := migrationFS.ReadDir("migrations")
	if err != nil {
		return err
	}
	files := make([]string, 0, len(entries))
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".sql") {
			files = append(files, e.Name())
		}
	}
	sort.Strings(files)

	applied := map[int]bool{}
	rows, err := s.pool.Query(ctx, `SELECT version FROM schema_migrations`)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var v int
		if err := rows.Scan(&v); err != nil {
			return err
		}
		applied[v] = true
	}

	for _, name := range files {
		var version int
		if _, err := fmt.Sscanf(name, "%03d_", &version); err != nil {
			return fmt.Errorf("bad migration name %q: %w", name, err)
		}
		if applied[version] {
			continue
		}
		body, err := migrationFS.ReadFile("migrations/" + name)
		if err != nil {
			return err
		}
		tx, err := s.pool.Begin(ctx)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, string(body)); err != nil {
			_ = tx.Rollback(ctx)
			return fmt.Errorf("apply %s: %w", name, err)
		}
		if _, err := tx.Exec(ctx,
			`INSERT INTO schema_migrations(version) VALUES ($1)`, version); err != nil {
			_ = tx.Rollback(ctx)
			return err
		}
		if err := tx.Commit(ctx); err != nil {
			return err
		}
	}
	return nil
}

// ---------- helpers ----------

func nextPeriodEnd(start time.Time) time.Time {
	return start.AddDate(0, 1, 0)
}

func annualPeriodEnd(start time.Time) time.Time {
	return start.AddDate(1, 0, 0)
}

func mapErr(err error) error {
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrNotFound
	}
	return err
}

// subscriptionColumns is the canonical SELECT list for subscriptions
// joined with plans.code. Order MUST match scanSubscription below.
const subscriptionColumns = `
    sub.id, sub.user_id, sub.plan_id, p.code, sub.status, sub.billing_cycle,
    sub.current_period_start, sub.current_period_end,
    sub.tokens_used, sub.tokens_limit,
    sub.overage_enabled, sub.overage_card_present,
    sub.overage_used_tokens, sub.overage_cap_tokens,
    sub.overage_reported_tokens, sub.overage_last_reported_at,
    sub.rate_limit_rps, sub.rate_limit_burst,
    sub.read_rps, sub.read_burst, sub.tx_rps, sub.tx_burst,
    COALESCE(sub.stripe_customer_id, ''), COALESCE(sub.stripe_subscription_id, ''),
    COALESCE(sub.stripe_overage_item_id, ''),
    sub.created_at, sub.updated_at`

func scanSubscription(row scanner, sub *Subscription) error {
	return row.Scan(
		&sub.ID, &sub.UserID, &sub.PlanID, &sub.PlanCode, &sub.Status, &sub.BillingCycle,
		&sub.CurrentPeriodStart, &sub.CurrentPeriodEnd,
		&sub.TokensUsed, &sub.TokensLimit,
		&sub.OverageEnabled, &sub.OverageCardPresent,
		&sub.OverageUsedTokens, &sub.OverageCapTokens,
		&sub.OverageReportedTokens, &sub.OverageLastReportedAt,
		&sub.RateLimitRPS, &sub.RateLimitBurst,
		&sub.ReadRPS, &sub.ReadBurst, &sub.TxRPS, &sub.TxBurst,
		&sub.StripeCustomerID, &sub.StripeSubscriptionID,
		&sub.StripeOverageItemID,
		&sub.CreatedAt, &sub.UpdatedAt,
	)
}

// ---------- generic helpers ----------

type scanner interface {
	Scan(dst ...any) error
}

func nullableTime(t time.Time) any {
	if t.IsZero() {
		return nil
	}
	return t
}

func derefStr(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}
func derefBool(p *bool) bool {
	if p == nil {
		return false
	}
	return *p
}
func derefInt(p *int) int {
	if p == nil {
		return 0
	}
	return *p
}
func derefInt64(p *int64) int64 {
	if p == nil {
		return 0
	}
	return *p
}
func derefTime(p *time.Time) time.Time {
	if p == nil {
		return time.Time{}
	}
	return *p
}
