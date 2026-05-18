package store

import (
	"context"
	"embed"
	"errors"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// envInt reads an integer env var with a default. A non-empty but
// malformed value is treated as the default so a typo doesn't take
// the gateway down on boot.
func envInt(key string, fallback int) int {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return fallback
}

//go:embed migrations/*.sql
var migrationFS embed.FS

type pgStore struct {
	pool *pgxpool.Pool
}

// NewPostgres opens a pool, pings, and runs migrations.
//
// Migrations run on a dedicated direct connection (not from the pool)
// so the transactional advisory lock survives across statements even
// when DATABASE_URL points at PgBouncer in transaction-pooling mode.
// Set MIGRATION_DATABASE_URL to a direct Postgres DSN to bypass the
// pooler explicitly; otherwise we use the same DSN as the pool.
//
// Pool sizing knobs (env, all optional):
//
//	PG_MAX_CONNS              — pool ceiling (default 20)
//	PG_MIN_CONNS              — warm idle pool (default 2)
//	PG_MAX_CONN_LIFETIME_SEC  — max age of any conn before rotation (default 1800)
//	PG_MAX_CONN_IDLE_SEC      — kill idle conns after N seconds (default 300)
//	PG_HEALTH_CHECK_SEC       — pgxpool health-check period (default 30)
//	PG_STATEMENT_TIMEOUT_MS   — Postgres `statement_timeout` (default 30000)
//	PG_IDLE_IN_TX_TIMEOUT_MS  — `idle_in_transaction_session_timeout` (default 60000)
//	PG_STATEMENT_CACHE_MODE   — pgx prepared-statement cache mode (default 'prepare'; set
//	                            to 'describe' under PgBouncer transaction-pool mode)
func NewPostgres(ctx context.Context, dsn string) (Store, error) {
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("parse dsn: %w", err)
	}
	cfg.MaxConns = int32(envInt("PG_MAX_CONNS", 20))
	cfg.MinConns = int32(envInt("PG_MIN_CONNS", 2))
	cfg.MaxConnLifetime = time.Duration(envInt("PG_MAX_CONN_LIFETIME_SEC", 1800)) * time.Second
	cfg.MaxConnIdleTime = time.Duration(envInt("PG_MAX_CONN_IDLE_SEC", 300)) * time.Second
	cfg.HealthCheckPeriod = time.Duration(envInt("PG_HEALTH_CHECK_SEC", 30)) * time.Second

	// PgBouncer transaction-pool mode does not support named prepared
	// statements across statements within a session. Operators set
	// PG_STATEMENT_CACHE_MODE=describe to switch pgx into a compatible
	// mode (server-side describe each call, no client-side cache).
	if mode := strings.TrimSpace(os.Getenv("PG_STATEMENT_CACHE_MODE")); mode != "" {
		switch mode {
		case "describe":
			cfg.ConnConfig.DefaultQueryExecMode = pgx.QueryExecModeDescribeExec
		case "exec":
			cfg.ConnConfig.DefaultQueryExecMode = pgx.QueryExecModeExec
		case "simple_protocol":
			cfg.ConnConfig.DefaultQueryExecMode = pgx.QueryExecModeSimpleProtocol
		case "cache_describe":
			cfg.ConnConfig.DefaultQueryExecMode = pgx.QueryExecModeCacheDescribe
		case "prepare", "cache_statement":
			cfg.ConnConfig.DefaultQueryExecMode = pgx.QueryExecModeCacheStatement
		}
	}

	// Apply Postgres session-level timeouts on every new connection so
	// runaway queries (statement_timeout) and abandoned transactions
	// (idle_in_transaction_session_timeout) free their conns instead of
	// holding the pool. Skip when 0 to allow opt-out.
	stmtTimeoutMS := envInt("PG_STATEMENT_TIMEOUT_MS", 30_000)
	idleTxTimeoutMS := envInt("PG_IDLE_IN_TX_TIMEOUT_MS", 60_000)
	cfg.AfterConnect = func(ctx context.Context, conn *pgx.Conn) error {
		if stmtTimeoutMS > 0 {
			if _, err := conn.Exec(ctx, fmt.Sprintf("SET statement_timeout = %d", stmtTimeoutMS)); err != nil {
				return fmt.Errorf("set statement_timeout: %w", err)
			}
		}
		if idleTxTimeoutMS > 0 {
			if _, err := conn.Exec(ctx, fmt.Sprintf("SET idle_in_transaction_session_timeout = %d", idleTxTimeoutMS)); err != nil {
				return fmt.Errorf("set idle_in_transaction_session_timeout: %w", err)
			}
		}
		return nil
	}

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

	migrationDSN := dsn
	if override := strings.TrimSpace(os.Getenv("MIGRATION_DATABASE_URL")); override != "" {
		migrationDSN = override
	}
	if err := runMigrationsDirect(ctx, migrationDSN); err != nil {
		pool.Close()
		return nil, fmt.Errorf("migrate: %w", err)
	}
	return &pgStore{pool: pool}, nil
}

func (s *pgStore) Close() { s.pool.Close() }

func (s *pgStore) Pool() *pgxpool.Pool { return s.pool }

// ---------- migrations ----------

// migrationAdvisoryLockKey is the stable advisory-lock key reserved for
// the gateway's migration runner. Two replicas booting at the same time
// both try to claim this key inside a transaction; the loser blocks on
// pg_advisory_xact_lock until the winner commits and then sees the
// migrations as already applied. Generated once and kept constant.
const migrationAdvisoryLockKey int64 = 0x416e6472_6f4d6967 // 'AndrMig'

// runMigrationsDirect applies every embedded *.sql in lexicographic
// order, serialised across replicas by a transactional advisory lock.
// The whole apply loop runs inside a single transaction on a dedicated
// direct connection (`pgx.Connect`, NOT via the pool) — the advisory
// lock and the schema mutations share the same backend, required for
// transactional advisory locks to behave correctly under PgBouncer in
// transaction-pooling mode.
//
// Wrapping every migration in the outer transaction trades crash safety
// per-file for cross-replica serialisation. If any single migration
// fails we rollback the entire boot; the schema stays at the previous
// version and the operator can fix and rerun.
func runMigrationsDirect(ctx context.Context, dsn string) error {
	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		return fmt.Errorf("migrate: connect: %w", err)
	}
	defer conn.Close(ctx)

	tx, err := conn.Begin(ctx)
	if err != nil {
		return fmt.Errorf("migrate: begin tx: %w", err)
	}
	rollback := func() {
		if err := tx.Rollback(ctx); err != nil && !errors.Is(err, pgx.ErrTxClosed) {
			// best-effort log — the caller already has a richer error.
			_ = err
		}
	}

	// Block until we own the migration lock. Released on commit/rollback.
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, migrationAdvisoryLockKey); err != nil {
		rollback()
		return fmt.Errorf("migrate: acquire lock: %w", err)
	}

	if _, err := tx.Exec(ctx, `
        CREATE TABLE IF NOT EXISTS schema_migrations (
            version    int PRIMARY KEY,
            applied_at timestamptz NOT NULL DEFAULT now()
        )`); err != nil {
		rollback()
		return err
	}

	entries, err := migrationFS.ReadDir("migrations")
	if err != nil {
		rollback()
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
	rows, err := tx.Query(ctx, `SELECT version FROM schema_migrations`)
	if err != nil {
		rollback()
		return err
	}
	for rows.Next() {
		var v int
		if err := rows.Scan(&v); err != nil {
			rows.Close()
			rollback()
			return err
		}
		applied[v] = true
	}
	rows.Close()

	for _, name := range files {
		var version int
		if _, err := fmt.Sscanf(name, "%03d_", &version); err != nil {
			rollback()
			return fmt.Errorf("bad migration name %q: %w", name, err)
		}
		if applied[version] {
			continue
		}
		body, err := migrationFS.ReadFile("migrations/" + name)
		if err != nil {
			rollback()
			return err
		}
		if _, err := tx.Exec(ctx, string(body)); err != nil {
			rollback()
			return fmt.Errorf("apply %s: %w", name, err)
		}
		// ON CONFLICT DO NOTHING defends against a previous run that
		// committed the migration but failed to record it — replays
		// idempotently rather than crashing with a duplicate-key error.
		if _, err := tx.Exec(ctx,
			`INSERT INTO schema_migrations(version) VALUES ($1) ON CONFLICT DO NOTHING`, version); err != nil {
			rollback()
			return err
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("migrate: commit: %w", err)
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
