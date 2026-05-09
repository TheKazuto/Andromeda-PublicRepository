package store

import (
	"context"
	"embed"
	"encoding/json"
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

// planColumns is the canonical SELECT list for plans. Order MUST match
// scanPlan below.
const planColumns = `
    id, code, name,
    monthly_tokens, price_cents, annual_price_cents, overage_per_1k_cents,
    rate_limit_rps, rate_limit_burst,
    read_rps, read_burst, tx_rps, tx_burst,
    features, is_active, is_giftable, sort_order,
    created_at, updated_at`

func scanPlan(row scanner) (Plan, error) {
	var (
		p           Plan
		featuresRaw []byte
	)
	if err := row.Scan(&p.ID, &p.Code, &p.Name,
		&p.MonthlyTokens, &p.PriceCents, &p.AnnualPriceCents, &p.OveragePer1kCents,
		&p.RateLimitRPS, &p.RateLimitBurst,
		&p.ReadRPS, &p.ReadBurst, &p.TxRPS, &p.TxBurst,
		&featuresRaw, &p.IsActive, &p.IsGiftable, &p.SortOrder,
		&p.CreatedAt, &p.UpdatedAt); err != nil {
		return p, err
	}
	if len(featuresRaw) > 0 {
		_ = json.Unmarshal(featuresRaw, &p.Features)
	}
	if p.Features == nil {
		p.Features = map[string]any{}
	}
	return p, nil
}

// ---------- hot path ----------

func (s *pgStore) AuthenticateAPIKey(ctx context.Context, hashedKey string) (*AuthenticatedKey, error) {
	q := `
        SELECT
            u.id, u.email, u.name, u.created_at,
            k.id, k.user_id, k.name, k.prefix, k.scopes,
            COALESCE(k.ip_allowlist, '{}'::text[]),
            COALESCE(k.allowed_origins, '{}'::text[]),
            k.created_at, k.last_used_at, k.revoked_at,
            ` + subscriptionColumns + `
        FROM api_keys k
        JOIN users u ON u.id = k.user_id
        LEFT JOIN subscriptions sub
               ON sub.user_id = u.id AND sub.status = 'active'
        LEFT JOIN plans p ON p.id = sub.plan_id
        WHERE k.hashed_key = $1
        LIMIT 1`

	var (
		u    User
		k    APIKey
		sub  Subscription
		hasS bool
	)

	row := s.pool.QueryRow(ctx, q, hashedKey)
	// Scan into staging pointers so we can detect NULL on the subscription
	// side (LEFT JOIN may produce NULLs across the entire sub.* slice).
	var (
		subID, subUserID, planID, planCode, status, cycle    *string
		ps, pe, sCreatedAt, sUpdatedAt, overageLastReportedAt *time.Time
		used, limit, overageUsed, overageCap, overageReported *int64
		rps, burst, readRPS, readBurst, txRPS, txBurst       *int
		overageEnabled, overageCardPresent                   *bool
		stripeCustomerID, stripeSubscriptionID               *string
		stripeOverageItemID                                  *string
	)
	err := row.Scan(
		&u.ID, &u.Email, &u.Name, &u.CreatedAt,
		&k.ID, &k.UserID, &k.Name, &k.Prefix, &k.Scopes,
		&k.IPAllowlist,
		&k.AllowedOrigins,
		&k.CreatedAt, &k.LastUsedAt, &k.RevokedAt,
		&subID, &subUserID, &planID, &planCode, &status, &cycle,
		&ps, &pe,
		&used, &limit,
		&overageEnabled, &overageCardPresent,
		&overageUsed, &overageCap,
		&overageReported, &overageLastReportedAt,
		&rps, &burst,
		&readRPS, &readBurst, &txRPS, &txBurst,
		&stripeCustomerID, &stripeSubscriptionID,
		&stripeOverageItemID,
		&sCreatedAt, &sUpdatedAt,
	)
	if err != nil {
		return nil, mapErr(err)
	}
	if k.RevokedAt != nil {
		return nil, ErrKeyRevoked
	}

	if subID != nil {
		hasS = true
		sub.ID = derefStr(subID)
		sub.UserID = u.ID
		sub.PlanID = derefStr(planID)
		sub.PlanCode = derefStr(planCode)
		sub.Status = derefStr(status)
		sub.BillingCycle = derefStr(cycle)
		sub.CurrentPeriodStart = derefTime(ps)
		sub.CurrentPeriodEnd = derefTime(pe)
		sub.TokensUsed = derefInt64(used)
		sub.TokensLimit = derefInt64(limit)
		sub.OverageEnabled = derefBool(overageEnabled)
		sub.OverageCardPresent = derefBool(overageCardPresent)
		sub.OverageUsedTokens = derefInt64(overageUsed)
		sub.OverageCapTokens = derefInt64(overageCap)
		sub.OverageReportedTokens = derefInt64(overageReported)
		sub.OverageLastReportedAt = overageLastReportedAt
		sub.RateLimitRPS = derefInt(rps)
		sub.RateLimitBurst = derefInt(burst)
		sub.ReadRPS = derefInt(readRPS)
		sub.ReadBurst = derefInt(readBurst)
		sub.TxRPS = derefInt(txRPS)
		sub.TxBurst = derefInt(txBurst)
		sub.StripeCustomerID = derefStr(stripeCustomerID)
		sub.StripeSubscriptionID = derefStr(stripeSubscriptionID)
		sub.StripeOverageItemID = derefStr(stripeOverageItemID)
		sub.CreatedAt = derefTime(sCreatedAt)
		sub.UpdatedAt = derefTime(sUpdatedAt)
	}

	out := &AuthenticatedKey{User: &u, APIKey: &k}
	if hasS {
		out.Subscription = &sub
	}
	return out, nil
}

func (s *pgStore) TouchAPIKeyUsed(ctx context.Context, apiKeyID string) error {
	_, err := s.pool.Exec(ctx,
		`UPDATE api_keys SET last_used_at = now() WHERE id = $1`, apiKeyID)
	return err
}

// ---------- quota (legacy single-bucket — keeps current middleware working) ----------

// ConsumeTokens runs in a transaction:
//  1. SELECT FOR UPDATE the subscription
//  2. Roll the period over if it ended (resets tokens_used, snapshots
//     plan limits — including the new read/tx buckets and overage cap)
//  3. Atomically increment tokens_used if there is budget; otherwise
//     return ErrQuotaExceeded.
//
// Note: this intentionally ignores credits / gift cards / overage. The
// pricer refactor (5.2) replaces this with a credits→monthly→gift→overage
// pipeline. Until then, monthly is the only bucket charged.
func (s *pgStore) ConsumeTokens(ctx context.Context, subscriptionID string, cost int) (int64, error) {
	if cost <= 0 {
		return 0, fmt.Errorf("cost must be > 0")
	}

	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var (
		periodStart, periodEnd time.Time
		used, limit            int64
		planID, billingCycle   string
	)
	err = tx.QueryRow(ctx, `
        SELECT current_period_start, current_period_end,
               tokens_used, tokens_limit, plan_id, billing_cycle
        FROM subscriptions
        WHERE id = $1 AND status = 'active'
        FOR UPDATE`, subscriptionID).
		Scan(&periodStart, &periodEnd, &used, &limit, &planID, &billingCycle)
	if err != nil {
		return 0, mapErr(err)
	}

	// Period rollover.
	if !time.Now().UTC().Before(periodEnd) {
		var (
			newLimit                                int64
			newRps, newBurst                        int
			newReadRps, newReadBurst                int
			newTxRps, newTxBurst                    int
			overagePer1kCents                       int
		)
		err = tx.QueryRow(ctx, `
            SELECT monthly_tokens, rate_limit_rps, rate_limit_burst,
                   read_rps, read_burst, tx_rps, tx_burst, overage_per_1k_cents
            FROM plans WHERE id = $1`, planID).
			Scan(&newLimit, &newRps, &newBurst,
				&newReadRps, &newReadBurst, &newTxRps, &newTxBurst,
				&overagePer1kCents)
		if err != nil {
			return 0, fmt.Errorf("load plan: %w", err)
		}
		_ = overagePer1kCents // reserved for the pricer refactor

		newStart := periodEnd
		var newEnd time.Time
		if billingCycle == "annual" {
			newEnd = annualPeriodEnd(newStart)
		} else {
			newEnd = nextPeriodEnd(newStart)
		}
		// Catch up if dormant for several periods.
		now := time.Now().UTC()
		for !now.Before(newEnd) {
			newStart = newEnd
			if billingCycle == "annual" {
				newEnd = annualPeriodEnd(newStart)
			} else {
				newEnd = nextPeriodEnd(newStart)
			}
		}

		// Hard cap = 2× monthly tokens (overage cap).
		newOverageCap := newLimit * 2

		if _, err := tx.Exec(ctx, `
            UPDATE subscriptions
            SET current_period_start  = $1,
                current_period_end    = $2,
                tokens_used           = 0,
                tokens_limit          = $3,
                overage_used_tokens   = 0,
                overage_cap_tokens    = $4,
                rate_limit_rps        = $5,
                rate_limit_burst      = $6,
                read_rps              = $7,
                read_burst            = $8,
                tx_rps                = $9,
                tx_burst              = $10,
                updated_at            = now()
            WHERE id = $11`,
			newStart, newEnd, newLimit, newOverageCap,
			newRps, newBurst, newReadRps, newReadBurst, newTxRps, newTxBurst,
			subscriptionID); err != nil {
			return 0, err
		}
		used = 0
		limit = newLimit
	}

	if used+int64(cost) > limit {
		if err := tx.Commit(ctx); err != nil {
			return 0, err
		}
		return 0, ErrQuotaExceeded
	}

	var newUsed int64
	err = tx.QueryRow(ctx, `
        UPDATE subscriptions
        SET tokens_used = tokens_used + $1, updated_at = now()
        WHERE id = $2
        RETURNING tokens_used`, cost, subscriptionID).Scan(&newUsed)
	if err != nil {
		return 0, err
	}
	if err := tx.Commit(ctx); err != nil {
		return 0, err
	}
	return newUsed, nil
}

func (s *pgStore) RefundTokens(ctx context.Context, subscriptionID string, cost int) error {
	if cost <= 0 {
		return nil
	}
	_, err := s.pool.Exec(ctx, `
        UPDATE subscriptions
        SET tokens_used = GREATEST(tokens_used - $1, 0), updated_at = now()
        WHERE id = $2`, cost, subscriptionID)
	return err
}

// ---------- pricing ----------

func (s *pgStore) ListRequestCosts(ctx context.Context) ([]RequestCost, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT route_key, cost_tokens, description, updated_at FROM request_costs`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []RequestCost{}
	for rows.Next() {
		var c RequestCost
		if err := rows.Scan(&c.RouteKey, &c.CostTokens, &c.Description, &c.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

func (s *pgStore) UpsertRequestCost(ctx context.Context, c RequestCost) error {
	_, err := s.pool.Exec(ctx, `
        INSERT INTO request_costs (route_key, cost_tokens, description, updated_at)
        VALUES ($1, $2, $3, now())
        ON CONFLICT (route_key) DO UPDATE
        SET cost_tokens = EXCLUDED.cost_tokens,
            description = EXCLUDED.description,
            updated_at  = now()`,
		c.RouteKey, c.CostTokens, c.Description)
	return err
}

// ---------- usage events ----------

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

// ---------- plans ----------

func (s *pgStore) ListPlans(ctx context.Context) ([]Plan, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT `+planColumns+` FROM plans ORDER BY sort_order, code`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Plan{}
	for rows.Next() {
		p, err := scanPlan(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

func (s *pgStore) GetPlanByCode(ctx context.Context, code string) (*Plan, error) {
	row := s.pool.QueryRow(ctx,
		`SELECT `+planColumns+` FROM plans WHERE code = $1`, code)
	p, err := scanPlan(row)
	if err != nil {
		return nil, mapErr(err)
	}
	return &p, nil
}

func (s *pgStore) UpdatePlan(ctx context.Context, code string, mut PlanMutation) (*Plan, error) {
	sets := []string{}
	args := []any{code}
	add := func(col string, v any) {
		args = append(args, v)
		sets = append(sets, fmt.Sprintf("%s = $%d", col, len(args)))
	}
	if mut.Name != nil {
		add("name", *mut.Name)
	}
	if mut.MonthlyTokens != nil {
		add("monthly_tokens", *mut.MonthlyTokens)
	}
	if mut.PriceCents != nil {
		add("price_cents", *mut.PriceCents)
	}
	if mut.AnnualPriceCents != nil {
		add("annual_price_cents", *mut.AnnualPriceCents)
	}
	if mut.OveragePer1kCents != nil {
		add("overage_per_1k_cents", *mut.OveragePer1kCents)
	}
	if mut.RateLimitRPS != nil {
		add("rate_limit_rps", *mut.RateLimitRPS)
	}
	if mut.RateLimitBurst != nil {
		add("rate_limit_burst", *mut.RateLimitBurst)
	}
	if mut.ReadRPS != nil {
		add("read_rps", *mut.ReadRPS)
	}
	if mut.ReadBurst != nil {
		add("read_burst", *mut.ReadBurst)
	}
	if mut.TxRPS != nil {
		add("tx_rps", *mut.TxRPS)
	}
	if mut.TxBurst != nil {
		add("tx_burst", *mut.TxBurst)
	}
	if mut.Features != nil {
		b, err := json.Marshal(mut.Features)
		if err != nil {
			return nil, fmt.Errorf("marshal features: %w", err)
		}
		add("features", string(b))
	}
	if mut.IsActive != nil {
		add("is_active", *mut.IsActive)
	}
	if mut.IsGiftable != nil {
		add("is_giftable", *mut.IsGiftable)
	}
	if mut.SortOrder != nil {
		add("sort_order", *mut.SortOrder)
	}
	if len(sets) == 0 {
		return s.GetPlanByCode(ctx, code)
	}
	sets = append(sets, "updated_at = now()")
	q := fmt.Sprintf(`UPDATE plans SET %s WHERE code = $1 RETURNING %s`,
		strings.Join(sets, ", "), planColumns)

	row := s.pool.QueryRow(ctx, q, args...)
	p, err := scanPlan(row)
	if err != nil {
		return nil, mapErr(err)
	}
	return &p, nil
}

// ---------- users / keys / subscriptions ----------

func (s *pgStore) CreateUser(ctx context.Context, u *User) error {
	if u.ID == "" {
		return fmt.Errorf("user id required")
	}
	_, err := s.pool.Exec(ctx, `
        INSERT INTO users (id, email, name, created_at)
        VALUES ($1, $2, $3, COALESCE($4, now()))`,
		u.ID, u.Email, u.Name, nullableTime(u.CreatedAt))
	if err != nil && strings.Contains(err.Error(), "duplicate key") {
		return ErrAlreadyExists
	}
	return err
}

func (s *pgStore) GetUserByEmail(ctx context.Context, email string) (*User, error) {
	row := s.pool.QueryRow(ctx,
		`SELECT id, email, name, COALESCE(stripe_customer_id, ''), created_at
         FROM users WHERE email = $1`, email)
	var u User
	if err := row.Scan(&u.ID, &u.Email, &u.Name, &u.StripeCustomerID, &u.CreatedAt); err != nil {
		return nil, mapErr(err)
	}
	return &u, nil
}

func (s *pgStore) CreateAPIKey(ctx context.Context, k *APIKey) error {
	if k.ID == "" || k.UserID == "" {
		return fmt.Errorf("api key id and user id required")
	}
	if k.IPAllowlist == nil {
		k.IPAllowlist = []string{}
	}
	if k.AllowedOrigins == nil {
		k.AllowedOrigins = []string{}
	}
	_, err := s.pool.Exec(ctx, `
        INSERT INTO api_keys (id, user_id, name, prefix, hashed_key, scopes, ip_allowlist, allowed_origins, created_at)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, COALESCE($9, now()))`,
		k.ID, k.UserID, k.Name, k.Prefix, k.HashedKey, k.Scopes, k.IPAllowlist, k.AllowedOrigins, nullableTime(k.CreatedAt))
	if err != nil && strings.Contains(err.Error(), "duplicate key") {
		return ErrAlreadyExists
	}
	return err
}

func (s *pgStore) ListAPIKeysByUser(ctx context.Context, userID string) ([]APIKey, error) {
	rows, err := s.pool.Query(ctx, `
        SELECT id, user_id, name, prefix, scopes,
               COALESCE(ip_allowlist, '{}'::text[]),
               COALESCE(allowed_origins, '{}'::text[]),
               created_at, last_used_at, revoked_at
        FROM api_keys WHERE user_id = $1 ORDER BY created_at DESC`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []APIKey{}
	for rows.Next() {
		var k APIKey
		if err := rows.Scan(&k.ID, &k.UserID, &k.Name, &k.Prefix, &k.Scopes,
			&k.IPAllowlist,
			&k.AllowedOrigins,
			&k.CreatedAt, &k.LastUsedAt, &k.RevokedAt); err != nil {
			return nil, err
		}
		out = append(out, k)
	}
	return out, rows.Err()
}

// UpdateAPIKey patches the named fields. Validation of scopes / CIDRs
// happens at the handler layer before this is called.
func (s *pgStore) UpdateAPIKey(ctx context.Context, userID, keyID string, mut APIKeyMutation) (*APIKey, error) {
	sets := []string{}
	args := []any{userID, keyID}
	add := func(col string, v any) {
		args = append(args, v)
		sets = append(sets, fmt.Sprintf("%s = $%d", col, len(args)))
	}
	if mut.Name != nil {
		add("name", *mut.Name)
	}
	if mut.Scopes != nil {
		add("scopes", mut.Scopes)
	}
	if mut.IPAllowlist != nil {
		add("ip_allowlist", mut.IPAllowlist)
	}
	if mut.AllowedOrigins != nil {
		add("allowed_origins", mut.AllowedOrigins)
	}
	if len(sets) == 0 {
		// Nothing to update — return current state.
		row := s.pool.QueryRow(ctx, `
            SELECT id, user_id, name, prefix, scopes,
                   COALESCE(ip_allowlist, '{}'::text[]),
                   COALESCE(allowed_origins, '{}'::text[]),
                   created_at, last_used_at, revoked_at
            FROM api_keys WHERE id = $2 AND user_id = $1`, userID, keyID)
		var k APIKey
		if err := row.Scan(&k.ID, &k.UserID, &k.Name, &k.Prefix, &k.Scopes,
			&k.IPAllowlist, &k.AllowedOrigins, &k.CreatedAt, &k.LastUsedAt, &k.RevokedAt); err != nil {
			return nil, mapErr(err)
		}
		return &k, nil
	}

	q := fmt.Sprintf(`UPDATE api_keys SET %s
                      WHERE user_id = $1 AND id = $2 AND revoked_at IS NULL
                      RETURNING id, user_id, name, prefix, scopes,
                                COALESCE(ip_allowlist, '{}'::text[]),
                                COALESCE(allowed_origins, '{}'::text[]),
                                created_at, last_used_at, revoked_at`,
		strings.Join(sets, ", "))
	row := s.pool.QueryRow(ctx, q, args...)
	var k APIKey
	if err := row.Scan(&k.ID, &k.UserID, &k.Name, &k.Prefix, &k.Scopes,
		&k.IPAllowlist, &k.AllowedOrigins, &k.CreatedAt, &k.LastUsedAt, &k.RevokedAt); err != nil {
		return nil, mapErr(err)
	}
	return &k, nil
}

func (s *pgStore) RevokeAPIKey(ctx context.Context, userID, keyID string) error {
	tag, err := s.pool.Exec(ctx, `
        UPDATE api_keys SET revoked_at = now()
        WHERE id = $1 AND user_id = $2 AND revoked_at IS NULL`, keyID, userID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// AssignPlan creates or replaces the active subscription for a user. The
// new subscription is snapshotted with the plan's current values for
// tokens, RPS buckets and overage cap (= 2× monthly_tokens).
func (s *pgStore) AssignPlan(ctx context.Context, userID, planCode string) (*Subscription, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var (
		planID                              string
		monthlyTokens                       int64
		legacyRps, legacyBurst              int
		readRps, readBurst, txRps, txBurst  int
	)
	err = tx.QueryRow(ctx, `
        SELECT id, monthly_tokens,
               rate_limit_rps, rate_limit_burst,
               read_rps, read_burst, tx_rps, tx_burst
        FROM plans WHERE code = $1 AND is_active = true`, planCode).
		Scan(&planID, &monthlyTokens,
			&legacyRps, &legacyBurst,
			&readRps, &readBurst, &txRps, &txBurst)
	if err != nil {
		return nil, mapErr(err)
	}

	if _, err := tx.Exec(ctx, `
        UPDATE subscriptions SET status = 'cancelled', updated_at = now()
        WHERE user_id = $1 AND status = 'active'`, userID); err != nil {
		return nil, err
	}

	now := time.Now().UTC()
	end := nextPeriodEnd(now)
	overageCap := monthlyTokens * 2

	var subID string
	err = tx.QueryRow(ctx, `
        INSERT INTO subscriptions
            (user_id, plan_id, status, billing_cycle,
             current_period_start, current_period_end,
             tokens_used, tokens_limit,
             overage_enabled, overage_card_present, overage_used_tokens, overage_cap_tokens,
             rate_limit_rps, rate_limit_burst,
             read_rps, read_burst, tx_rps, tx_burst)
        VALUES ($1, $2, 'active', 'monthly',
                $3, $4,
                0, $5,
                false, false, 0, $6,
                $7, $8,
                $9, $10, $11, $12)
        RETURNING id`,
		userID, planID, now, end, monthlyTokens, overageCap,
		legacyRps, legacyBurst, readRps, readBurst, txRps, txBurst).
		Scan(&subID)
	if err != nil {
		return nil, err
	}

	// Re-read with the canonical column set so the returned struct is
	// consistent with GetActiveSubscription / AuthenticateAPIKey.
	row := tx.QueryRow(ctx, `
        SELECT `+subscriptionColumns+`
        FROM subscriptions sub
        JOIN plans p ON p.id = sub.plan_id
        WHERE sub.id = $1`, subID)
	var sub Subscription
	if err := scanSubscription(row, &sub); err != nil {
		return nil, err
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return &sub, nil
}

func (s *pgStore) GetActiveSubscription(ctx context.Context, userID string) (*Subscription, error) {
	row := s.pool.QueryRow(ctx, `
        SELECT `+subscriptionColumns+`
        FROM subscriptions sub
        JOIN plans p ON p.id = sub.plan_id
        WHERE sub.user_id = $1 AND sub.status = 'active'
        LIMIT 1`, userID)
	var sub Subscription
	if err := scanSubscription(row, &sub); err != nil {
		return nil, mapErr(err)
	}
	return &sub, nil
}

func (s *pgStore) UpdateSubscription(ctx context.Context, subscriptionID string, mut SubscriptionMutation) (*Subscription, error) {
	sets := []string{}
	args := []any{subscriptionID}
	add := func(col string, v any) {
		args = append(args, v)
		sets = append(sets, fmt.Sprintf("%s = $%d", col, len(args)))
	}
	if mut.OverageEnabled != nil {
		add("overage_enabled", *mut.OverageEnabled)
	}
	if mut.OverageCardPresent != nil {
		add("overage_card_present", *mut.OverageCardPresent)
	}
	if mut.OverageCapTokens != nil {
		add("overage_cap_tokens", *mut.OverageCapTokens)
	}
	if mut.BillingCycle != nil {
		add("billing_cycle", *mut.BillingCycle)
	}
	if mut.StripeCustomerID != nil {
		add("stripe_customer_id", *mut.StripeCustomerID)
	}
	if mut.StripeSubscriptionID != nil {
		add("stripe_subscription_id", *mut.StripeSubscriptionID)
	}
	if len(sets) == 0 {
		// Nothing to update — return current state.
		row := s.pool.QueryRow(ctx, `
            SELECT `+subscriptionColumns+`
            FROM subscriptions sub
            JOIN plans p ON p.id = sub.plan_id
            WHERE sub.id = $1`, subscriptionID)
		var sub Subscription
		if err := scanSubscription(row, &sub); err != nil {
			return nil, mapErr(err)
		}
		return &sub, nil
	}
	sets = append(sets, "updated_at = now()")

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	q := fmt.Sprintf(`UPDATE subscriptions SET %s WHERE id = $1`, strings.Join(sets, ", "))
	tag, err := tx.Exec(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	if tag.RowsAffected() == 0 {
		return nil, ErrNotFound
	}

	row := tx.QueryRow(ctx, `
        SELECT `+subscriptionColumns+`
        FROM subscriptions sub
        JOIN plans p ON p.id = sub.plan_id
        WHERE sub.id = $1`, subscriptionID)
	var sub Subscription
	if err := scanSubscription(row, &sub); err != nil {
		return nil, mapErr(err)
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return &sub, nil
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
