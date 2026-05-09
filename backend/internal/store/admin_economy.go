package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

// =============================================================================
// Admin economy: plan/cost/key/credit/coupon/pricing-change mutations.
//
// All schema (`plans`, `request_costs`, `credits`, `gift_cards`,
// `pricing_history`) is owned by the gateway's migration set. Backend
// reaches into the same Postgres pool for admin ops.
// =============================================================================

var (
	ErrGiftNotEligible   = errors.New("gift card not eligible for refund")
	ErrPricingChangeBusy = errors.New("pricing change already applied or cancelled")
)

// AdminEconomyStore is the subset of operations the /admin economy
// handlers (plans, request-costs, api-keys, credits, coupons,
// pricing-changes, overage) need. Backend's PostgresStore satisfies it.
type AdminEconomyStore interface {
	// Plans + costs.
	UpdatePlan(ctx context.Context, code string, mut PlanMutation) (*Plan, error)
	ListRequestCosts(ctx context.Context) ([]RequestCost, error)
	UpsertRequestCost(ctx context.Context, c RequestCost) error

	// API keys.
	UpdateAPIKey(ctx context.Context, userID, keyID string, mut APIKeyMutation) (*APIKey, error)

	// Credits.
	GrantCredit(ctx context.Context, in CreditGrant) (*Credit, error)

	// Gift cards (refund + admin listing).
	RefundGiftCard(ctx context.Context, id string) (*GiftCard, error)
	ListGiftCardsForAdmin(ctx context.Context, source, status string) ([]GiftCard, error)

	// Pricing changes. ListPendingPricingChanges is also part of
	// NotificationStore — admin reuses that view directly.
	CreatePricingChange(ctx context.Context, in PricingChangeCreate) (*PricingChange, error)
	ListPendingPricingChanges(ctx context.Context) ([]PricingChange, error)
	ListPricingChangesByTarget(ctx context.Context, changeType, target string) ([]PricingChange, error)
	CancelPricingChange(ctx context.Context, id int64) error
}

// =============================================================================
// Plan mutations
// =============================================================================

type PlanMutation struct {
	Name              *string
	MonthlyTokens     *int64
	PriceCents        *int
	AnnualPriceCents  *int
	OveragePer1kCents *int
	RateLimitRPS      *int
	RateLimitBurst    *int
	ReadRPS           *int
	ReadBurst         *int
	TxRPS             *int
	TxBurst           *int
	Features          map[string]any
	IsActive          *bool
	IsGiftable        *bool
	SortOrder         *int
}

func (s *PostgresStore) UpdatePlan(ctx context.Context, code string, mut PlanMutation) (*Plan, error) {
	code = strings.ToLower(strings.TrimSpace(code))
	if code == "" {
		return nil, fmt.Errorf("code required")
	}
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
		raw, err := json.Marshal(mut.Features)
		if err != nil {
			return nil, fmt.Errorf("marshal features: %w", err)
		}
		add("features", raw)
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
	q := fmt.Sprintf(`UPDATE plans SET %s WHERE code = $1`, strings.Join(sets, ", "))
	tag, err := s.pool.Exec(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	if tag.RowsAffected() == 0 {
		return nil, ErrNotFound
	}
	return s.GetPlanByCode(ctx, code)
}

// =============================================================================
// Request costs (route → cost-tokens map)
// =============================================================================

type RequestCost struct {
	RouteKey    string    `json:"routeKey"`
	CostTokens  int       `json:"costTokens"`
	Description string    `json:"description"`
	UpdatedAt   time.Time `json:"updatedAt"`
}

func (s *PostgresStore) ListRequestCosts(ctx context.Context) ([]RequestCost, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT route_key, cost_tokens, COALESCE(description, ''), updated_at
		 FROM request_costs ORDER BY route_key`)
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

func (s *PostgresStore) UpsertRequestCost(ctx context.Context, c RequestCost) error {
	if c.RouteKey == "" {
		return fmt.Errorf("route_key required")
	}
	if c.CostTokens < 1 {
		return fmt.Errorf("cost_tokens must be >= 1")
	}
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

// =============================================================================
// API key admin updates (scopes / IP allowlist / name)
// =============================================================================

type APIKeyMutation struct {
	Name           *string
	Scopes         []string // nil = unchanged; empty slice = clear (treated as nil for safety)
	IPAllowlist    *[]string // nil = unchanged; empty slice = clear
	AllowedOrigins *[]string // nil = unchanged; empty slice = clear
}

func (s *PostgresStore) UpdateAPIKey(ctx context.Context, userID, keyID string, mut APIKeyMutation) (*APIKey, error) {
	if userID == "" || keyID == "" {
		return nil, fmt.Errorf("userID and keyID required")
	}
	sets := []string{}
	args := []any{keyID, userID}
	add := func(col string, v any) {
		args = append(args, v)
		sets = append(sets, fmt.Sprintf("%s = $%d", col, len(args)))
	}
	if mut.Name != nil {
		add("name", *mut.Name)
	}
	if mut.Scopes != nil && len(mut.Scopes) > 0 {
		add("scopes", mut.Scopes)
	}
	if mut.IPAllowlist != nil {
		add("ip_allowlist", *mut.IPAllowlist)
	}
	if mut.AllowedOrigins != nil {
		add("allowed_origins", *mut.AllowedOrigins)
	}
	if len(sets) == 0 {
		return s.getAPIKeyByID(ctx, userID, keyID)
	}
	q := fmt.Sprintf(`UPDATE api_keys SET %s WHERE id = $1 AND user_id = $2 AND revoked_at IS NULL`,
		strings.Join(sets, ", "))
	tag, err := s.pool.Exec(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	if tag.RowsAffected() == 0 {
		return nil, ErrNotFound
	}
	return s.getAPIKeyByID(ctx, userID, keyID)
}

func (s *PostgresStore) getAPIKeyByID(ctx context.Context, userID, keyID string) (*APIKey, error) {
	row := s.pool.QueryRow(ctx, `
		SELECT id, user_id, name, prefix, hashed_key, scopes,
		       COALESCE(ip_allowlist, '{}'::text[]),
		       COALESCE(allowed_origins, '{}'::text[]),
		       created_at, last_used_at, revoked_at
		FROM api_keys WHERE id = $1 AND user_id = $2`, keyID, userID)
	k := &APIKey{}
	if err := row.Scan(&k.ID, &k.UserID, &k.Name, &k.Prefix, &k.HashedKey, &k.Scopes,
		&k.IPAllowlist, &k.AllowedOrigins, &k.CreatedAt, &k.LastUsedAt, &k.RevokedAt); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return k, nil
}

// =============================================================================
// Credits
// =============================================================================

type Credit struct {
	ID         string     `json:"id"`
	UserID     string     `json:"userId"`
	Amount     int64      `json:"amount"`
	Consumed   int64      `json:"consumed"`
	Reason     string     `json:"reason"`
	GrantedBy  string     `json:"grantedBy"`
	ExpiresAt  time.Time  `json:"expiresAt"`
	ExhaustedAt *time.Time `json:"exhaustedAt,omitempty"`
	CreatedAt  time.Time  `json:"createdAt"`
}

type CreditGrant struct {
	UserID    string
	Amount    int64
	Reason    string
	GrantedBy string
	ExpiresAt time.Time // optional override of the 30-day default
}

const creditDefaultTTL = 30 * 24 * time.Hour

func (s *PostgresStore) GrantCredit(ctx context.Context, in CreditGrant) (*Credit, error) {
	if in.UserID == "" {
		return nil, fmt.Errorf("user_id required")
	}
	if in.Amount <= 0 {
		return nil, fmt.Errorf("amount must be > 0")
	}
	switch in.Reason {
	case "trial", "support", "promo", "hackathon", "partner":
	default:
		return nil, fmt.Errorf("reason must be 'trial', 'support', 'promo', 'hackathon' or 'partner'")
	}
	now := time.Now().UTC()
	expiresAt := in.ExpiresAt
	if expiresAt.IsZero() {
		expiresAt = now.Add(creditDefaultTTL)
	}
	if expiresAt.Sub(now) > creditDefaultTTL+24*time.Hour {
		return nil, fmt.Errorf("expires_at cannot be more than 30 days from now")
	}
	row := s.pool.QueryRow(ctx, `
		INSERT INTO credits (user_id, amount, reason, granted_by, expires_at)
		VALUES ($1, $2, $3, $4, $5)
		RETURNING id, user_id, amount, consumed, reason, granted_by, expires_at, exhausted_at, created_at`,
		in.UserID, in.Amount, in.Reason, in.GrantedBy, expiresAt)
	c := &Credit{}
	if err := row.Scan(&c.ID, &c.UserID, &c.Amount, &c.Consumed, &c.Reason,
		&c.GrantedBy, &c.ExpiresAt, &c.ExhaustedAt, &c.CreatedAt); err != nil {
		return nil, err
	}
	return c, nil
}

// =============================================================================
// Gift cards — refund + admin listing
// =============================================================================

const giftRefundWindow = 7 * 24 * time.Hour

// RefundGiftCard marks a gift card as refunded. Eligibility:
//
//   - Source must be 'paid' (promo cards have no money to refund).
//   - Created within the last 7 days.
//   - Not yet redeemed and not yet refunded.
//
// Returns ErrGiftNotEligible / ErrGiftAlreadyUsed / ErrGiftRefunded /
// ErrNotFound on the corresponding states.
func (s *PostgresStore) RefundGiftCard(ctx context.Context, id string) (*GiftCard, error) {
	if id == "" {
		return nil, ErrNotFound
	}
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	row := tx.QueryRow(ctx,
		`SELECT `+giftCardColumns+` FROM gift_cards WHERE id = $1 FOR UPDATE`, id)
	var g GiftCard
	if err := scanGiftCard(row, &g); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	if g.RedeemedAt != nil {
		return nil, ErrGiftAlreadyUsed
	}
	if g.RefundedAt != nil {
		return nil, ErrGiftRefunded
	}
	if g.Source != "paid" {
		return nil, ErrGiftNotEligible
	}
	if time.Since(g.CreatedAt) > giftRefundWindow {
		return nil, ErrGiftNotEligible
	}

	row = tx.QueryRow(ctx, `
		UPDATE gift_cards SET refunded_at = now()
		WHERE id = $1
		RETURNING `+giftCardColumns, id)
	if err := scanGiftCard(row, &g); err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return &g, nil
}

// ListGiftCardsForAdmin returns at most 500 most-recent gift cards
// matching the filters. Filters with empty values are ignored.
func (s *PostgresStore) ListGiftCardsForAdmin(ctx context.Context, source, status string) ([]GiftCard, error) {
	q := `SELECT ` + giftCardColumns + ` FROM gift_cards`
	conds := []string{}
	args := []any{}

	source = strings.ToLower(strings.TrimSpace(source))
	switch source {
	case "":
	case "paid", "promo":
		args = append(args, source)
		conds = append(conds, fmt.Sprintf("source = $%d", len(args)))
	default:
		return nil, fmt.Errorf("source must be 'paid' or 'promo'")
	}

	status = strings.ToLower(strings.TrimSpace(status))
	switch status {
	case "":
	case "active":
		conds = append(conds, "redeemed_at IS NULL AND refunded_at IS NULL AND expires_at > now()")
	case "redeemed":
		conds = append(conds, "redeemed_at IS NOT NULL")
	case "refunded":
		conds = append(conds, "refunded_at IS NOT NULL")
	case "expired":
		conds = append(conds, "redeemed_at IS NULL AND refunded_at IS NULL AND expires_at <= now()")
	default:
		return nil, fmt.Errorf("status must be 'active', 'redeemed', 'refunded' or 'expired'")
	}

	if len(conds) > 0 {
		q += " WHERE " + strings.Join(conds, " AND ")
	}
	q += " ORDER BY created_at DESC LIMIT 500"

	rows, err := s.pool.Query(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []GiftCard{}
	for rows.Next() {
		var g GiftCard
		if err := scanGiftCard(rows, &g); err != nil {
			return nil, err
		}
		out = append(out, g)
	}
	return out, rows.Err()
}

// =============================================================================
// Pricing changes (versioned, scheduled, applied by the M2 worker)
// =============================================================================

type PricingChangeCreate struct {
	ChangeType  string // 'cost' | 'plan_price' | 'plan_overage' | 'plan_tokens'
	TargetKey   string
	NewValue    int64
	EffectiveAt time.Time
	CreatedBy   string
	Reason      string
}

// MinPricingNoticeWindow is the minimum lead time between scheduling a
// price change and its effective date. 30 days mirrors the gateway
// invariant — the M2 notification worker emails users in this window.
const MinPricingNoticeWindow = 30 * 24 * time.Hour

// pricingChangeColumns + scanPricingChange + PricingChange type live
// in notifications.go (declared in M2). We reuse them here.

// CreatePricingChange records a scheduled mutation. Captures the CURRENT
// live value as old_value so the audit trail is complete even if a later
// change supersedes this one. Refuses effective_at < now() + 30 days.
func (s *PostgresStore) CreatePricingChange(ctx context.Context, in PricingChangeCreate) (*PricingChange, error) {
	switch in.ChangeType {
	case "route_cost",
		"plan_price", "plan_annual_price",
		"plan_tokens", "plan_read_rps", "plan_tx_rps", "plan_overage":
	default:
		return nil, fmt.Errorf("unknown change_type: %s", in.ChangeType)
	}
	if strings.TrimSpace(in.TargetKey) == "" {
		return nil, fmt.Errorf("target_key required")
	}
	if in.CreatedBy == "" {
		return nil, fmt.Errorf("created_by required")
	}
	if in.NewValue < 0 {
		return nil, fmt.Errorf("new_value must be >= 0")
	}
	now := time.Now().UTC()
	if in.EffectiveAt.IsZero() {
		return nil, fmt.Errorf("effective_at required")
	}
	if in.EffectiveAt.Before(now.Add(MinPricingNoticeWindow)) {
		return nil, fmt.Errorf("effective_at must be at least 30 days in the future")
	}

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	oldVal, err := lookupCurrentPricingValue(ctx, tx, in.ChangeType, in.TargetKey)
	if err != nil {
		return nil, err
	}

	row := tx.QueryRow(ctx, `
        INSERT INTO pricing_history
            (change_type, target_key, old_value, new_value,
             effective_at, created_by, reason)
        VALUES ($1, $2, $3, $4, $5, $6, $7)
        RETURNING `+pricingChangeColumns,
		in.ChangeType, in.TargetKey, oldVal, in.NewValue,
		in.EffectiveAt, in.CreatedBy, in.Reason)
	var p PricingChange
	if err := scanPricingChange(row, &p); err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return &p, nil
}

// lookupCurrentPricingValue fetches the live value being mutated, used to
// fill old_value at scheduling time. Returns a nil pointer when the
// target doesn't exist — admin sees "no prior value" instead of erroring
// the whole insert.
func lookupCurrentPricingValue(ctx context.Context, tx pgx.Tx, changeType, target string) (*int64, error) {
	var (
		v   int64
		err error
	)
	switch changeType {
	case "plan_price":
		err = tx.QueryRow(ctx,
			`SELECT price_cents FROM plans WHERE code = $1`, target).Scan(&v)
	case "plan_annual_price":
		err = tx.QueryRow(ctx,
			`SELECT annual_price_cents FROM plans WHERE code = $1`, target).Scan(&v)
	case "plan_tokens":
		err = tx.QueryRow(ctx,
			`SELECT monthly_tokens FROM plans WHERE code = $1`, target).Scan(&v)
	case "plan_read_rps":
		err = tx.QueryRow(ctx,
			`SELECT read_rps FROM plans WHERE code = $1`, target).Scan(&v)
	case "plan_tx_rps":
		err = tx.QueryRow(ctx,
			`SELECT tx_rps FROM plans WHERE code = $1`, target).Scan(&v)
	case "plan_overage":
		err = tx.QueryRow(ctx,
			`SELECT overage_per_1k_cents FROM plans WHERE code = $1`, target).Scan(&v)
	case "route_cost":
		err = tx.QueryRow(ctx,
			`SELECT cost_tokens FROM request_costs WHERE route_key = $1`, target).Scan(&v)
	default:
		return nil, fmt.Errorf("unknown change_type: %s", changeType)
	}
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	return &v, nil
}

func (s *PostgresStore) ListPricingChangesByTarget(ctx context.Context, changeType, target string) ([]PricingChange, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT `+pricingChangeColumns+`
		FROM pricing_history
		WHERE change_type = $1 AND target_key = $2
		ORDER BY effective_at DESC`,
		changeType, target)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []PricingChange{}
	for rows.Next() {
		var pc PricingChange
		if err := scanPricingChange(rows, &pc); err != nil {
			return nil, err
		}
		out = append(out, pc)
	}
	return out, rows.Err()
}

// ListPendingPricingChanges already lives in notifications.go (used by
// the M2 worker). Admin handlers reuse it directly.

func (s *PostgresStore) CancelPricingChange(ctx context.Context, id int64) error {
	tag, err := s.pool.Exec(ctx, `
		UPDATE pricing_history
		SET cancelled_at = now()
		WHERE id = $1
		  AND applied_at IS NULL
		  AND cancelled_at IS NULL`, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		// Either the row doesn't exist OR it's already terminal. We
		// could distinguish with a follow-up SELECT but the admin UI
		// doesn't need that level of detail.
		var n int
		err := s.pool.QueryRow(ctx, `SELECT COUNT(*)::int FROM pricing_history WHERE id = $1`, id).Scan(&n)
		if err == nil && n == 0 {
			return ErrNotFound
		}
		return ErrPricingChangeBusy
	}
	return nil
}

