package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// =============================================================================
// Customer-facing read paths: pricing, balance, usage, gift redemption.
//
// All tables live in the gateway-owned schema; the backend just reads /
// writes through the same Postgres pool.
// =============================================================================

var (
	ErrGiftAlreadyUsed = errors.New("gift card already redeemed")
	ErrGiftExpired     = errors.New("gift card expired")
	ErrGiftRefunded    = errors.New("gift card refunded")
)

// Plan mirrors gateway's plans row.
type Plan struct {
	Code              string
	Name              string
	MonthlyTokens     int64
	PriceCents        int
	AnnualPriceCents  int
	OveragePer1kCents int
	RateLimitRPS      int
	RateLimitBurst    int
	ReadRPS           int
	ReadBurst         int
	TxRPS             int
	TxBurst           int
	Features          map[string]any
	IsActive          bool
	IsGiftable        bool
	SortOrder         int
}

// Balance is the per-bucket remaining-token snapshot for a user.
type Balance struct {
	Subscription     *Subscription `json:"subscription,omitempty"`
	Credits          int64         `json:"credits"`
	MonthlyRemaining int64         `json:"monthlyRemaining"`
	OverageAvailable int64         `json:"overageAvailable"`
	TotalRemaining   int64         `json:"totalRemaining"`
	PeriodEnd        time.Time     `json:"periodEnd,omitempty"`
}

// UsageDailyBucket / UsageRouteBucket / UsageReport are the projections
// the dashboard chart consumes.
type UsageDailyBucket struct {
	Date   time.Time `json:"date"`
	Tokens int64     `json:"tokens"`
	Calls  int64     `json:"calls"`
}

type UsageRouteBucket struct {
	RouteKey string `json:"routeKey"`
	Tokens   int64  `json:"tokens"`
	Calls    int64  `json:"calls"`
}

type UsageReport struct {
	Since     time.Time          `json:"since"`
	Until     time.Time          `json:"until"`
	Tokens    int64              `json:"tokens"`
	Calls     int64              `json:"calls"`
	Daily     []UsageDailyBucket `json:"daily"`
	TopRoutes []UsageRouteBucket `json:"topRoutes"`
}

// GiftCardRedemption is what ApplyGiftCard returns: the gift after it
// is marked redeemed, plus the subscription that received the benefit.
type GiftCardRedemption struct {
	GiftCard     *GiftCard     `json:"giftCard"`
	Subscription *Subscription `json:"subscription"`
	Action       string        `json:"action"` // 'created' | 'extended' | 'upgraded'
	AddedTokens  int64         `json:"addedTokens"`
	AddedDays    int           `json:"addedDays"`
}

// CustomerStore is the subset of operations the customer-facing
// endpoints (/v1/me/*, /v1/pricing/plans, /v1/gifts/*) call.
type CustomerStore interface {
	// Plans.
	ListPlans(ctx context.Context) ([]Plan, error)
	GetPlanByCode(ctx context.Context, code string) (*Plan, error)

	// Balance + usage.
	ComputeBalance(ctx context.Context, userID string) (*Balance, error)
	SumActiveCredits(ctx context.Context, userID string) (int64, error)
	GetUsageReport(ctx context.Context, userID string, since, until time.Time, routeLimit int) (*UsageReport, error)

	// Gift redemption.
	GetGiftCardByToken(ctx context.Context, token string) (*GiftCard, error)
	ApplyGiftCard(ctx context.Context, token, recipientUserID string) (*GiftCardRedemption, error)
}

// ----- PostgresStore implementations -----

const planColumns = `
	code, name,
	monthly_tokens, price_cents, annual_price_cents, overage_per_1k_cents,
	rate_limit_rps, rate_limit_burst,
	read_rps, read_burst, tx_rps, tx_burst,
	features, is_active, is_giftable, sort_order`

func scanPlan(row pgx.Row) (Plan, error) {
	var (
		p           Plan
		featuresRaw []byte
	)
	if err := row.Scan(&p.Code, &p.Name,
		&p.MonthlyTokens, &p.PriceCents, &p.AnnualPriceCents, &p.OveragePer1kCents,
		&p.RateLimitRPS, &p.RateLimitBurst,
		&p.ReadRPS, &p.ReadBurst, &p.TxRPS, &p.TxBurst,
		&featuresRaw, &p.IsActive, &p.IsGiftable, &p.SortOrder); err != nil {
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

func (s *PostgresStore) ListPlans(ctx context.Context) ([]Plan, error) {
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

func (s *PostgresStore) GetPlanByCode(ctx context.Context, code string) (*Plan, error) {
	row := s.pool.QueryRow(ctx,
		`SELECT `+planColumns+` FROM plans WHERE code = $1`, code)
	p, err := scanPlan(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return &p, nil
}

func (s *PostgresStore) SumActiveCredits(ctx context.Context, userID string) (int64, error) {
	var total int64
	err := s.pool.QueryRow(ctx, `
		SELECT COALESCE(SUM(amount - consumed), 0)
		FROM credits
		WHERE user_id = $1
		  AND exhausted_at IS NULL
		  AND expires_at > now()`, userID).Scan(&total)
	if err != nil {
		return 0, err
	}
	return total, nil
}

func (s *PostgresStore) ComputeBalance(ctx context.Context, userID string) (*Balance, error) {
	out := &Balance{}

	credits, err := s.SumActiveCredits(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("sum credits: %w", err)
	}
	out.Credits = credits

	sub, err := s.GetActiveSubscription(ctx, userID)
	switch {
	case err == nil:
		out.Subscription = sub
		out.MonthlyRemaining = sub.TokensLimit - sub.TokensUsed
		if out.MonthlyRemaining < 0 {
			out.MonthlyRemaining = 0
		}
		if sub.OverageEnabled && sub.OverageCardPresent {
			out.OverageAvailable = sub.OverageCapTokens - sub.OverageUsedTokens
			if out.OverageAvailable < 0 {
				out.OverageAvailable = 0
			}
		}
		out.PeriodEnd = sub.CurrentPeriodEnd
	case errors.Is(err, ErrNotFound):
		// User has no active subscription — credits-only balance.
	default:
		return nil, fmt.Errorf("load subscription: %w", err)
	}

	out.TotalRemaining = out.Credits + out.MonthlyRemaining + out.OverageAvailable
	return out, nil
}

func (s *PostgresStore) GetUsageReport(ctx context.Context, userID string, since, until time.Time, routeLimit int) (*UsageReport, error) {
	if userID == "" {
		return nil, ErrNotFound
	}
	if !since.Before(until) {
		return nil, errors.New("since must be before until")
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

	dailyRows, err := s.pool.Query(ctx, `
		SELECT date_trunc('day', occurred_at)::timestamptz AS day,
		       SUM(cost_tokens)::bigint AS tokens,
		       COUNT(*)::bigint         AS calls
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

func (s *PostgresStore) GetGiftCardByToken(ctx context.Context, token string) (*GiftCard, error) {
	row := s.pool.QueryRow(ctx,
		`SELECT `+giftCardColumns+` FROM gift_cards WHERE redeem_token = $1`, token)
	var g GiftCard
	if err := scanGiftCard(row, &g); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return &g, nil
}

// ApplyGiftCard atomically marks a gift redeemed AND applies the plan
// to the recipient's subscription. Three outcomes:
//
//   - Action="created"  — recipient had no active subscription
//   - Action="extended" — current plan tier ≥ gift plan tier
//   - Action="upgraded" — current plan tier < gift plan tier (plan + RPS swap)
//
// "Tier" comparison is plans.sort_order — equal tiers are treated as
// equal (no upgrade). Errors: ErrNotFound / ErrGiftAlreadyUsed /
// ErrGiftExpired / ErrGiftRefunded.
func (s *PostgresStore) ApplyGiftCard(ctx context.Context, token, recipientUserID string) (*GiftCardRedemption, error) {
	if token == "" || recipientUserID == "" {
		return nil, ErrNotFound
	}

	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	row := tx.QueryRow(ctx,
		`SELECT `+giftCardColumns+`
		 FROM gift_cards WHERE redeem_token = $1
		 FOR UPDATE`, token)
	var gift GiftCard
	if err := scanGiftCard(row, &gift); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	now := time.Now().UTC()
	if gift.RedeemedAt != nil {
		return nil, ErrGiftAlreadyUsed
	}
	if gift.RefundedAt != nil {
		return nil, ErrGiftRefunded
	}
	if !now.Before(gift.ExpiresAt) {
		return nil, ErrGiftExpired
	}

	var (
		giftPlanID      string
		giftMonthly     int64
		giftSortOrder   int
		giftLegacyRPS   int
		giftLegacyBurst int
		giftReadRPS     int
		giftReadBurst   int
		giftTxRPS       int
		giftTxBurst     int
	)
	err = tx.QueryRow(ctx, `
		SELECT id, monthly_tokens, sort_order,
		       rate_limit_rps, rate_limit_burst,
		       read_rps, read_burst, tx_rps, tx_burst
		FROM plans
		WHERE code = $1 AND is_active = true`, gift.PlanCode).
		Scan(&giftPlanID, &giftMonthly, &giftSortOrder,
			&giftLegacyRPS, &giftLegacyBurst,
			&giftReadRPS, &giftReadBurst, &giftTxRPS, &giftTxBurst)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("load gift plan: %w", err)
	}

	addedTokens := giftMonthly * int64(gift.DurationMonths)
	addedDays := gift.DurationMonths * 30

	var subID string
	err = tx.QueryRow(ctx,
		`SELECT id FROM subscriptions
		 WHERE user_id = $1 AND status = 'active'
		 FOR UPDATE`, recipientUserID).Scan(&subID)

	var (
		action string
		subOut Subscription
	)

	switch {
	case errors.Is(err, pgx.ErrNoRows):
		action = "created"
		periodStart := now
		periodEnd := periodStart.AddDate(0, gift.DurationMonths, 0)
		overageCap := giftMonthly * 2

		if err := tx.QueryRow(ctx, `
			INSERT INTO subscriptions
			    (user_id, plan_id, status, billing_cycle,
			     current_period_start, current_period_end,
			     tokens_used, tokens_limit,
			     overage_enabled, overage_card_present,
			     overage_used_tokens, overage_cap_tokens,
			     rate_limit_rps, rate_limit_burst,
			     read_rps, read_burst, tx_rps, tx_burst)
			VALUES ($1, $2, 'active', 'monthly',
			        $3, $4,
			        0, $5,
			        false, false, 0, $6,
			        $7, $8,
			        $9, $10, $11, $12)
			RETURNING id`,
			recipientUserID, giftPlanID,
			periodStart, periodEnd,
			giftMonthly, overageCap,
			giftLegacyRPS, giftLegacyBurst,
			giftReadRPS, giftReadBurst, giftTxRPS, giftTxBurst).Scan(&subID); err != nil {
			return nil, fmt.Errorf("create sub from gift: %w", err)
		}

	case err != nil:
		return nil, fmt.Errorf("lock subscription: %w", err)

	default:
		var (
			currentPlanID      string
			currentSortOrder   int
			currentTokensLimit int64
			currentPeriodEnd   time.Time
			currentOverageCap  int64
		)
		err = tx.QueryRow(ctx, `
			SELECT sub.plan_id, p.sort_order,
			       sub.tokens_limit, sub.current_period_end, sub.overage_cap_tokens
			FROM subscriptions sub
			JOIN plans p ON p.id = sub.plan_id
			WHERE sub.id = $1`, subID).
			Scan(&currentPlanID, &currentSortOrder,
				&currentTokensLimit, &currentPeriodEnd, &currentOverageCap)
		if err != nil {
			return nil, fmt.Errorf("read current sub: %w", err)
		}

		newLimit := currentTokensLimit + addedTokens
		newPeriodEnd := currentPeriodEnd.AddDate(0, gift.DurationMonths, 0)

		if giftSortOrder > currentSortOrder {
			action = "upgraded"
			newOverageCap := currentOverageCap + giftMonthly*2
			if _, err := tx.Exec(ctx, `
				UPDATE subscriptions
				SET plan_id              = $1,
				    tokens_limit         = $2,
				    current_period_end   = $3,
				    overage_cap_tokens   = $4,
				    rate_limit_rps       = $5,
				    rate_limit_burst     = $6,
				    read_rps             = $7,
				    read_burst           = $8,
				    tx_rps               = $9,
				    tx_burst             = $10,
				    updated_at           = now()
				WHERE id = $11`,
				giftPlanID, newLimit, newPeriodEnd, newOverageCap,
				giftLegacyRPS, giftLegacyBurst,
				giftReadRPS, giftReadBurst, giftTxRPS, giftTxBurst,
				subID); err != nil {
				return nil, fmt.Errorf("upgrade subscription: %w", err)
			}
		} else {
			action = "extended"
			if _, err := tx.Exec(ctx, `
				UPDATE subscriptions
				SET tokens_limit       = $1,
				    current_period_end = $2,
				    updated_at         = now()
				WHERE id = $3`,
				newLimit, newPeriodEnd, subID); err != nil {
				return nil, fmt.Errorf("extend subscription: %w", err)
			}
		}
	}

	// Mark gift redeemed.
	row = tx.QueryRow(ctx, `
		UPDATE gift_cards
		SET redeemed_at = now(), redeemed_by = $1
		WHERE id = $2
		RETURNING `+giftCardColumns,
		recipientUserID, gift.ID)
	if err := scanGiftCard(row, &gift); err != nil {
		return nil, fmt.Errorf("mark redeemed: %w", err)
	}

	// Re-read subscription with the canonical view.
	row = tx.QueryRow(ctx, `
		SELECT `+subColumns+`
		FROM subscriptions sub
		JOIN plans p ON p.id = sub.plan_id
		WHERE sub.id = $1`, subID)
	if err := scanSubscription(row, &subOut); err != nil {
		return nil, fmt.Errorf("read updated sub: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}

	return &GiftCardRedemption{
		GiftCard:     &gift,
		Subscription: &subOut,
		Action:       action,
		AddedTokens:  addedTokens,
		AddedDays:    addedDays,
	}, nil
}
