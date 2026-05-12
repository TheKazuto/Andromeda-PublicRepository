package store

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

// GiftRefundWindow is the maximum age, after creation, during which a
// paid gift card may be refunded. Once redeemed, refund is forbidden.
const GiftRefundWindow = 7 * 24 * time.Hour

// GiftCardTTL is how long a gift card stays redeemable from purchase /
// grant. After this, it auto-expires.
const GiftCardTTL = 365 * 24 * time.Hour // 12 months

const giftCardColumns = `
    id, redeem_token, plan_code, duration_months, source,
    buyer_user_id, COALESCE(buyer_email, ''), paid_amount_cents,
    COALESCE(stripe_payment_id, ''), COALESCE(granted_by, ''),
    message, expires_at, redeemed_at, redeemed_by, refunded_at, created_at`

func scanGiftCard(row scanner, g *GiftCard) error {
	return row.Scan(
		&g.ID, &g.RedeemToken, &g.PlanCode, &g.DurationMonths, &g.Source,
		&g.BuyerUserID, &g.BuyerEmail, &g.PaidAmountCents,
		&g.StripePaymentID, &g.GrantedBy,
		&g.Message, &g.ExpiresAt, &g.RedeemedAt, &g.RedeemedBy, &g.RefundedAt, &g.CreatedAt,
	)
}

// CreateGiftCard inserts a paid or promo gift card and returns it. The
// caller is responsible for generating the redeem_token (see auth/giftkey
// helpers in the API layer).
func (s *pgStore) CreateGiftCard(ctx context.Context, in GiftCardCreate) (*GiftCard, error) {
	if in.RedeemToken == "" {
		return nil, errInvalid("redeem_token required")
	}
	if in.PlanCode == "" {
		return nil, errInvalid("plan_code required")
	}
	if in.DurationMonths != 1 && in.DurationMonths != 12 {
		return nil, errInvalid("duration_months must be 1 or 12")
	}
	switch in.Source {
	case "paid":
		if in.PaidAmountCents == nil || *in.PaidAmountCents <= 0 {
			return nil, errInvalid("paid_amount_cents required for source=paid")
		}
	case "promo":
		if strings.TrimSpace(in.GrantedBy) == "" {
			return nil, errInvalid("granted_by required for source=promo")
		}
	default:
		return nil, errInvalid("source must be 'paid' or 'promo'")
	}
	if in.ExpiresAt.IsZero() {
		in.ExpiresAt = time.Now().UTC().Add(GiftCardTTL)
	}

	row := s.pool.QueryRow(ctx, `
        INSERT INTO gift_cards
            (redeem_token, plan_code, duration_months, source,
             buyer_user_id, buyer_email, paid_amount_cents, stripe_payment_id,
             granted_by, message, expires_at)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
        RETURNING `+giftCardColumns,
		in.RedeemToken, in.PlanCode, in.DurationMonths, in.Source,
		in.BuyerUserID, nullableStr(in.BuyerEmail), in.PaidAmountCents, nullableStr(in.StripePaymentID),
		nullableStr(in.GrantedBy), in.Message, in.ExpiresAt)

	var g GiftCard
	if err := scanGiftCard(row, &g); err != nil {
		if strings.Contains(err.Error(), "duplicate key") {
			return nil, ErrAlreadyExists
		}
		return nil, mapErr(err)
	}
	return &g, nil
}

func (s *pgStore) GetGiftCardByToken(ctx context.Context, token string) (*GiftCard, error) {
	row := s.pool.QueryRow(ctx,
		`SELECT `+giftCardColumns+` FROM gift_cards WHERE redeem_token = $1`, token)
	var g GiftCard
	if err := scanGiftCard(row, &g); err != nil {
		return nil, mapErr(err)
	}
	return &g, nil
}

func (s *pgStore) ListGiftCardsByBuyer(ctx context.Context, userID string) ([]GiftCard, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT `+giftCardColumns+`
         FROM gift_cards WHERE buyer_user_id = $1
         ORDER BY created_at DESC`, userID)
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

func (s *pgStore) ListGiftCardsByRecipient(ctx context.Context, userID string) ([]GiftCard, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT `+giftCardColumns+`
         FROM gift_cards WHERE redeemed_by = $1
         ORDER BY redeemed_at DESC NULLS LAST, created_at DESC`, userID)
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

// RedeemGiftCard atomically marks a card as redeemed by the recipient
// IF AND ONLY IF it is not already redeemed, refunded or expired.
//
// The caller is responsible for the side effect of granting the plan to
// the recipient (extend / upgrade / etc) — that decision lives in the
// API layer. This function only flips the persistent state.
func (s *pgStore) RedeemGiftCard(ctx context.Context, token, recipientUserID string) (*GiftCard, error) {
	if token == "" || recipientUserID == "" {
		return nil, ErrNotFound
	}

	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	// SELECT FOR UPDATE so concurrent redeem attempts on the same token
	// serialise; the second one will fall through the guards below.
	row := tx.QueryRow(ctx,
		`SELECT `+giftCardColumns+`
         FROM gift_cards WHERE redeem_token = $1
         FOR UPDATE`, token)
	var g GiftCard
	if err := scanGiftCard(row, &g); err != nil {
		return nil, mapErr(err)
	}
	now := time.Now().UTC()
	if g.RedeemedAt != nil {
		return nil, ErrGiftAlreadyUsed
	}
	if g.RefundedAt != nil {
		return nil, ErrGiftRefunded
	}
	if !now.Before(g.ExpiresAt) {
		return nil, ErrGiftExpired
	}

	row = tx.QueryRow(ctx, `
        UPDATE gift_cards
        SET redeemed_at = now(), redeemed_by = $1
        WHERE id = $2
        RETURNING `+giftCardColumns,
		recipientUserID, g.ID)
	if err := scanGiftCard(row, &g); err != nil {
		return nil, mapErr(err)
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return &g, nil
}

// RefundGiftCard reverses a paid gift card. Only allowed for paid cards
// that are still within the GiftRefundWindow and have not been redeemed.
// Promo cards have no refund (no money was charged to begin with).
func (s *pgStore) RefundGiftCard(ctx context.Context, id string) (*GiftCard, error) {
	if id == "" {
		return nil, ErrNotFound
	}

	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	row := tx.QueryRow(ctx,
		`SELECT `+giftCardColumns+`
         FROM gift_cards WHERE id = $1
         FOR UPDATE`, id)
	var g GiftCard
	if err := scanGiftCard(row, &g); err != nil {
		return nil, mapErr(err)
	}
	if g.Source != "paid" {
		return nil, ErrGiftNotEligible
	}
	if g.RedeemedAt != nil {
		return nil, ErrGiftAlreadyUsed
	}
	if g.RefundedAt != nil {
		return nil, ErrGiftRefunded
	}
	if time.Since(g.CreatedAt) > GiftRefundWindow {
		return nil, ErrGiftNotEligible
	}

	row = tx.QueryRow(ctx, `
        UPDATE gift_cards SET refunded_at = now()
        WHERE id = $1
        RETURNING `+giftCardColumns, id)
	if err := scanGiftCard(row, &g); err != nil {
		return nil, mapErr(err)
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return &g, nil
}

func nullableStr(s string) any {
	if s == "" {
		return nil
	}
	return s
}

// ApplyGiftCard atomically redeems a gift card AND applies its plan to
// the recipient's subscription. Three outcomes:
//
//   - No active subscription → create one with the gift's plan + duration.
//   - Active subscription, current plan tier <= gift plan tier → extend
//     period_end by the gift's duration AND bump tokens_limit by the
//     gift's contribution. If gift's plan is strictly higher tier, also
//     swap the plan + RPS limits (Action="upgraded"); otherwise just
//     extend (Action="extended").
//   - Active subscription, current plan tier > gift plan tier → still
//     extend (don't downgrade). Action="extended".
//
// "Tier" is defined by plans.sort_order. Equal sort_order is treated as
// equal (no upgrade).
func (s *pgStore) ApplyGiftCard(ctx context.Context, token, recipientUserID string) (*GiftCardRedemption, error) {
	if token == "" || recipientUserID == "" {
		return nil, ErrNotFound
	}

	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	// 1. Lock and validate the gift card.
	row := tx.QueryRow(ctx,
		`SELECT `+giftCardColumns+`
         FROM gift_cards WHERE redeem_token = $1
         FOR UPDATE`, token)
	var gift GiftCard
	if err := scanGiftCard(row, &gift); err != nil {
		return nil, mapErr(err)
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

	// 2. Resolve the gift's plan (snapshot of monthly_tokens, RPS, etc).
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
		return nil, fmt.Errorf("load gift plan: %w", mapErr(err))
	}

	addedTokens := giftMonthly * int64(gift.DurationMonths)
	addedDays := gift.DurationMonths * 30 // approx; period_end uses month math below

	// 3. Lock the recipient's active subscription (if any).
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
		// Case A: create fresh subscription.
		action = "created"
		periodStart := now
		periodEnd := periodStart.AddDate(0, gift.DurationMonths, 0)
		overageCap := giftMonthly * 2

		var newSubID string
		err = tx.QueryRow(ctx, `
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
			giftReadRPS, giftReadBurst, giftTxRPS, giftTxBurst).Scan(&newSubID)
		if err != nil {
			return nil, fmt.Errorf("create sub from gift: %w", err)
		}
		subID = newSubID

	case err != nil:
		return nil, fmt.Errorf("lock subscription: %w", err)

	default:
		// Case B/C: subscription exists. Compare tiers and decide upgrade.
		var (
			currentPlanID      string
			currentPlanCode    string
			currentSortOrder   int
			currentTokensLimit int64
			currentPeriodEnd   time.Time
			currentOverageCap  int64
		)
		err = tx.QueryRow(ctx, `
            SELECT sub.plan_id, p.code, p.sort_order,
                   sub.tokens_limit, sub.current_period_end, sub.overage_cap_tokens
            FROM subscriptions sub
            JOIN plans p ON p.id = sub.plan_id
            WHERE sub.id = $1`, subID).
			Scan(&currentPlanID, &currentPlanCode, &currentSortOrder,
				&currentTokensLimit, &currentPeriodEnd, &currentOverageCap)
		if err != nil {
			return nil, fmt.Errorf("read current sub: %w", err)
		}

		newLimit := currentTokensLimit + addedTokens
		newPeriodEnd := currentPeriodEnd.AddDate(0, gift.DurationMonths, 0)

		shouldUpgrade := giftSortOrder > currentSortOrder
		if shouldUpgrade {
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

	// 4. Mark the gift as redeemed.
	row = tx.QueryRow(ctx, `
        UPDATE gift_cards
        SET redeemed_at = now(), redeemed_by = $1
        WHERE id = $2
        RETURNING `+giftCardColumns,
		recipientUserID, gift.ID)
	if err := scanGiftCard(row, &gift); err != nil {
		return nil, fmt.Errorf("mark redeemed: %w", err)
	}

	// 5. Re-read subscription with the canonical view.
	row = tx.QueryRow(ctx, `
        SELECT `+subscriptionColumns+`
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
