package store

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// ConsumeTokensV2 charges `cost` tokens following the consumption order:
//
//   credits  → monthly  → overage
//
// The whole operation runs in a single ReadCommitted transaction with
// FOR UPDATE locks on:
//
//   * the subscription row (so concurrent calls serialise per user)
//   * each active credit row touched (so the row's `consumed` is correct)
//
// Period rollover happens in-line if `current_period_end` has passed:
// the subscription is reset with a fresh limit/buckets pulled from the
// associated plan, and `current_period_start/end` advance.
//
// Errors:
//
//   * ErrQuotaExceeded — buckets combined cannot cover `cost`. Includes
//     the case where overage is needed but disabled / no card on file.
//   * ErrNotFound      — subscription does not exist or is not active.
func (s *pgStore) ConsumeTokensV2(ctx context.Context, subscriptionID string, cost int) (*ConsumptionResult, error) {
	if cost <= 0 {
		return nil, errInvalid("cost must be > 0")
	}

	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	// 1. Lock subscription. We need the user_id to consume credits.
	var (
		userID                                   string
		periodStart, periodEnd                   time.Time
		used, limit                              int64
		overageUsed, overageCap                  int64
		overageEnabled, cardPresent              bool
		planID, billingCycle                     string
	)
	err = tx.QueryRow(ctx, `
        SELECT user_id, current_period_start, current_period_end,
               tokens_used, tokens_limit,
               overage_used_tokens, overage_cap_tokens,
               overage_enabled, overage_card_present,
               plan_id, billing_cycle
        FROM subscriptions
        WHERE id = $1 AND status = 'active'
        FOR UPDATE`, subscriptionID).
		Scan(&userID, &periodStart, &periodEnd,
			&used, &limit, &overageUsed, &overageCap,
			&overageEnabled, &cardPresent,
			&planID, &billingCycle)
	if err != nil {
		return nil, mapErr(err)
	}

	// 2. Period rollover.
	now := time.Now().UTC()
	if !now.Before(periodEnd) {
		var (
			newLimit                           int64
			newRPS, newBurst                   int
			newReadRPS, newReadBurst           int
			newTxRPS, newTxBurst               int
		)
		err = tx.QueryRow(ctx, `
            SELECT monthly_tokens, rate_limit_rps, rate_limit_burst,
                   read_rps, read_burst, tx_rps, tx_burst
            FROM plans WHERE id = $1`, planID).
			Scan(&newLimit, &newRPS, &newBurst,
				&newReadRPS, &newReadBurst, &newTxRPS, &newTxBurst)
		if err != nil {
			return nil, fmt.Errorf("load plan on rollover: %w", err)
		}
		newStart := periodEnd
		var newEnd time.Time
		if billingCycle == "annual" {
			newEnd = annualPeriodEnd(newStart)
		} else {
			newEnd = nextPeriodEnd(newStart)
		}
		for !now.Before(newEnd) {
			newStart = newEnd
			if billingCycle == "annual" {
				newEnd = annualPeriodEnd(newStart)
			} else {
				newEnd = nextPeriodEnd(newStart)
			}
		}
		newOverageCap := newLimit * 2

		if _, err := tx.Exec(ctx, `
            UPDATE subscriptions
            SET current_period_start = $1,
                current_period_end   = $2,
                tokens_used          = 0,
                tokens_limit         = $3,
                overage_used_tokens  = 0,
                overage_cap_tokens   = $4,
                rate_limit_rps       = $5,
                rate_limit_burst     = $6,
                read_rps             = $7,
                read_burst           = $8,
                tx_rps               = $9,
                tx_burst             = $10,
                updated_at           = now()
            WHERE id = $11`,
			newStart, newEnd, newLimit, newOverageCap,
			newRPS, newBurst, newReadRPS, newReadBurst, newTxRPS, newTxBurst,
			subscriptionID); err != nil {
			return nil, err
		}
		used = 0
		limit = newLimit
		overageUsed = 0
		overageCap = newOverageCap
		periodStart = newStart
		periodEnd = newEnd
	}

	remaining := cost
	var fromCredits, fromMonthly, fromOverage int
	var creditDebitsCaptured []CreditDebit

	// 3a. Credits — oldest-expiring first, locked.
	if remaining > 0 {
		creditRows, err := tx.Query(ctx, `
            SELECT id, amount, consumed
            FROM credits
            WHERE user_id = $1
              AND exhausted_at IS NULL
              AND expires_at > now()
            ORDER BY expires_at ASC, created_at ASC
            FOR UPDATE`, userID)
		if err != nil {
			return nil, err
		}
		type creditRow struct {
			id                string
			amount, consumed  int64
		}
		var credits []creditRow
		for creditRows.Next() {
			var cr creditRow
			if err := creditRows.Scan(&cr.id, &cr.amount, &cr.consumed); err != nil {
				creditRows.Close()
				return nil, err
			}
			credits = append(credits, cr)
		}
		creditRows.Close()

		var debits []CreditDebit
		for _, cr := range credits {
			if remaining == 0 {
				break
			}
			avail := cr.amount - cr.consumed
			if avail <= 0 {
				continue
			}
			take := avail
			if int64(remaining) < take {
				take = int64(remaining)
			}
			newConsumed := cr.consumed + take
			var exhaustedAt any
			if newConsumed >= cr.amount {
				exhaustedAt = time.Now().UTC()
			} else {
				exhaustedAt = nil
			}
			if _, err := tx.Exec(ctx, `
                UPDATE credits
                SET consumed = $2, exhausted_at = $3
                WHERE id = $1`, cr.id, newConsumed, exhaustedAt); err != nil {
				return nil, err
			}
			fromCredits += int(take)
			remaining -= int(take)
			debits = append(debits, CreditDebit{CreditID: cr.id, Amount: take})
		}
		// Stash debits on the result so RefundTokensV2 can reverse them
		// per-row. Done outside the loop so a partial drain still records.
		// We assign back into the outer scope via the closure capture.
		creditDebitsCaptured = debits
	}

	// 3b. Monthly.
	if remaining > 0 {
		monthlyAvail := limit - used
		if monthlyAvail > 0 {
			take := monthlyAvail
			if int64(remaining) < take {
				take = int64(remaining)
			}
			fromMonthly = int(take)
			remaining -= int(take)
		}
	}

	// 3c. Overage — only when card + opt-in.
	if remaining > 0 {
		if !overageEnabled || !cardPresent {
			return nil, ErrQuotaExceeded
		}
		overageAvail := overageCap - overageUsed
		if overageAvail < int64(remaining) {
			return nil, ErrQuotaExceeded
		}
		fromOverage = remaining
		remaining = 0
	}

	// 4. Apply monthly + overage updates to the subscription. Credits
	//    were already updated in their own UPDATEs above.
	if fromMonthly > 0 || fromOverage > 0 {
		if _, err := tx.Exec(ctx, `
            UPDATE subscriptions
            SET tokens_used         = tokens_used + $2,
                overage_used_tokens = overage_used_tokens + $3,
                updated_at          = now()
            WHERE id = $1`, subscriptionID, fromMonthly, fromOverage); err != nil {
			return nil, err
		}
	}

	// 5. Re-read the subscription so the result reflects post-update state.
	subRow := tx.QueryRow(ctx, `
        SELECT `+subscriptionColumns+`
        FROM subscriptions sub
        JOIN plans p ON p.id = sub.plan_id
        WHERE sub.id = $1`, subscriptionID)
	var sub Subscription
	if err := scanSubscription(subRow, &sub); err != nil {
		return nil, err
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}

	// 6. Compute threshold crossings against (monthly + overage) usage
	//    over the monthly limit. The 200% threshold corresponds to the
	//    overage hard cap.
	res := &ConsumptionResult{
		Cost:         cost,
		FromCredits:  fromCredits,
		FromMonthly:  fromMonthly,
		FromOverage:  fromOverage,
		TokensUsed:   sub.TokensUsed,
		OverageUsed:  sub.OverageUsedTokens,
		Subscription: &sub,
		CreditDebits: creditDebitsCaptured,
	}
	totalNew := sub.TokensUsed + sub.OverageUsedTokens
	totalOld := totalNew - int64(fromMonthly+fromOverage)
	if sub.TokensLimit > 0 {
		check := func(pct int) bool {
			thr := (sub.TokensLimit * int64(pct)) / 100
			return totalOld < thr && totalNew >= thr
		}
		res.Crossed80Pct = check(80)
		res.Crossed95Pct = check(95)
		res.Crossed100Pct = check(100)
		res.Crossed200Pct = check(200)
	}
	return res, nil
}

// RefundTokensV2 reverses a prior consumption. Refunds happen per
// bucket using the breakdown captured in ConsumptionResult:
//
//   * Monthly + overage: decrement the subscription counters.
//   * Credits: walk r.CreditDebits and undo each row's `consumed`
//     amount, also clearing exhausted_at when the row no longer
//     sums to its full amount.
//
// All updates run in a single transaction so a partial refund cannot
// leave the user with inconsistent counters.
func (s *pgStore) RefundTokensV2(ctx context.Context, subscriptionID string, r ConsumptionResult) error {
	if r.FromMonthly == 0 && r.FromOverage == 0 && len(r.CreditDebits) == 0 {
		return nil
	}

	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if r.FromMonthly > 0 || r.FromOverage > 0 {
		if _, err := tx.Exec(ctx, `
            UPDATE subscriptions
            SET tokens_used         = GREATEST(tokens_used - $2, 0),
                overage_used_tokens = GREATEST(overage_used_tokens - $3, 0),
                updated_at          = now()
            WHERE id = $1`, subscriptionID, r.FromMonthly, r.FromOverage); err != nil {
			return err
		}
	}

	for _, d := range r.CreditDebits {
		if d.Amount <= 0 || d.CreditID == "" {
			continue
		}
		// Decrement consumed; if the new total is below the credit's
		// original amount, clear exhausted_at so the credit becomes
		// active again. The CASE expression guards against double-
		// refund: GREATEST clamps to 0.
		if _, err := tx.Exec(ctx, `
            UPDATE credits
            SET consumed     = GREATEST(consumed - $2, 0),
                exhausted_at = CASE
                                  WHEN GREATEST(consumed - $2, 0) < amount THEN NULL
                                  ELSE exhausted_at
                               END
            WHERE id = $1`, d.CreditID, d.Amount); err != nil {
			return err
		}
	}

	return tx.Commit(ctx)
}

// ComputeBalance returns the per-bucket remaining-token snapshot for a
// user. Safe to call for users with no active subscription — the result
// will have Subscription == nil and only Credits populated.
func (s *pgStore) ComputeBalance(ctx context.Context, userID string) (*Balance, error) {
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
	case isNotFound(err):
		// User has no active subscription — credits-only balance is fine.
	default:
		return nil, fmt.Errorf("load subscription: %w", err)
	}

	out.TotalRemaining = out.Credits + out.MonthlyRemaining + out.OverageAvailable
	return out, nil
}

func isNotFound(err error) bool {
	return err == ErrNotFound
}
