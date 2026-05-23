package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// ConsumeTokensV2 charges `cost` tokens following the consumption order:
//
//	credits  → monthly  → overage
//
// The whole operation runs in a single ReadCommitted transaction with
// FOR UPDATE locks on:
//
//   - the subscription row (so concurrent calls serialise per user)
//   - each active credit row touched (so the row's `consumed` is correct)
//
// Period rollover happens in-line if `current_period_end` has passed:
// the subscription is reset with a fresh limit/buckets pulled from the
// associated plan, and `current_period_start/end` advance.
//
// Errors:
//
//   - ErrQuotaExceeded — buckets combined cannot cover `cost`. Includes
//     the case where overage is needed but disabled / no card on file.
//   - ErrNotFound      — subscription does not exist or is not active.
func (s *pgStore) ConsumeTokensV2(ctx context.Context, subscriptionID string, cost int, opID string) (*ConsumptionResult, error) {
	if cost <= 0 {
		return nil, errInvalid("cost must be > 0")
	}
	// An empty opID means the caller cannot offer cross-retry idempotency
	// (no Idempotency-Key, no request id). Mint a unique one so the ledger
	// row is still written but every call is treated as distinct — i.e. the
	// pre-ledger behaviour, never an accidental no-op dedup against "".
	if opID == "" {
		opID = uuid.NewString()
	}

	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	// 1. Lock subscription. We need the user_id to consume credits.
	var (
		userID                      string
		periodStart, periodEnd      time.Time
		used, limit                 int64
		overageUsed, overageCap     int64
		overageEnabled, cardPresent bool
		planID, billingCycle        string
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

	// 1b. Ledger idempotency gate. Claim this op_id as a charge; on conflict
	//     the charge already ran, so replay the stored breakdown without
	//     debiting again. The subscription FOR UPDATE lock above serialises
	//     concurrent calls with the same op_id through this point.
	var ledgerID int64
	err = tx.QueryRow(ctx, `
        INSERT INTO token_ledger (op_id, kind, subscription_id, cost)
        VALUES ($1, 'charge', $2, $3)
        ON CONFLICT (op_id, kind) DO NOTHING
        RETURNING id`, opID, subscriptionID, cost).Scan(&ledgerID)
	if errors.Is(err, pgx.ErrNoRows) {
		return s.replayLedgerCharge(ctx, tx, subscriptionID, opID)
	}
	if err != nil {
		return nil, err
	}

	// 2. Period rollover.
	now := time.Now().UTC()
	if !now.Before(periodEnd) {
		var (
			newLimit                 int64
			newRPS, newBurst         int
			newReadRPS, newReadBurst int
			newTxRPS, newTxBurst     int
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
		newStart, newEnd := rollPeriod(periodEnd, billingCycle == "annual", now)
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

	// 3. Read the active credit rows (oldest-expiring first, locked) then let
	//    the pure allocator decide the credits → monthly → overage split.
	//    The arithmetic lives in allocateConsumption (see quotamath.go).
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
	var buckets []creditBucket
	for creditRows.Next() {
		var b creditBucket
		if err := creditRows.Scan(&b.id, &b.amount, &b.consumed); err != nil {
			creditRows.Close()
			return nil, err
		}
		buckets = append(buckets, b)
	}
	creditRows.Close()
	if err := creditRows.Err(); err != nil {
		return nil, err
	}

	plan, err := allocateConsumption(cost, buckets, used, limit, overageUsed, overageCap, overageEnabled, cardPresent)
	if err != nil {
		return nil, err // ErrQuotaExceeded (buckets can't cover) or errInvalid
	}

	// 4a. Persist the touched credit rows.
	for _, cu := range plan.creditUpdates {
		var exhaustedAt any
		if cu.exhausted {
			exhaustedAt = time.Now().UTC()
		}
		if _, err := tx.Exec(ctx, `
            UPDATE credits SET consumed = $2, exhausted_at = $3 WHERE id = $1`,
			cu.id, cu.newConsumed, exhaustedAt); err != nil {
			return nil, err
		}
	}

	// 4b. Apply monthly + overage to the subscription counters.
	if plan.fromMonthly > 0 || plan.fromOverage > 0 {
		if _, err := tx.Exec(ctx, `
            UPDATE subscriptions
            SET tokens_used         = tokens_used + $2,
                overage_used_tokens = overage_used_tokens + $3,
                updated_at          = now()
            WHERE id = $1`, subscriptionID, plan.fromMonthly, plan.fromOverage); err != nil {
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

	// 6. Build the result + threshold crossings against (monthly + overage)
	//    usage over the monthly limit (200% == the overage hard cap).
	res := &ConsumptionResult{
		Cost:         cost,
		FromCredits:  plan.fromCredits,
		FromMonthly:  plan.fromMonthly,
		FromOverage:  plan.fromOverage,
		TokensUsed:   sub.TokensUsed,
		OverageUsed:  sub.OverageUsedTokens,
		Subscription: &sub,
		CreditDebits: plan.creditDebits,
	}
	totalNew := sub.TokensUsed + sub.OverageUsedTokens
	totalOld := totalNew - int64(plan.fromMonthly+plan.fromOverage)
	res.Crossed80Pct, res.Crossed95Pct, res.Crossed100Pct, res.Crossed200Pct =
		crossedThresholds(sub.TokensLimit, totalOld, totalNew)

	// 7. Record the breakdown on the ledger row so a later refund can clamp
	//    to exactly what this op consumed and a replay can return it verbatim.
	//    Subscription is json:"-" so it is naturally excluded from the snapshot.
	breakdown, err := json.Marshal(res)
	if err != nil {
		return nil, fmt.Errorf("marshal ledger breakdown: %w", err)
	}
	if _, err := tx.Exec(ctx,
		`UPDATE token_ledger SET breakdown = $2 WHERE id = $1`, ledgerID, breakdown); err != nil {
		return nil, err
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return res, nil
}

// RefundTokensV2 reverses a prior consumption. Refunds happen per
// bucket using the breakdown captured in ConsumptionResult:
//
//   - Monthly + overage: decrement the subscription counters.
//   - Credits: walk r.CreditDebits and undo each row's `consumed`
//     amount, also clearing exhausted_at when the row no longer
//     sums to its full amount.
//
// All updates run in a single transaction so a partial refund cannot
// leave the user with inconsistent counters.
func (s *pgStore) RefundTokensV2(ctx context.Context, subscriptionID string, r ConsumptionResult, opID string) error {
	if r.FromMonthly == 0 && r.FromOverage == 0 && len(r.CreditDebits) == 0 {
		return nil
	}

	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	// Ledger idempotency + clamp. With an opID, claim the refund exactly once
	// (a conflict means it was already refunded — no-op) and clamp the amounts
	// to what the matching charge actually consumed, so a buggy or replayed
	// caller can never refund more than was taken.
	if opID != "" {
		var refundID int64
		err = tx.QueryRow(ctx, `
            INSERT INTO token_ledger (op_id, kind, subscription_id, cost)
            VALUES ($1, 'refund', $2, $3)
            ON CONFLICT (op_id, kind) DO NOTHING
            RETURNING id`, opID, subscriptionID, r.Cost).Scan(&refundID)
		if errors.Is(err, pgx.ErrNoRows) {
			return tx.Commit(ctx) // already refunded — idempotent no-op
		}
		if err != nil {
			return err
		}
		r = s.clampRefundToCharge(ctx, tx, subscriptionID, opID, r)
		if r.FromMonthly == 0 && r.FromOverage == 0 && len(r.CreditDebits) == 0 {
			return tx.Commit(ctx) // nothing left to give back after clamping
		}
	}

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

// replayLedgerCharge returns the stored breakdown for an already-charged
// op_id without debiting again. Called inside ConsumeTokensV2's transaction
// when the charge ledger insert hit a conflict; it commits the transaction.
func (s *pgStore) replayLedgerCharge(ctx context.Context, tx pgx.Tx, subscriptionID, opID string) (*ConsumptionResult, error) {
	var breakdown []byte
	if err := tx.QueryRow(ctx,
		`SELECT breakdown FROM token_ledger WHERE op_id = $1 AND kind = 'charge' AND subscription_id = $2`,
		opID, subscriptionID).Scan(&breakdown); err != nil {
		return nil, err
	}
	res := &ConsumptionResult{}
	if len(breakdown) > 0 {
		if err := json.Unmarshal(breakdown, res); err != nil {
			return nil, fmt.Errorf("decode ledger breakdown: %w", err)
		}
	}
	// Refresh the subscription so counters/limit reflect the present, and a
	// replay never re-reports a threshold crossing (those fire only on the
	// first charge that crosses).
	subRow := tx.QueryRow(ctx, `
        SELECT `+subscriptionColumns+`
        FROM subscriptions sub
        JOIN plans p ON p.id = sub.plan_id
        WHERE sub.id = $1`, subscriptionID)
	var sub Subscription
	if err := scanSubscription(subRow, &sub); err != nil {
		return nil, err
	}
	res.Subscription = &sub
	res.TokensUsed = sub.TokensUsed
	res.OverageUsed = sub.OverageUsedTokens
	res.Crossed80Pct, res.Crossed95Pct, res.Crossed100Pct, res.Crossed200Pct = false, false, false, false
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return res, nil
}

// clampRefundToCharge limits each bucket of r to what the matching charge
// (same op_id) actually consumed. With no charge breakdown on record it
// returns r unchanged — the per-row GREATEST(...,0) in the UPDATEs is the
// final safety net either way.
func (s *pgStore) clampRefundToCharge(ctx context.Context, tx pgx.Tx, subscriptionID, opID string, r ConsumptionResult) ConsumptionResult {
	var breakdown []byte
	if err := tx.QueryRow(ctx,
		`SELECT breakdown FROM token_ledger WHERE op_id = $1 AND kind = 'charge' AND subscription_id = $2`,
		opID, subscriptionID).Scan(&breakdown); err != nil || len(breakdown) == 0 {
		return r
	}
	var charge ConsumptionResult
	if err := json.Unmarshal(breakdown, &charge); err != nil {
		return r
	}
	if r.FromMonthly > charge.FromMonthly {
		r.FromMonthly = charge.FromMonthly
	}
	if r.FromOverage > charge.FromOverage {
		r.FromOverage = charge.FromOverage
	}
	chargedByCredit := make(map[string]int64, len(charge.CreditDebits))
	for _, d := range charge.CreditDebits {
		chargedByCredit[d.CreditID] += d.Amount
	}
	clamped := make([]CreditDebit, 0, len(r.CreditDebits))
	for _, d := range r.CreditDebits {
		amt := d.Amount
		if max := chargedByCredit[d.CreditID]; amt > max {
			amt = max
		}
		if amt > 0 {
			clamped = append(clamped, CreditDebit{CreditID: d.CreditID, Amount: amt})
		}
	}
	r.CreditDebits = clamped
	return r
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
