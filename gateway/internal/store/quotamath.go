package store

import "time"

// This file holds the *pure* arithmetic behind ConsumeTokensV2 — no DB, no
// clock. Keeping it isolated makes the bucket-allocation and period-rollover
// logic exhaustively unit-testable; consume.go does the locking/IO and applies
// what these functions decide.

// creditBucket is the math-only view of one `credits` row.
type creditBucket struct {
	id       string
	amount   int64
	consumed int64
}

// creditUpdate is the new state ConsumeTokensV2 must persist for a touched
// credit row.
type creditUpdate struct {
	id          string
	newConsumed int64
	exhausted   bool
}

// drainPlan is the decision allocateConsumption returned: how `cost` was
// split, the per-row credit updates to apply, and the CreditDebit records
// for a future refund.
type drainPlan struct {
	fromCredits   int
	fromMonthly   int
	fromOverage   int
	creditUpdates []creditUpdate
	creditDebits  []CreditDebit
}

// allocateConsumption decides how `cost` tokens are charged across the
// consumption order credits → monthly → overage, given the current counters.
//
// `credits` must already be ordered oldest-expiring-first — this function
// drains them in slice order. Overage is only tapped when overageEnabled &&
// cardPresent and the cap can cover the shortfall; otherwise ErrQuotaExceeded.
//
// Pure: no IO. Negative `monthlyAvail` (used already past limit) and zero-
// availability credit rows are treated as "no budget here, move on".
func allocateConsumption(
	cost int,
	credits []creditBucket,
	used, limit, overageUsed, overageCap int64,
	overageEnabled, cardPresent bool,
) (drainPlan, error) {
	if cost <= 0 {
		return drainPlan{}, errInvalid("cost must be > 0")
	}

	remaining := int64(cost)
	var plan drainPlan

	// credits — oldest first
	for _, cr := range credits {
		if remaining == 0 {
			break
		}
		avail := cr.amount - cr.consumed
		if avail <= 0 {
			continue
		}
		take := avail
		if remaining < take {
			take = remaining
		}
		newConsumed := cr.consumed + take
		plan.fromCredits += int(take)
		remaining -= take
		plan.creditDebits = append(plan.creditDebits, CreditDebit{CreditID: cr.id, Amount: take})
		plan.creditUpdates = append(plan.creditUpdates, creditUpdate{
			id:          cr.id,
			newConsumed: newConsumed,
			exhausted:   newConsumed >= cr.amount,
		})
	}

	// monthly
	if remaining > 0 {
		if monthlyAvail := limit - used; monthlyAvail > 0 {
			take := monthlyAvail
			if remaining < take {
				take = remaining
			}
			plan.fromMonthly = int(take)
			remaining -= take
		}
	}

	// overage — opt-in + card only
	if remaining > 0 {
		if !overageEnabled || !cardPresent {
			return drainPlan{}, ErrQuotaExceeded
		}
		if overageCap-overageUsed < remaining {
			return drainPlan{}, ErrQuotaExceeded
		}
		plan.fromOverage = int(remaining)
		remaining = 0
	}

	return plan, nil
}

// crossedThresholds reports which monthly-limit percentages the combined
// (monthly + overage) usage crossed on this charge — true only on the FIRST
// crossing (totalOld below, totalNew at-or-above). limit <= 0 → all false.
func crossedThresholds(limit, totalOld, totalNew int64) (c80, c95, c100, c200 bool) {
	if limit <= 0 {
		return
	}
	at := func(pct int64) bool {
		thr := (limit * pct) / 100
		return totalOld < thr && totalNew >= thr
	}
	return at(80), at(95), at(100), at(200)
}

// rollPeriod advances an expired billing window past `now`. `expiredEnd` is
// the current_period_end that has already passed; `annual` picks the step
// size. It returns the new [start, end) pair (end is always > now). It does
// not check whether the period actually expired — callers do that first.
func rollPeriod(expiredEnd time.Time, annual bool, now time.Time) (start, end time.Time) {
	step := nextPeriodEnd
	if annual {
		step = annualPeriodEnd
	}
	start = expiredEnd
	end = step(start)
	for !now.Before(end) {
		start = end
		end = step(start)
	}
	return start, end
}
