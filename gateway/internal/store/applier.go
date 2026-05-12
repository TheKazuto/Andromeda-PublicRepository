package store

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"
)

// ApplyPendingPricingChanges runs one tick of the pricing applier:
//  1. Fetches every pricing_history row whose effective_at has arrived
//     and which has not been applied or cancelled.
//  2. For each, copies new_value into the live table (request_costs
//     for route_cost, plans for plan_*).
//  3. Stamps applied_at on the pricing_history row.
//
// Each change runs in its own transaction so a failure on one does not
// block the rest. Returns a slice of outcomes (one per change) so the
// caller can log / alert on partial failures.
//
// Idempotent: a change already applied will not re-apply (the WHERE
// clause filters applied_at IS NULL). Safe to call from a periodic
// worker every minute.
func (s *pgStore) ApplyPendingPricingChanges(ctx context.Context) ([]AppliedPricingChange, error) {
	rows, err := s.pool.Query(ctx, `
        SELECT id, change_type, target_key, new_value
        FROM pricing_history
        WHERE applied_at IS NULL
          AND cancelled_at IS NULL
          AND effective_at <= now()
        ORDER BY effective_at ASC, id ASC`)
	if err != nil {
		return nil, fmt.Errorf("list due pricing changes: %w", err)
	}
	type pending struct {
		id         int64
		changeType string
		target     string
		newValue   int64
	}
	var due []pending
	for rows.Next() {
		var p pending
		if err := rows.Scan(&p.id, &p.changeType, &p.target, &p.newValue); err != nil {
			rows.Close()
			return nil, err
		}
		due = append(due, p)
	}
	rows.Close()

	out := make([]AppliedPricingChange, 0, len(due))
	for _, p := range due {
		applyErr := s.applyOne(ctx, p.id, p.changeType, p.target, p.newValue)
		out = append(out, AppliedPricingChange{
			ChangeID:   p.id,
			ChangeType: p.changeType,
			TargetKey:  p.target,
			NewValue:   p.newValue,
			Error:      applyErr,
		})
	}
	return out, nil
}

// applyOne runs a single change in its own transaction. Updates the live
// table first; only on success marks pricing_history.applied_at.
func (s *pgStore) applyOne(ctx context.Context, id int64, changeType, target string, newValue int64) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	switch changeType {
	case "route_cost":
		if _, err := tx.Exec(ctx, `
            INSERT INTO request_costs (route_key, cost_tokens, description, updated_at)
            VALUES ($1, $2, '', now())
            ON CONFLICT (route_key) DO UPDATE
            SET cost_tokens = EXCLUDED.cost_tokens,
                updated_at  = now()`, target, newValue); err != nil {
			return fmt.Errorf("update request_costs: %w", err)
		}
	case "plan_price":
		if err := updatePlanColumn(ctx, tx, target, "price_cents", newValue); err != nil {
			return err
		}
	case "plan_annual_price":
		if err := updatePlanColumn(ctx, tx, target, "annual_price_cents", newValue); err != nil {
			return err
		}
	case "plan_tokens":
		if err := updatePlanColumn(ctx, tx, target, "monthly_tokens", newValue); err != nil {
			return err
		}
	case "plan_read_rps":
		if err := updatePlanColumn(ctx, tx, target, "read_rps", newValue); err != nil {
			return err
		}
	case "plan_tx_rps":
		if err := updatePlanColumn(ctx, tx, target, "tx_rps", newValue); err != nil {
			return err
		}
	case "plan_overage":
		if err := updatePlanColumn(ctx, tx, target, "overage_per_1k_cents", newValue); err != nil {
			return err
		}
	default:
		return fmt.Errorf("unknown change_type: %s", changeType)
	}

	tag, err := tx.Exec(ctx, `
        UPDATE pricing_history
        SET applied_at = now()
        WHERE id = $1 AND applied_at IS NULL AND cancelled_at IS NULL`, id)
	if err != nil {
		return fmt.Errorf("mark applied: %w", err)
	}
	if tag.RowsAffected() == 0 {
		// Concurrent applier or cancellation — abort silently.
		return ErrPricingChangeBusy
	}

	return tx.Commit(ctx)
}

// updatePlanColumn writes `value` into the named column of the plan
// identified by `code`. The column name is constructed from a fixed
// allowlist in applyOne, so it is safe to interpolate here.
func updatePlanColumn(ctx context.Context, tx pgx.Tx, code, column string, value int64) error {
	q := fmt.Sprintf(`UPDATE plans SET %s = $2, updated_at = now() WHERE code = $1`, column)
	tag, err := tx.Exec(ctx, q, code, value)
	if err != nil {
		return fmt.Errorf("update plans.%s: %w", column, err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("plan %q not found", code)
	}
	return nil
}
