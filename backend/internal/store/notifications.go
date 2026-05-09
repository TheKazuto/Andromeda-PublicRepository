package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// =============================================================================
// Notification + applier types and interfaces.
//
// Backend's notification workers (quota threshold, pricing change,
// pricing applier) live alongside the BillingStore implementation and
// share the same Postgres pool. The schema is owned by the gateway.
// =============================================================================

// NotificationSubscription is the projection the quota worker iterates.
type NotificationSubscription struct {
	SubscriptionID    string
	UserID            string
	UserEmail         string
	PlanCode          string
	TokensUsed        int64
	OverageUsedTokens int64
	TokensLimit       int64
	PeriodStart       time.Time
	PeriodEnd         time.Time
}

// UsedPercent returns the (used + overage) / limit ratio in [0, ∞)
// percent units. Negative or zero limit returns 0.
func (n NotificationSubscription) UsedPercent() int {
	if n.TokensLimit <= 0 {
		return 0
	}
	total := n.TokensUsed + n.OverageUsedTokens
	pct := (total * 100) / n.TokensLimit
	return int(pct)
}

// NotificationRecipient is the minimal projection the pricing change
// worker uses when fanning out emails.
type NotificationRecipient struct {
	UserID    string
	UserEmail string
}

// PricingChange mirrors gateway's pricing_history row shape.
type PricingChange struct {
	ID                 int64      `json:"id"`
	ChangeType         string     `json:"changeType"`
	TargetKey          string     `json:"targetKey"`
	OldValue           *int64     `json:"oldValue,omitempty"`
	NewValue           int64      `json:"newValue"`
	EffectiveAt        time.Time  `json:"effectiveAt"`
	AppliedAt          *time.Time `json:"appliedAt,omitempty"`
	CancelledAt        *time.Time `json:"cancelledAt,omitempty"`
	NotificationSentAt *time.Time `json:"notificationSentAt,omitempty"`
	CreatedBy          string     `json:"createdBy"`
	Reason             string     `json:"reason"`
	CreatedAt          time.Time  `json:"createdAt"`
}

// AppliedPricingChange describes the result of one pricing-applier tick.
type AppliedPricingChange struct {
	ChangeID   int64
	ChangeType string
	TargetKey  string
	NewValue   int64
	Error      error
}

// NotificationStore is the subset of operations the email + webhook
// workers (quota + pricing) call.
type NotificationStore interface {
	ListActiveSubscriptionsForNotifications(ctx context.Context) ([]NotificationSubscription, error)
	GetPrimaryAPIKeyForUser(ctx context.Context, userID string) (*APIKey, error)
	ListUsersOnPlan(ctx context.Context, planCode string) ([]NotificationRecipient, error)
	MarkThresholdNotified(ctx context.Context, subscriptionID string, periodStart time.Time, thresholdPct int) (bool, error)
	ListPendingPricingChanges(ctx context.Context) ([]PricingChange, error)
	MarkPricingChangeNotified(ctx context.Context, id int64) error
}

// PricingStore is the subset the applier worker calls.
type PricingStore interface {
	ApplyPendingPricingChanges(ctx context.Context) ([]AppliedPricingChange, error)
}

// ----- PostgresStore implementations -----

func (s *PostgresStore) ListActiveSubscriptionsForNotifications(ctx context.Context) ([]NotificationSubscription, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT sub.id, sub.user_id, u.email, p.code,
		       sub.tokens_used, sub.overage_used_tokens,
		       sub.tokens_limit,
		       sub.current_period_start, sub.current_period_end
		FROM subscriptions sub
		JOIN users u ON u.id = sub.user_id
		JOIN plans p ON p.id = sub.plan_id
		WHERE sub.status = 'active'
		  AND sub.tokens_limit > 0`)
	if err != nil {
		return nil, fmt.Errorf("list active subs: %w", err)
	}
	defer rows.Close()
	out := []NotificationSubscription{}
	for rows.Next() {
		var n NotificationSubscription
		if err := rows.Scan(&n.SubscriptionID, &n.UserID, &n.UserEmail, &n.PlanCode,
			&n.TokensUsed, &n.OverageUsedTokens,
			&n.TokensLimit,
			&n.PeriodStart, &n.PeriodEnd); err != nil {
			return nil, err
		}
		out = append(out, n)
	}
	return out, rows.Err()
}

func (s *PostgresStore) GetPrimaryAPIKeyForUser(ctx context.Context, userID string) (*APIKey, error) {
	row := s.pool.QueryRow(ctx, `
		SELECT id, user_id, name, prefix, scopes,
		       created_at, last_used_at, revoked_at
		FROM api_keys
		WHERE user_id = $1 AND revoked_at IS NULL
		ORDER BY last_used_at DESC NULLS LAST, created_at ASC
		LIMIT 1`, userID)
	var k APIKey
	if err := row.Scan(&k.ID, &k.UserID, &k.Name, &k.Prefix, &k.Scopes,
		&k.CreatedAt, &k.LastUsedAt, &k.RevokedAt); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return &k, nil
}

func (s *PostgresStore) ListUsersOnPlan(ctx context.Context, planCode string) ([]NotificationRecipient, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT u.id, u.email
		FROM subscriptions sub
		JOIN users u ON u.id = sub.user_id
		JOIN plans p ON p.id = sub.plan_id
		WHERE sub.status = 'active' AND p.code = $1`, planCode)
	if err != nil {
		return nil, fmt.Errorf("list users on plan %s: %w", planCode, err)
	}
	defer rows.Close()
	out := []NotificationRecipient{}
	for rows.Next() {
		var r NotificationRecipient
		if err := rows.Scan(&r.UserID, &r.UserEmail); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func (s *PostgresStore) MarkThresholdNotified(ctx context.Context, subscriptionID string, periodStart time.Time, thresholdPct int) (bool, error) {
	switch thresholdPct {
	case 80, 95, 100, 200:
	default:
		return false, fmt.Errorf("threshold_pct must be 80, 95, 100 or 200")
	}
	tag, err := s.pool.Exec(ctx, `
		INSERT INTO notification_thresholds
		    (subscription_id, period_start, threshold_pct)
		VALUES ($1, $2, $3)
		ON CONFLICT (subscription_id, period_start, threshold_pct) DO NOTHING`,
		subscriptionID, periodStart, thresholdPct)
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() == 1, nil
}

const pricingChangeColumns = `
	id, change_type, target_key, old_value, new_value,
	effective_at, applied_at, cancelled_at, notification_sent_at,
	created_by, reason, created_at`

func scanPricingChange(row pgx.Row, p *PricingChange) error {
	return row.Scan(
		&p.ID, &p.ChangeType, &p.TargetKey, &p.OldValue, &p.NewValue,
		&p.EffectiveAt, &p.AppliedAt, &p.CancelledAt, &p.NotificationSentAt,
		&p.CreatedBy, &p.Reason, &p.CreatedAt,
	)
}

func (s *PostgresStore) ListPendingPricingChanges(ctx context.Context) ([]PricingChange, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT `+pricingChangeColumns+`
		 FROM pricing_history
		 WHERE applied_at IS NULL AND cancelled_at IS NULL
		 ORDER BY effective_at ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []PricingChange{}
	for rows.Next() {
		var p PricingChange
		if err := scanPricingChange(rows, &p); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

func (s *PostgresStore) MarkPricingChangeNotified(ctx context.Context, id int64) error {
	tag, err := s.pool.Exec(ctx, `
		UPDATE pricing_history
		SET notification_sent_at = now()
		WHERE id = $1 AND notification_sent_at IS NULL`, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// ApplyPendingPricingChanges applies every scheduled change whose
// effective_at has arrived. Each change runs in its own tx so a
// failure on one row does not block the rest. Returns per-change
// outcomes for the worker to log.
func (s *PostgresStore) ApplyPendingPricingChanges(ctx context.Context) ([]AppliedPricingChange, error) {
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
		applyErr := s.applyOnePricingChange(ctx, p.id, p.changeType, p.target, p.newValue)
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

func (s *PostgresStore) applyOnePricingChange(ctx context.Context, id int64, changeType, target string, newValue int64) error {
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
		return errors.New("pricing change already applied or cancelled")
	}
	return tx.Commit(ctx)
}

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
