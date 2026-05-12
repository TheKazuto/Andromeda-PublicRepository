package store

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
)

// plans persistence + the plan scanner. Split out of postgres.go.

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
