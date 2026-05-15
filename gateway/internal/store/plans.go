package store

import (
	"context"
	"encoding/json"
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

