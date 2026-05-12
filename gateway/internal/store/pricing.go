package store

import "context"

// request_costs (route-key pricing) persistence. Split out of postgres.go.

func (s *pgStore) ListRequestCosts(ctx context.Context) ([]RequestCost, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT route_key, cost_tokens, description, updated_at FROM request_costs`)
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

func (s *pgStore) UpsertRequestCost(ctx context.Context, c RequestCost) error {
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
