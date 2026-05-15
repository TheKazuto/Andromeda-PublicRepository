package store

import (
	"context"
	"fmt"
	"strings"
	"time"
)

// API keys + users persistence. Split out of postgres.go; the pgStore
// receiver, migration runner and shared scanners live there.

func (s *pgStore) AuthenticateAPIKey(ctx context.Context, hashedKey string) (*AuthenticatedKey, error) {
	q := `
        SELECT
            u.id, u.email, u.name, u.created_at,
            k.id, k.user_id, k.name, k.prefix, k.scopes,
            COALESCE(k.ip_allowlist, '{}'::text[]),
            COALESCE(k.allowed_origins, '{}'::text[]),
            k.created_at, k.last_used_at, k.revoked_at,
            ` + subscriptionColumns + `
        FROM api_keys k
        JOIN users u ON u.id = k.user_id
        LEFT JOIN subscriptions sub
               ON sub.user_id = u.id AND sub.status = 'active'
        LEFT JOIN plans p ON p.id = sub.plan_id
        WHERE k.hashed_key = $1
        LIMIT 1`

	var (
		u    User
		k    APIKey
		sub  Subscription
		hasS bool
	)

	row := s.pool.QueryRow(ctx, q, hashedKey)
	// Scan into staging pointers so we can detect NULL on the subscription
	// side (LEFT JOIN may produce NULLs across the entire sub.* slice).
	var (
		subID, subUserID, planID, planCode, status, cycle     *string
		ps, pe, sCreatedAt, sUpdatedAt, overageLastReportedAt *time.Time
		used, limit, overageUsed, overageCap, overageReported *int64
		rps, burst, readRPS, readBurst, txRPS, txBurst        *int
		overageEnabled, overageCardPresent                    *bool
		stripeCustomerID, stripeSubscriptionID                *string
		stripeOverageItemID                                   *string
	)
	err := row.Scan(
		&u.ID, &u.Email, &u.Name, &u.CreatedAt,
		&k.ID, &k.UserID, &k.Name, &k.Prefix, &k.Scopes,
		&k.IPAllowlist,
		&k.AllowedOrigins,
		&k.CreatedAt, &k.LastUsedAt, &k.RevokedAt,
		&subID, &subUserID, &planID, &planCode, &status, &cycle,
		&ps, &pe,
		&used, &limit,
		&overageEnabled, &overageCardPresent,
		&overageUsed, &overageCap,
		&overageReported, &overageLastReportedAt,
		&rps, &burst,
		&readRPS, &readBurst, &txRPS, &txBurst,
		&stripeCustomerID, &stripeSubscriptionID,
		&stripeOverageItemID,
		&sCreatedAt, &sUpdatedAt,
	)
	if err != nil {
		return nil, mapErr(err)
	}
	if k.RevokedAt != nil {
		return nil, ErrKeyRevoked
	}

	if subID != nil {
		hasS = true
		sub.ID = derefStr(subID)
		sub.UserID = u.ID
		sub.PlanID = derefStr(planID)
		sub.PlanCode = derefStr(planCode)
		sub.Status = derefStr(status)
		sub.BillingCycle = derefStr(cycle)
		sub.CurrentPeriodStart = derefTime(ps)
		sub.CurrentPeriodEnd = derefTime(pe)
		sub.TokensUsed = derefInt64(used)
		sub.TokensLimit = derefInt64(limit)
		sub.OverageEnabled = derefBool(overageEnabled)
		sub.OverageCardPresent = derefBool(overageCardPresent)
		sub.OverageUsedTokens = derefInt64(overageUsed)
		sub.OverageCapTokens = derefInt64(overageCap)
		sub.OverageReportedTokens = derefInt64(overageReported)
		sub.OverageLastReportedAt = overageLastReportedAt
		sub.RateLimitRPS = derefInt(rps)
		sub.RateLimitBurst = derefInt(burst)
		sub.ReadRPS = derefInt(readRPS)
		sub.ReadBurst = derefInt(readBurst)
		sub.TxRPS = derefInt(txRPS)
		sub.TxBurst = derefInt(txBurst)
		sub.StripeCustomerID = derefStr(stripeCustomerID)
		sub.StripeSubscriptionID = derefStr(stripeSubscriptionID)
		sub.StripeOverageItemID = derefStr(stripeOverageItemID)
		sub.CreatedAt = derefTime(sCreatedAt)
		sub.UpdatedAt = derefTime(sUpdatedAt)
	}

	out := &AuthenticatedKey{User: &u, APIKey: &k}
	if hasS {
		out.Subscription = &sub
	}
	return out, nil
}

func (s *pgStore) TouchAPIKeyUsed(ctx context.Context, apiKeyID string) error {
	_, err := s.pool.Exec(ctx,
		`UPDATE api_keys SET last_used_at = now() WHERE id = $1`, apiKeyID)
	return err
}

// ---------- users / keys / subscriptions ----------

func (s *pgStore) CreateUser(ctx context.Context, u *User) error {
	if u.ID == "" {
		return fmt.Errorf("user id required")
	}
	_, err := s.pool.Exec(ctx, `
        INSERT INTO users (id, email, name, created_at)
        VALUES ($1, $2, $3, COALESCE($4, now()))`,
		u.ID, u.Email, u.Name, nullableTime(u.CreatedAt))
	if err != nil && strings.Contains(err.Error(), "duplicate key") {
		return ErrAlreadyExists
	}
	return err
}

func (s *pgStore) GetUserByEmail(ctx context.Context, email string) (*User, error) {
	row := s.pool.QueryRow(ctx,
		`SELECT id, email, name, COALESCE(stripe_customer_id, ''), created_at
         FROM users WHERE email = $1`, email)
	var u User
	if err := row.Scan(&u.ID, &u.Email, &u.Name, &u.StripeCustomerID, &u.CreatedAt); err != nil {
		return nil, mapErr(err)
	}
	return &u, nil
}

func (s *pgStore) CreateAPIKey(ctx context.Context, k *APIKey) error {
	if k.ID == "" || k.UserID == "" {
		return fmt.Errorf("api key id and user id required")
	}
	if k.IPAllowlist == nil {
		k.IPAllowlist = []string{}
	}
	if k.AllowedOrigins == nil {
		k.AllowedOrigins = []string{}
	}
	_, err := s.pool.Exec(ctx, `
        INSERT INTO api_keys (id, user_id, name, prefix, hashed_key, scopes, ip_allowlist, allowed_origins, created_at)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, COALESCE($9, now()))`,
		k.ID, k.UserID, k.Name, k.Prefix, k.HashedKey, k.Scopes, k.IPAllowlist, k.AllowedOrigins, nullableTime(k.CreatedAt))
	if err != nil && strings.Contains(err.Error(), "duplicate key") {
		return ErrAlreadyExists
	}
	return err
}

func (s *pgStore) ListAPIKeysByUser(ctx context.Context, userID string) ([]APIKey, error) {
	rows, err := s.pool.Query(ctx, `
        SELECT id, user_id, name, prefix, scopes,
               COALESCE(ip_allowlist, '{}'::text[]),
               COALESCE(allowed_origins, '{}'::text[]),
               created_at, last_used_at, revoked_at
        FROM api_keys WHERE user_id = $1 ORDER BY created_at DESC`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []APIKey{}
	for rows.Next() {
		var k APIKey
		if err := rows.Scan(&k.ID, &k.UserID, &k.Name, &k.Prefix, &k.Scopes,
			&k.IPAllowlist,
			&k.AllowedOrigins,
			&k.CreatedAt, &k.LastUsedAt, &k.RevokedAt); err != nil {
			return nil, err
		}
		out = append(out, k)
	}
	return out, rows.Err()
}

func (s *pgStore) RevokeAPIKey(ctx context.Context, userID, keyID string) error {
	tag, err := s.pool.Exec(ctx, `
        UPDATE api_keys SET revoked_at = now()
        WHERE id = $1 AND user_id = $2 AND revoked_at IS NULL`, keyID, userID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}
