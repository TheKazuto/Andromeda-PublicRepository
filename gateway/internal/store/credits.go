package store

import (
	"context"
	"time"
)

// defaultCreditTTL is the maximum lifetime of a credit. Per the economy
// decisions: every credit (trial, support, promo, hackathon, partner)
// expires in 30 days from grant. The admin can override to a shorter
// window per grant; longer is rejected at the route layer.
const defaultCreditTTL = 30 * 24 * time.Hour

// MaxCreditTTL bounds how far in the future a credit may expire. Useful
// for the admin endpoint to enforce policy without re-reading config.
const MaxCreditTTL = defaultCreditTTL

// GrantCredit inserts a new credit row. If ExpiresAt is zero or further
// than 30 days, it is clamped to now()+30d.
func (s *pgStore) GrantCredit(ctx context.Context, in CreditGrant) (*Credit, error) {
	if in.UserID == "" {
		return nil, ErrNotFound
	}
	if in.Amount <= 0 {
		return nil, errInvalid("credit amount must be > 0")
	}
	if in.Reason == "" {
		in.Reason = "support"
	}
	if in.GrantedBy == "" {
		in.GrantedBy = "system"
	}
	now := time.Now().UTC()
	exp := in.ExpiresAt
	if exp.IsZero() {
		exp = now.Add(defaultCreditTTL)
	}
	maxExp := now.Add(defaultCreditTTL)
	if exp.After(maxExp) {
		exp = maxExp
	}
	if !exp.After(now) {
		return nil, errInvalid("credit expires_at must be in the future")
	}

	row := s.pool.QueryRow(ctx, `
        INSERT INTO credits (user_id, amount, consumed, reason, granted_by, expires_at)
        VALUES ($1, $2, 0, $3, $4, $5)
        RETURNING id, user_id, amount, consumed, reason, granted_by,
                  expires_at, exhausted_at, created_at`,
		in.UserID, in.Amount, in.Reason, in.GrantedBy, exp)

	var c Credit
	if err := row.Scan(&c.ID, &c.UserID, &c.Amount, &c.Consumed,
		&c.Reason, &c.GrantedBy,
		&c.ExpiresAt, &c.ExhaustedAt, &c.CreatedAt); err != nil {
		return nil, mapErr(err)
	}
	return &c, nil
}

// ListActiveCredits returns credits for the user that are not exhausted
// and not expired, ordered by expiration date ascending (oldest-expiring
// first — consume those before the ones that have more time left).
func (s *pgStore) ListActiveCredits(ctx context.Context, userID string) ([]Credit, error) {
	rows, err := s.pool.Query(ctx, `
        SELECT id, user_id, amount, consumed, reason, granted_by,
               expires_at, exhausted_at, created_at
        FROM credits
        WHERE user_id = $1
          AND exhausted_at IS NULL
          AND expires_at > now()
        ORDER BY expires_at ASC, created_at ASC`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Credit{}
	for rows.Next() {
		var c Credit
		if err := rows.Scan(&c.ID, &c.UserID, &c.Amount, &c.Consumed,
			&c.Reason, &c.GrantedBy,
			&c.ExpiresAt, &c.ExhaustedAt, &c.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// SumActiveCredits returns the total of (amount - consumed) across all
// active credits for the user. Used by GET /v1/me/balance.
func (s *pgStore) SumActiveCredits(ctx context.Context, userID string) (int64, error) {
	var total int64
	err := s.pool.QueryRow(ctx, `
        SELECT COALESCE(SUM(amount - consumed), 0)
        FROM credits
        WHERE user_id = $1
          AND exhausted_at IS NULL
          AND expires_at > now()`, userID).Scan(&total)
	if err != nil {
		return 0, err
	}
	return total, nil
}

// errInvalid wraps a static message as an error. Defined here so the
// satellite files in the package can share it without depending on
// fmt.Errorf at every call site.
type invalidErr struct{ msg string }

func (e invalidErr) Error() string { return e.msg }

func errInvalid(msg string) error { return invalidErr{msg: msg} }
