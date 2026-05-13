package store

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
)

// IsTenantOAuthRedirectAllowed answers whether the (userID, redirectURI) pair
// exists in tenant_oauth_redirects. The broker's /authorize calls this before
// minting the OAuth state cookie. Comparison is exact — no scheme/case/path
// normalization — because Google/Apple themselves match registered URIs that
// way. If the tenant wants two URIs (e.g. https://app.example/cb and
// https://app.example/cb?source=foo) they must each be inserted as rows.
func (s *pgStore) IsTenantOAuthRedirectAllowed(ctx context.Context, userID, redirectURI string) (bool, error) {
	const q = `SELECT 1 FROM tenant_oauth_redirects WHERE user_id = $1 AND redirect_uri = $2 LIMIT 1`
	var one int
	err := s.pool.QueryRow(ctx, q, userID, redirectURI).Scan(&one)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return false, nil
		}
		return false, fmt.Errorf("query tenant_oauth_redirects: %w", err)
	}
	return true, nil
}
