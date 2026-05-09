package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// =============================================================================
// Failed-login lockout
// =============================================================================

// IncrementUserFailedLogin bumps users.failed_login_attempts and sets
// users.locked_until when the attempt count crosses lockThreshold. The
// transition is done atomically inside a single UPDATE so two concurrent
// failed logins never race on the threshold.
func (s *PostgresStore) IncrementUserFailedLogin(ctx context.Context, userID string, lockThreshold int, lockDuration time.Duration) error {
	if userID == "" {
		return nil
	}
	_, err := s.pool.Exec(ctx, `
		UPDATE users
		SET failed_login_attempts = failed_login_attempts + 1,
		    locked_until = CASE
		      WHEN failed_login_attempts + 1 >= $2 THEN now() + ($3::int * interval '1 second')
		      ELSE locked_until
		    END
		WHERE id = $1
	`, userID, lockThreshold, int(lockDuration.Seconds()))
	if err != nil {
		return fmt.Errorf("increment failed login: %w", err)
	}
	return nil
}

// ResetUserFailedLogin zeroes the counter and clears the lock — called on
// any successful login.
func (s *PostgresStore) ResetUserFailedLogin(ctx context.Context, userID string) error {
	if userID == "" {
		return nil
	}
	_, err := s.pool.Exec(ctx, `
		UPDATE users
		SET failed_login_attempts = 0, locked_until = NULL
		WHERE id = $1
	`, userID)
	if err != nil {
		return fmt.Errorf("reset failed login: %w", err)
	}
	return nil
}

// IsUserLocked reports whether the user is currently locked. When an expired
// lock is found we proactively clear it so the next login can proceed.
func (s *PostgresStore) IsUserLocked(ctx context.Context, userID string) (bool, *time.Time, error) {
	if userID == "" {
		return false, nil, nil
	}
	var lockedUntil *time.Time
	err := s.pool.QueryRow(ctx, `
		SELECT locked_until FROM users WHERE id = $1
	`, userID).Scan(&lockedUntil)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil, nil
	}
	if err != nil {
		return false, nil, fmt.Errorf("lookup user lock: %w", err)
	}
	if lockedUntil == nil {
		return false, nil, nil
	}
	if lockedUntil.After(time.Now().UTC()) {
		return true, lockedUntil, nil
	}
	// Lock expired — clear it on the way out so the next attempt can proceed.
	_, _ = s.pool.Exec(ctx, `
		UPDATE users
		SET failed_login_attempts = 0, locked_until = NULL
		WHERE id = $1
	`, userID)
	return false, nil, nil
}

// =============================================================================
// Admin lockout (same pattern as users; separate columns on admin_users)
// =============================================================================

func (s *PostgresStore) IncrementAdminFailedLogin(ctx context.Context, adminID string, lockThreshold int, lockDuration time.Duration) error {
	if adminID == "" {
		return nil
	}
	_, err := s.pool.Exec(ctx, `
		UPDATE admin_users
		SET failed_login_attempts = failed_login_attempts + 1,
		    locked_until = CASE
		      WHEN failed_login_attempts + 1 >= $2 THEN now() + ($3::int * interval '1 second')
		      ELSE locked_until
		    END
		WHERE id = $1
	`, adminID, lockThreshold, int(lockDuration.Seconds()))
	if err != nil {
		return fmt.Errorf("increment admin failed login: %w", err)
	}
	return nil
}

func (s *PostgresStore) ResetAdminFailedLogin(ctx context.Context, adminID string) error {
	if adminID == "" {
		return nil
	}
	_, err := s.pool.Exec(ctx, `
		UPDATE admin_users
		SET failed_login_attempts = 0, locked_until = NULL
		WHERE id = $1
	`, adminID)
	if err != nil {
		return fmt.Errorf("reset admin failed login: %w", err)
	}
	return nil
}

func (s *PostgresStore) IsAdminLocked(ctx context.Context, adminID string) (bool, *time.Time, error) {
	if adminID == "" {
		return false, nil, nil
	}
	var lockedUntil *time.Time
	err := s.pool.QueryRow(ctx, `
		SELECT locked_until FROM admin_users WHERE id = $1
	`, adminID).Scan(&lockedUntil)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil, nil
	}
	if err != nil {
		return false, nil, fmt.Errorf("lookup admin lock: %w", err)
	}
	if lockedUntil == nil {
		return false, nil, nil
	}
	if lockedUntil.After(time.Now().UTC()) {
		return true, lockedUntil, nil
	}
	_, _ = s.pool.Exec(ctx, `
		UPDATE admin_users
		SET failed_login_attempts = 0, locked_until = NULL
		WHERE id = $1
	`, adminID)
	return false, nil, nil
}

// =============================================================================
// Refresh tokens
// =============================================================================

func (s *PostgresStore) CreateRefreshToken(ctx context.Context, in RefreshTokenIssue) (string, error) {
	if in.IssuedAt.IsZero() {
		in.IssuedAt = time.Now().UTC()
	}
	row := s.pool.QueryRow(ctx, `
		INSERT INTO refresh_tokens (user_id, token_hash, issued_at, expires_at, user_agent, ip)
		VALUES ($1, $2, $3, $4, $5, $6)
		RETURNING id
	`, in.UserID, in.TokenHash, in.IssuedAt, in.ExpiresAt, nullable(in.UserAgent), nullable(in.IP))
	var id string
	if err := row.Scan(&id); err != nil {
		return "", fmt.Errorf("insert refresh token: %w", err)
	}
	return id, nil
}

// RotateRefreshToken creates the child refresh token and consumes the parent
// in a single transaction. If parentID was already consumed, the child insert
// is rolled back and ErrNotFound is returned.
func (s *PostgresStore) RotateRefreshToken(ctx context.Context, parentID string, in RefreshTokenIssue) (string, error) {
	if parentID == "" {
		return "", ErrNotFound
	}
	if in.IssuedAt.IsZero() {
		in.IssuedAt = time.Now().UTC()
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return "", fmt.Errorf("begin refresh rotation: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var id string
	if err := tx.QueryRow(ctx, `
		INSERT INTO refresh_tokens (user_id, token_hash, issued_at, expires_at, user_agent, ip)
		VALUES ($1, $2, $3, $4, $5, $6)
		RETURNING id
	`, in.UserID, in.TokenHash, in.IssuedAt, in.ExpiresAt, nullable(in.UserAgent), nullable(in.IP)).Scan(&id); err != nil {
		return "", fmt.Errorf("insert rotated refresh token: %w", err)
	}

	tag, err := tx.Exec(ctx, `
		UPDATE refresh_tokens
		SET revoked_at = now(), replaced_by = $2
		WHERE id = $1 AND revoked_at IS NULL
	`, parentID, id)
	if err != nil {
		return "", fmt.Errorf("consume parent refresh token: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return "", ErrNotFound
	}
	if err := tx.Commit(ctx); err != nil {
		return "", fmt.Errorf("commit refresh rotation: %w", err)
	}
	return id, nil
}

func (s *PostgresStore) GetRefreshTokenByHash(ctx context.Context, hash string) (*RefreshTokenRow, error) {
	row := s.pool.QueryRow(ctx, `
		SELECT id, user_id, issued_at, expires_at, revoked_at, replaced_by
		FROM refresh_tokens WHERE token_hash = $1
	`, hash)
	var r RefreshTokenRow
	if err := row.Scan(&r.ID, &r.UserID, &r.IssuedAt, &r.ExpiresAt, &r.RevokedAt, &r.ReplacedBy); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("get refresh token: %w", err)
	}
	return &r, nil
}

// ConsumeRefreshToken atomically marks the supplied token as revoked and
// records the child token id (replacedByID) that replaces it. The atomic
// `WHERE revoked_at IS NULL` guarantees single-use semantics — a second
// call with the same id will affect zero rows.
func (s *PostgresStore) ConsumeRefreshToken(ctx context.Context, id, replacedByID string) error {
	tag, err := s.pool.Exec(ctx, `
		UPDATE refresh_tokens
		SET revoked_at = now(), replaced_by = $2
		WHERE id = $1 AND revoked_at IS NULL
	`, id, nullable(replacedByID))
	if err != nil {
		return fmt.Errorf("consume refresh token: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// RevokeRefreshTokensByUser revokes every active refresh token for a user.
// Called from /v1/auth/logout when the operator wants to sign out
// everywhere, and as part of password change flows.
func (s *PostgresStore) RevokeRefreshTokensByUser(ctx context.Context, userID string) error {
	_, err := s.pool.Exec(ctx, `
		UPDATE refresh_tokens
		SET revoked_at = now()
		WHERE user_id = $1 AND revoked_at IS NULL
	`, userID)
	if err != nil {
		return fmt.Errorf("revoke refresh tokens: %w", err)
	}
	return nil
}

// RevokeRefreshTokenFamily walks the replaced_by chain forward from startID
// and revokes every descendant. Called when the auth layer detects reuse
// of an already-consumed token (a strong signal the cookie was stolen).
func (s *PostgresStore) RevokeRefreshTokenFamily(ctx context.Context, startID string) error {
	_, err := s.pool.Exec(ctx, `
		WITH RECURSIVE chain AS (
			SELECT id, replaced_by FROM refresh_tokens WHERE id = $1
			UNION ALL
			SELECT r.id, r.replaced_by
			FROM refresh_tokens r
			JOIN chain c ON r.id = c.replaced_by
		)
		UPDATE refresh_tokens
		SET revoked_at = COALESCE(revoked_at, now())
		WHERE id IN (SELECT id FROM chain)
	`, startID)
	if err != nil {
		return fmt.Errorf("revoke refresh family: %w", err)
	}
	return nil
}

// =============================================================================
// Password reset tokens
// =============================================================================

func (s *PostgresStore) CreatePasswordResetToken(ctx context.Context, in PasswordResetIssue) error {
	if in.IssuedAt.IsZero() {
		in.IssuedAt = time.Now().UTC()
	}
	_, err := s.pool.Exec(ctx, `
		INSERT INTO password_reset_tokens (user_id, token_hash, issued_at, expires_at)
		VALUES ($1, $2, $3, $4)
	`, in.UserID, in.TokenHash, in.IssuedAt, in.ExpiresAt)
	if err != nil {
		return fmt.Errorf("insert password reset token: %w", err)
	}
	return nil
}

// ConsumePasswordResetToken validates and marks-used in a single SQL
// statement so two concurrent /v1/auth/reset-password calls cannot both
// succeed (TOCTOU defense).
func (s *PostgresStore) ConsumePasswordResetToken(ctx context.Context, hash string) (string, error) {
	row := s.pool.QueryRow(ctx, `
		UPDATE password_reset_tokens
		SET used_at = now()
		WHERE token_hash = $1
		  AND used_at IS NULL
		  AND expires_at > now()
		RETURNING user_id
	`, hash)
	var userID string
	if err := row.Scan(&userID); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return "", ErrNotFound
		}
		return "", fmt.Errorf("consume password reset: %w", err)
	}
	return userID, nil
}

// nullable converts an empty string to a NULL pgx value so empty defaults
// do not pollute the column.
func nullable(s string) any {
	if s == "" {
		return nil
	}
	return s
}
