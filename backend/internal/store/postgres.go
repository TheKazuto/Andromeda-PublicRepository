package store

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// PostgresStore is the durable implementation of Store backed by Postgres.
// Schema is owned by `migrations/*.sql`; this file only issues CRUD queries.
type PostgresStore struct {
	pool *pgxpool.Pool
}

// NewPostgres opens a pgx pool against databaseURL and verifies connectivity
// with a ping. Caller is responsible for running migrations beforehand.
//
// Pool sizing knobs (env, all optional):
//
//	PG_MAX_CONNS              — pool ceiling (default 10)
//	PG_MIN_CONNS              — warm idle pool (default 1)
//	PG_HEALTH_CHECK_SEC       — pgxpool health-check period (default 30)
//	PG_CONN_MAX_LIFETIME_SEC  — max age of any conn (default 3600)
//	PG_CONN_MAX_IDLE_SEC      — kill idle conns after N seconds (default 600)
//	PG_STATEMENT_TIMEOUT_MS   — `statement_timeout` per session (default 30000)
//	PG_IDLE_IN_TX_TIMEOUT_MS  — `idle_in_transaction_session_timeout` (default 60000)
//	PG_STATEMENT_CACHE_MODE   — set to 'describe' under PgBouncer tx-pool mode
func NewPostgres(ctx context.Context, databaseURL string) (*PostgresStore, error) {
	cfg, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		return nil, fmt.Errorf("parse DATABASE_URL: %w", err)
	}
	cfg.MaxConns = int32(envInt("PG_MAX_CONNS", 10))
	cfg.MinConns = int32(envInt("PG_MIN_CONNS", 1))
	cfg.HealthCheckPeriod = time.Duration(envInt("PG_HEALTH_CHECK_SEC", 30)) * time.Second
	cfg.MaxConnLifetime = time.Duration(envInt("PG_CONN_MAX_LIFETIME_SEC", 3600)) * time.Second
	cfg.MaxConnIdleTime = time.Duration(envInt("PG_CONN_MAX_IDLE_SEC", 600)) * time.Second

	if mode := strings.TrimSpace(os.Getenv("PG_STATEMENT_CACHE_MODE")); mode != "" {
		switch mode {
		case "describe":
			cfg.ConnConfig.DefaultQueryExecMode = pgx.QueryExecModeDescribeExec
		case "exec":
			cfg.ConnConfig.DefaultQueryExecMode = pgx.QueryExecModeExec
		case "simple_protocol":
			cfg.ConnConfig.DefaultQueryExecMode = pgx.QueryExecModeSimpleProtocol
		case "cache_describe":
			cfg.ConnConfig.DefaultQueryExecMode = pgx.QueryExecModeCacheDescribe
		case "prepare", "cache_statement":
			cfg.ConnConfig.DefaultQueryExecMode = pgx.QueryExecModeCacheStatement
		}
	}

	stmtTimeoutMS := envInt("PG_STATEMENT_TIMEOUT_MS", 30_000)
	idleTxTimeoutMS := envInt("PG_IDLE_IN_TX_TIMEOUT_MS", 60_000)
	cfg.AfterConnect = func(ctx context.Context, conn *pgx.Conn) error {
		if stmtTimeoutMS > 0 {
			if _, err := conn.Exec(ctx, fmt.Sprintf("SET statement_timeout = %d", stmtTimeoutMS)); err != nil {
				return fmt.Errorf("set statement_timeout: %w", err)
			}
		}
		if idleTxTimeoutMS > 0 {
			if _, err := conn.Exec(ctx, fmt.Sprintf("SET idle_in_transaction_session_timeout = %d", idleTxTimeoutMS)); err != nil {
				return fmt.Errorf("set idle_in_transaction_session_timeout: %w", err)
			}
		}
		return nil
	}

	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("create pg pool: %w", err)
	}
	pingCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := pool.Ping(pingCtx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("ping pg: %w", err)
	}
	return &PostgresStore{pool: pool}, nil
}

func (s *PostgresStore) Close() error {
	s.pool.Close()
	return nil
}

// Pool exposes the underlying pgxpool. Used by satellite packages
// (webhooks publisher) that need raw access without dragging in
// the full Store interface.
func (s *PostgresStore) Pool() *pgxpool.Pool { return s.pool }

// ----- USERS -----

func (s *PostgresStore) CreateUser(ctx context.Context, u *User) error {
	if u.CreatedAt.IsZero() {
		u.CreatedAt = time.Now().UTC()
	}
	_, err := s.pool.Exec(ctx, `
		INSERT INTO users (id, email, name, password_hash, plan, created_at)
		VALUES ($1, $2, $3, $4, $5, $6)
	`, u.ID, u.Email, u.Name, u.PasswordHash, u.Plan, u.CreatedAt)
	if err != nil {
		if isUniqueViolation(err) {
			return ErrAlreadyExists
		}
		return fmt.Errorf("insert user: %w", err)
	}
	return nil
}

func (s *PostgresStore) GetUserByID(ctx context.Context, id string) (*User, error) {
	return s.queryUser(ctx, `
		SELECT id, email, name, password_hash, plan, created_at, deleted_at
		FROM users WHERE id = $1 AND deleted_at IS NULL
	`, id)
}

func (s *PostgresStore) GetUserByEmail(ctx context.Context, email string) (*User, error) {
	return s.queryUser(ctx, `
		SELECT id, email, name, password_hash, plan, created_at, deleted_at
		FROM users WHERE email = $1 AND deleted_at IS NULL
	`, email)
}

func (s *PostgresStore) GetUserByProvider(ctx context.Context, provider, subject string) (*User, error) {
	return s.queryUser(ctx, `
		SELECT u.id, u.email, u.name, u.password_hash, u.plan, u.created_at, u.deleted_at
		FROM users u
		JOIN user_oauth_links l ON l.user_id = u.id
		WHERE l.provider = $1 AND l.subject = $2 AND u.deleted_at IS NULL
	`, strings.ToLower(provider), subject)
}

func (s *PostgresStore) LinkProvider(ctx context.Context, userID, provider, subject string) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var existingUser string
	err = tx.QueryRow(ctx, `
		SELECT user_id FROM user_oauth_links WHERE provider = $1 AND subject = $2
	`, strings.ToLower(provider), subject).Scan(&existingUser)
	if err == nil {
		if existingUser == userID {
			return tx.Commit(ctx)
		}
		return ErrAlreadyExists
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return fmt.Errorf("lookup link: %w", err)
	}

	var n int
	if err := tx.QueryRow(ctx, `SELECT 1 FROM users WHERE id = $1`, userID).Scan(&n); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		return fmt.Errorf("lookup user: %w", err)
	}

	_, err = tx.Exec(ctx, `
		INSERT INTO user_oauth_links (user_id, provider, subject, created_at)
		VALUES ($1, $2, $3, $4)
	`, userID, strings.ToLower(provider), subject, time.Now().UTC())
	if err != nil {
		if isUniqueViolation(err) {
			return ErrAlreadyExists
		}
		return fmt.Errorf("insert link: %w", err)
	}
	return tx.Commit(ctx)
}

func (s *PostgresStore) UpdateUser(ctx context.Context, id string, mutate func(*User)) (*User, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	row := tx.QueryRow(ctx, `
		SELECT id, email, name, password_hash, plan, created_at, deleted_at
		FROM users WHERE id = $1 AND deleted_at IS NULL FOR UPDATE
	`, id)
	u, err := scanUser(row)
	if err != nil {
		return nil, err
	}
	mutate(u)

	if _, err := tx.Exec(ctx, `
		UPDATE users SET email = $2, name = $3, password_hash = $4, plan = $5
		WHERE id = $1
	`, u.ID, u.Email, u.Name, u.PasswordHash, u.Plan); err != nil {
		return nil, fmt.Errorf("update user: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("commit: %w", err)
	}
	return u, nil
}

func (s *PostgresStore) UpdateUserPassword(ctx context.Context, id, newHash string) error {
	tag, err := s.pool.Exec(ctx, `
		UPDATE users SET password_hash = $2
		WHERE id = $1 AND deleted_at IS NULL
	`, id, newHash)
	if err != nil {
		return fmt.Errorf("update password: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// SoftDeleteUser anonymizes the user, drops oauth links, revokes keys,
// and stamps deleted_at — all in one transaction. Idempotent: a second
// call on an already-deleted user returns nil without changes.
func (s *PostgresStore) SoftDeleteUser(ctx context.Context, id string) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var deletedAt *time.Time
	err = tx.QueryRow(ctx, `SELECT deleted_at FROM users WHERE id = $1 FOR UPDATE`, id).Scan(&deletedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		return fmt.Errorf("lookup user: %w", err)
	}
	if deletedAt != nil {
		return nil // idempotent
	}

	now := time.Now().UTC()
	anonymized := "__deleted__:" + id

	if _, err := tx.Exec(ctx, `
		UPDATE users
		SET email = $2, name = '', password_hash = '', deleted_at = $3
		WHERE id = $1
	`, id, anonymized, now); err != nil {
		return fmt.Errorf("anonymize user: %w", err)
	}

	if _, err := tx.Exec(ctx, `DELETE FROM user_oauth_links WHERE user_id = $1`, id); err != nil {
		return fmt.Errorf("drop oauth links: %w", err)
	}

	if _, err := tx.Exec(ctx, `
		UPDATE api_keys SET revoked_at = $2
		WHERE user_id = $1 AND revoked_at IS NULL
	`, id, now); err != nil {
		return fmt.Errorf("revoke keys: %w", err)
	}

	// Burn every live session and password-reset token so the deleted
	// account cannot be authenticated against under any code path.
	if _, err := tx.Exec(ctx, `
		UPDATE refresh_tokens SET revoked_at = $2
		WHERE user_id = $1 AND revoked_at IS NULL
	`, id, now); err != nil {
		return fmt.Errorf("revoke refresh tokens: %w", err)
	}
	if _, err := tx.Exec(ctx, `
		DELETE FROM password_reset_tokens WHERE user_id = $1
	`, id); err != nil {
		return fmt.Errorf("drop password reset tokens: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit: %w", err)
	}
	return nil
}

// ----- API KEYS -----

func (s *PostgresStore) CreateAPIKey(ctx context.Context, k *APIKey) error {
	if k.CreatedAt.IsZero() {
		k.CreatedAt = time.Now().UTC()
	}
	ipAllowlist := k.IPAllowlist
	if ipAllowlist == nil {
		ipAllowlist = []string{}
	}
	originAllowlist := k.AllowedOrigins
	if originAllowlist == nil {
		originAllowlist = []string{}
	}
	_, err := s.pool.Exec(ctx, `
		INSERT INTO api_keys (id, user_id, name, prefix, hashed_key, scopes, ip_allowlist, allowed_origins, created_at, last_used_at, revoked_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
	`, k.ID, k.UserID, k.Name, k.Prefix, k.HashedKey, k.Scopes, ipAllowlist, originAllowlist, k.CreatedAt, k.LastUsedAt, k.RevokedAt)
	if err != nil {
		return fmt.Errorf("insert api_key: %w", err)
	}
	return nil
}

func (s *PostgresStore) ListAPIKeysByUser(ctx context.Context, userID string) ([]*APIKey, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, user_id, name, prefix, hashed_key, scopes,
		       COALESCE(ip_allowlist, '{}'::text[]),
		       COALESCE(allowed_origins, '{}'::text[]),
		       created_at, last_used_at, revoked_at
		FROM api_keys WHERE user_id = $1 ORDER BY created_at DESC
	`, userID)
	if err != nil {
		return nil, fmt.Errorf("list api_keys: %w", err)
	}
	defer rows.Close()

	out := []*APIKey{}
	for rows.Next() {
		k := &APIKey{}
		if err := rows.Scan(&k.ID, &k.UserID, &k.Name, &k.Prefix, &k.HashedKey, &k.Scopes, &k.IPAllowlist, &k.AllowedOrigins, &k.CreatedAt, &k.LastUsedAt, &k.RevokedAt); err != nil {
			return nil, fmt.Errorf("scan api_key: %w", err)
		}
		out = append(out, k)
	}
	return out, rows.Err()
}

// UpdateAPIKey is implemented in admin_economy.go (shared by admin and user
// flows; both go through APIKeyMutation).

func (s *PostgresStore) RevokeAPIKey(ctx context.Context, userID, id string) error {
	now := time.Now().UTC()
	tag, err := s.pool.Exec(ctx, `
		UPDATE api_keys SET revoked_at = $3
		WHERE id = $1 AND user_id = $2 AND revoked_at IS NULL
	`, id, userID, now)
	if err != nil {
		return fmt.Errorf("revoke api_key: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *PostgresStore) RevokeAllAPIKeysByUser(ctx context.Context, userID string) error {
	now := time.Now().UTC()
	if _, err := s.pool.Exec(ctx, `
		UPDATE api_keys SET revoked_at = $2
		WHERE user_id = $1 AND revoked_at IS NULL
	`, userID, now); err != nil {
		return fmt.Errorf("revoke all api_keys: %w", err)
	}
	return nil
}

// ----- TENANT OAUTH REDIRECTS (Login Social broker allowlist) -----

func (s *PostgresStore) ListTenantOAuthRedirects(ctx context.Context, userID string) ([]*TenantOAuthRedirect, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT user_id, redirect_uri, description, created_at
		FROM tenant_oauth_redirects WHERE user_id = $1
		ORDER BY created_at ASC
	`, userID)
	if err != nil {
		return nil, fmt.Errorf("list tenant_oauth_redirects: %w", err)
	}
	defer rows.Close()
	out := []*TenantOAuthRedirect{}
	for rows.Next() {
		r := &TenantOAuthRedirect{}
		if err := rows.Scan(&r.UserID, &r.RedirectURI, &r.Description, &r.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan tenant_oauth_redirect: %w", err)
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func (s *PostgresStore) AddTenantOAuthRedirect(ctx context.Context, r *TenantOAuthRedirect) error {
	if r.CreatedAt.IsZero() {
		r.CreatedAt = time.Now().UTC()
	}
	if _, err := s.pool.Exec(ctx, `
		INSERT INTO tenant_oauth_redirects (user_id, redirect_uri, description, created_at)
		VALUES ($1, $2, $3, $4)
	`, r.UserID, r.RedirectURI, r.Description, r.CreatedAt); err != nil {
		return fmt.Errorf("insert tenant_oauth_redirect: %w", err)
	}
	return nil
}

func (s *PostgresStore) RemoveTenantOAuthRedirect(ctx context.Context, userID, redirectURI string) error {
	tag, err := s.pool.Exec(ctx, `
		DELETE FROM tenant_oauth_redirects
		WHERE user_id = $1 AND redirect_uri = $2
	`, userID, redirectURI)
	if err != nil {
		return fmt.Errorf("delete tenant_oauth_redirect: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// ----- helpers -----

func (s *PostgresStore) queryUser(ctx context.Context, sql string, args ...any) (*User, error) {
	row := s.pool.QueryRow(ctx, sql, args...)
	return scanUser(row)
}

func scanUser(row pgx.Row) (*User, error) {
	u := &User{}
	if err := row.Scan(&u.ID, &u.Email, &u.Name, &u.PasswordHash, &u.Plan, &u.CreatedAt, &u.DeletedAt); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("scan user: %w", err)
	}
	return u, nil
}

// envInt reads an int env var with a default. Used for pool tuning so
// operators can size connections to match Railway/Postgres limits
// without recompiling.
func envInt(key string, fallback int) int {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return fallback
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < 0 {
		return fallback
	}
	return n
}

func isUniqueViolation(err error) bool {
	if err == nil {
		return false
	}
	// pgx returns *pgconn.PgError; sqlstate 23505 = unique_violation.
	msg := err.Error()
	return strings.Contains(msg, "23505") || strings.Contains(strings.ToLower(msg), "duplicate key")
}
