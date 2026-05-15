package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

// =============================================================================
// Admin auth, audit, and operator-management types.
//
// Tables (`admin_users`, `admin_audit_log`) are owned by the gateway's
// migration set — backend reads/writes through the same Postgres pool.
// =============================================================================

// ErrAdminInactive is returned by GetAdminUserByEmail when the row exists
// but is_active = false. Callers should treat as auth failure.
var ErrAdminInactive = errors.New("admin user is not active")

// AdminUser is an operator with access to /admin endpoints. Lives in a
// completely separate auth namespace from regular `users`.
type AdminUser struct {
	ID             string     `json:"id"`
	Email          string     `json:"email"`
	HashedPassword string     `json:"-"`
	Role           string     `json:"role"` // 'super_admin' | 'support' | 'billing'
	MFASecret      string     `json:"-"`
	MFARequired    bool       `json:"mfaRequired"`
	IsActive       bool       `json:"isActive"`
	LastLoginAt    *time.Time `json:"lastLoginAt,omitempty"`
	LastLoginIP    string     `json:"lastLoginIp,omitempty"`
	CreatedAt      time.Time  `json:"createdAt"`
	UpdatedAt      time.Time  `json:"updatedAt"`
}

// AdminUserCreate is the input for creating an admin user.
type AdminUserCreate struct {
	Email          string
	HashedPassword string
	Role           string
	MFARequired    bool
}

// AdminAuditEntry is a single line in admin_audit_log.
type AdminAuditEntry struct {
	ID         int64          `json:"id"`
	AdminID    string         `json:"adminId"`
	AdminEmail string         `json:"adminEmail"`
	Action     string         `json:"action"`
	Target     string         `json:"target,omitempty"`
	Payload    map[string]any `json:"payload"`
	IPAddress  string         `json:"ipAddress,omitempty"`
	UserAgent  string         `json:"userAgent,omitempty"`
	CreatedAt  time.Time      `json:"createdAt"`
}

// AdminAuditAppend is the input for recording an admin action.
type AdminAuditAppend struct {
	AdminID    string
	AdminEmail string
	Action     string
	Target     string
	Payload    map[string]any
	IPAddress  string
	UserAgent  string
}

// AdminStore is the subset of operations the admin auth + audit layer
// needs. PostgresStore satisfies it; MemoryStore does not.
type AdminStore interface {
	CreateAdminUser(ctx context.Context, in AdminUserCreate) (*AdminUser, error)
	GetAdminUserByEmail(ctx context.Context, email string) (*AdminUser, error)
	GetAdminUserByID(ctx context.Context, id string) (*AdminUser, error)
	ListAdminUsers(ctx context.Context) ([]AdminUser, error)
	TouchAdminLogin(ctx context.Context, adminID, ip string) error
	SetAdminMFASecret(ctx context.Context, adminID, secret string, required bool) error
	DeactivateAdminUser(ctx context.Context, adminID string) error
	CountAdminUsers(ctx context.Context) (int, error)

	// Lockout — same shape as the customer-side lockout. The threshold for
	// admin TOTP brute-force is intentionally tighter (3 failures) but the
	// store layer just exposes a generic increment; thresholds live in the
	// API layer.
	IncrementAdminFailedLogin(ctx context.Context, adminID string, lockThreshold int, lockDuration time.Duration) error
	ResetAdminFailedLogin(ctx context.Context, adminID string) error
	IsAdminLocked(ctx context.Context, adminID string) (locked bool, until *time.Time, err error)

	AppendAdminAudit(ctx context.Context, in AdminAuditAppend) error
	ListAdminAudit(ctx context.Context, limit int) ([]AdminAuditEntry, error)

	// TOTP replay protection — see auth.VerifyTOTP. The last successfully
	// accepted TOTP window is stored per-admin so the same 6-digit code
	// cannot be reused inside its 30-second validity envelope.
	GetAdminTOTPLastWindow(ctx context.Context, adminID string) (int64, error)
	SetAdminTOTPLastWindow(ctx context.Context, adminID string, window int64) error
}

const adminUserColumns = `
    id, email, hashed_password, role,
    COALESCE(mfa_secret, ''), mfa_required,
    is_active, last_login_at, COALESCE(last_login_ip, ''),
    created_at, updated_at`

func scanAdminUser(row pgx.Row, a *AdminUser) error {
	return row.Scan(
		&a.ID, &a.Email, &a.HashedPassword, &a.Role,
		&a.MFASecret, &a.MFARequired,
		&a.IsActive, &a.LastLoginAt, &a.LastLoginIP,
		&a.CreatedAt, &a.UpdatedAt,
	)
}

func (s *PostgresStore) CreateAdminUser(ctx context.Context, in AdminUserCreate) (*AdminUser, error) {
	if in.Email == "" || in.HashedPassword == "" {
		return nil, fmt.Errorf("email and hashed_password required")
	}
	switch in.Role {
	case "super_admin", "support", "billing":
	default:
		return nil, fmt.Errorf("role must be 'super_admin', 'support' or 'billing'")
	}

	row := s.pool.QueryRow(ctx, `
        INSERT INTO admin_users (email, hashed_password, role, mfa_required)
        VALUES ($1, $2, $3, $4)
        RETURNING `+adminUserColumns,
		strings.ToLower(in.Email), in.HashedPassword, in.Role, in.MFARequired)

	var a AdminUser
	if err := scanAdminUser(row, &a); err != nil {
		if isUniqueViolation(err) {
			return nil, ErrAlreadyExists
		}
		return nil, fmt.Errorf("create admin user: %w", err)
	}
	return &a, nil
}

func (s *PostgresStore) GetAdminUserByEmail(ctx context.Context, email string) (*AdminUser, error) {
	row := s.pool.QueryRow(ctx,
		`SELECT `+adminUserColumns+` FROM admin_users WHERE email = $1`,
		strings.ToLower(email))
	var a AdminUser
	if err := scanAdminUser(row, &a); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	if !a.IsActive {
		return nil, ErrAdminInactive
	}
	return &a, nil
}

func (s *PostgresStore) GetAdminUserByID(ctx context.Context, id string) (*AdminUser, error) {
	row := s.pool.QueryRow(ctx,
		`SELECT `+adminUserColumns+` FROM admin_users WHERE id = $1`, id)
	var a AdminUser
	if err := scanAdminUser(row, &a); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	if !a.IsActive {
		return nil, ErrAdminInactive
	}
	return &a, nil
}

func (s *PostgresStore) ListAdminUsers(ctx context.Context) ([]AdminUser, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT `+adminUserColumns+` FROM admin_users ORDER BY created_at ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []AdminUser{}
	for rows.Next() {
		var a AdminUser
		if err := scanAdminUser(rows, &a); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

func (s *PostgresStore) TouchAdminLogin(ctx context.Context, adminID, ip string) error {
	_, err := s.pool.Exec(ctx, `
        UPDATE admin_users
        SET last_login_at = now(),
            last_login_ip = $2,
            updated_at    = now()
        WHERE id = $1`, adminID, nullableStr(ip))
	return err
}

func (s *PostgresStore) SetAdminMFASecret(ctx context.Context, adminID, secret string, required bool) error {
	tag, err := s.pool.Exec(ctx, `
        UPDATE admin_users
        SET mfa_secret  = $2,
            mfa_required = $3,
            updated_at   = now()
        WHERE id = $1`, adminID, nullableStr(secret), required)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *PostgresStore) DeactivateAdminUser(ctx context.Context, adminID string) error {
	tag, err := s.pool.Exec(ctx, `
        UPDATE admin_users
        SET is_active = false, updated_at = now()
        WHERE id = $1`, adminID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// GetAdminTOTPLastWindow returns the most recently consumed TOTP window
// for the admin. Zero when the admin has never authenticated with TOTP.
func (s *PostgresStore) GetAdminTOTPLastWindow(ctx context.Context, adminID string) (int64, error) {
	var w *int64
	err := s.pool.QueryRow(ctx,
		`SELECT mfa_last_window FROM admin_users WHERE id = $1`, adminID).Scan(&w)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return 0, ErrNotFound
		}
		return 0, fmt.Errorf("get totp last window: %w", err)
	}
	if w == nil {
		return 0, nil
	}
	return *w, nil
}

// SetAdminTOTPLastWindow advances mfa_last_window only when the supplied
// window is strictly greater than the persisted one. The atomic update
// prevents two parallel logins from consuming the same window.
func (s *PostgresStore) SetAdminTOTPLastWindow(ctx context.Context, adminID string, window int64) error {
	tag, err := s.pool.Exec(ctx, `
        UPDATE admin_users
        SET mfa_last_window = $2, updated_at = now()
        WHERE id = $1
          AND (mfa_last_window IS NULL OR mfa_last_window < $2)`, adminID, window)
	if err != nil {
		return fmt.Errorf("set totp last window: %w", err)
	}
	if tag.RowsAffected() == 0 {
		// Either the admin doesn't exist or another login already
		// claimed this (or a newer) window — both are replay attempts.
		return ErrAlreadyExists
	}
	return nil
}

// CountAdminUsers returns the total number of rows in admin_users. Used
// by the bootstrap path to decide whether to seed the first super_admin.
func (s *PostgresStore) CountAdminUsers(ctx context.Context) (int, error) {
	var n int
	if err := s.pool.QueryRow(ctx,
		`SELECT COUNT(*)::int FROM admin_users`).Scan(&n); err != nil {
		return 0, err
	}
	return n, nil
}

// =============================================================================
// admin_audit_log
// =============================================================================

func (s *PostgresStore) AppendAdminAudit(ctx context.Context, in AdminAuditAppend) error {
	if in.AdminID == "" || in.AdminEmail == "" || in.Action == "" {
		return fmt.Errorf("admin_id, admin_email and action required")
	}
	payload := in.Payload
	if payload == nil {
		payload = map[string]any{}
	}
	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	_, err = s.pool.Exec(ctx, `
        INSERT INTO admin_audit_log
            (admin_id, admin_email, action, target, payload, ip_address, user_agent)
        VALUES ($1, $2, $3, $4, $5, $6, $7)`,
		in.AdminID, strings.ToLower(in.AdminEmail), in.Action, nullableStr(in.Target),
		payloadJSON, nullableStr(in.IPAddress), nullableStr(in.UserAgent))
	return err
}

func (s *PostgresStore) ListAdminAudit(ctx context.Context, limit int) ([]AdminAuditEntry, error) {
	if limit <= 0 || limit > 1000 {
		limit = 200
	}
	rows, err := s.pool.Query(ctx, `
        SELECT id, admin_id, admin_email, action,
               COALESCE(target, ''), payload,
               COALESCE(ip_address, ''), COALESCE(user_agent, ''),
               created_at
        FROM admin_audit_log
        ORDER BY id DESC
        LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []AdminAuditEntry{}
	for rows.Next() {
		var (
			e          AdminAuditEntry
			payloadRaw []byte
		)
		if err := rows.Scan(&e.ID, &e.AdminID, &e.AdminEmail, &e.Action,
			&e.Target, &payloadRaw,
			&e.IPAddress, &e.UserAgent,
			&e.CreatedAt); err != nil {
			return nil, err
		}
		if len(payloadRaw) > 0 {
			_ = json.Unmarshal(payloadRaw, &e.Payload)
		}
		if e.Payload == nil {
			e.Payload = map[string]any{}
		}
		out = append(out, e)
	}
	return out, rows.Err()
}
