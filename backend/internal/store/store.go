package store

import (
	"context"
	"errors"
	"strings"
	"time"
)

var (
	ErrNotFound      = errors.New("not found")
	ErrAlreadyExists = errors.New("already exists")
)

type User struct {
	ID           string     `json:"id"`
	Email        string     `json:"email"`
	Name         string     `json:"name"`
	PasswordHash string     `json:"-"`
	Plan         string     `json:"plan"`
	CreatedAt    time.Time  `json:"createdAt"`
	DeletedAt    *time.Time `json:"-"` // soft delete; never expose
}

type APIKey struct {
	ID             string     `json:"id"`
	UserID         string     `json:"userId"`
	Name           string     `json:"name"`
	Prefix         string     `json:"prefix"`
	HashedKey      string     `json:"-"`
	Scopes         []string   `json:"scopes"`
	IPAllowlist    []string   `json:"ipAllowlist,omitempty"`
	AllowedOrigins []string   `json:"allowedOrigins,omitempty"`
	CreatedAt      time.Time  `json:"createdAt"`
	LastUsedAt     *time.Time `json:"lastUsedAt,omitempty"`
	RevokedAt      *time.Time `json:"revokedAt,omitempty"`
}

// TenantOAuthRedirect is a single row in `tenant_oauth_redirects` — a
// redirect URI registered by the tenant for use with the Login Social OAuth
// broker (gateway `/v1/oauth/authorize`). The schema lives in the gateway
// migration `023_tenant_oauth_redirects.sql` (backend + gateway share the
// same Postgres). Tenant-scoped: never expose another user's rows.
type TenantOAuthRedirect struct {
	UserID      string    `json:"-"`
	RedirectURI string    `json:"redirectUri"`
	Description string    `json:"description,omitempty"`
	CreatedAt   time.Time `json:"createdAt"`
}

// RefreshTokenIssue holds everything needed to persist a freshly-minted
// refresh token. TokenHash is hex(sha256(raw)); the raw token never reaches
// the store layer.
type RefreshTokenIssue struct {
	UserID     string
	TokenHash  string
	IssuedAt   time.Time
	ExpiresAt  time.Time
	UserAgent  string
	IP         string
	ReplacesID string // optional — set when this issuance is part of a rotation
}

// RefreshTokenRow is what GetRefreshTokenByHash returns. Callers compare
// expires_at + revoked_at against the current time before trusting it.
type RefreshTokenRow struct {
	ID         string
	UserID     string
	IssuedAt   time.Time
	ExpiresAt  time.Time
	RevokedAt  *time.Time
	ReplacedBy *string
}

// PasswordResetIssue is the persisted form of a forgot-password token.
type PasswordResetIssue struct {
	UserID    string
	TokenHash string
	IssuedAt  time.Time
	ExpiresAt time.Time
}

// Store is the storage interface used by the API layer. Implementations:
//   - MemoryStore: in-process, lost on restart. Default for local dev.
//   - PostgresStore: durable, multi-instance safe. Used in production.
type Store interface {
	// Users
	CreateUser(ctx context.Context, u *User) error
	GetUserByID(ctx context.Context, id string) (*User, error)
	GetUserByEmail(ctx context.Context, email string) (*User, error)
	GetUserByProvider(ctx context.Context, provider, subject string) (*User, error)
	LinkProvider(ctx context.Context, userID, provider, subject string) error
	UpdateUser(ctx context.Context, id string, mutate func(*User)) (*User, error)
	UpdateUserPassword(ctx context.Context, id, newHash string) error
	SoftDeleteUser(ctx context.Context, id string) error

	// Lockout & failed-login tracking. Implementations may be a no-op when
	// the underlying schema does not support lockout (in-memory dev mode).
	IncrementUserFailedLogin(ctx context.Context, userID string, lockThreshold int, lockDuration time.Duration) error
	ResetUserFailedLogin(ctx context.Context, userID string) error
	IsUserLocked(ctx context.Context, userID string) (locked bool, until *time.Time, err error)

	// Refresh tokens
	CreateRefreshToken(ctx context.Context, in RefreshTokenIssue) (id string, err error)
	RotateRefreshToken(ctx context.Context, parentID string, in RefreshTokenIssue) (id string, err error)
	GetRefreshTokenByHash(ctx context.Context, hash string) (*RefreshTokenRow, error)
	ConsumeRefreshToken(ctx context.Context, id, replacedByID string) error
	RevokeRefreshTokensByUser(ctx context.Context, userID string) error
	RevokeRefreshTokenFamily(ctx context.Context, startID string) error

	// Password reset tokens
	CreatePasswordResetToken(ctx context.Context, in PasswordResetIssue) error
	ConsumePasswordResetToken(ctx context.Context, hash string) (userID string, err error)

	// API keys
	CreateAPIKey(ctx context.Context, k *APIKey) error
	ListAPIKeysByUser(ctx context.Context, userID string) ([]*APIKey, error)
	UpdateAPIKey(ctx context.Context, userID, id string, mut APIKeyMutation) (*APIKey, error)
	RevokeAPIKey(ctx context.Context, userID, id string) error
	RevokeAllAPIKeysByUser(ctx context.Context, userID string) error

	// Login Social — tenant OAuth redirect URIs (gateway broker allowlist).
	// Schema lives in the gateway migration 023; backend operates on the
	// same Postgres. All three methods are tenant-scoped on `userID`.
	ListTenantOAuthRedirects(ctx context.Context, userID string) ([]*TenantOAuthRedirect, error)
	AddTenantOAuthRedirect(ctx context.Context, r *TenantOAuthRedirect) error
	RemoveTenantOAuthRedirect(ctx context.Context, userID, redirectURI string) error

	// Lifecycle
	Close() error
}

func providerKey(provider, subject string) string {
	return strings.ToLower(provider) + ":" + subject
}
