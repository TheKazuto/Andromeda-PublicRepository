package store

import (
	"context"
	"sync"
	"time"
)

// MemoryStore is the in-process implementation of Store. Data is lost on
// restart — use only for local development. Production must configure
// DATABASE_URL and the PostgresStore implementation.
type MemoryStore struct {
	mu        sync.RWMutex
	users     map[string]*User
	byEmail   map[string]string
	byProvSub map[string]string // "google:<subject>" or "github:<subject>" -> userID
	keys      map[string]*APIKey

	// Auth lockout & token tables (in-memory equivalents of the Postgres
	// schema — only used in dev where DATABASE_URL is unset).
	failedLogins map[string]int
	lockedUntil  map[string]time.Time
	refresh      map[string]*memRefresh // by id
	refreshHash  map[string]string      // hash -> id
	pwReset      map[string]*memReset   // hash -> row
}

type memRefresh struct {
	ID         string
	UserID     string
	IssuedAt   time.Time
	ExpiresAt  time.Time
	RevokedAt  *time.Time
	ReplacedBy *string
}

type memReset struct {
	UserID    string
	ExpiresAt time.Time
	UsedAt    *time.Time
}

func NewMemory() *MemoryStore {
	return &MemoryStore{
		users:        make(map[string]*User),
		byEmail:      make(map[string]string),
		byProvSub:    make(map[string]string),
		keys:         make(map[string]*APIKey),
		failedLogins: make(map[string]int),
		lockedUntil:  make(map[string]time.Time),
		refresh:      make(map[string]*memRefresh),
		refreshHash:  make(map[string]string),
		pwReset:      make(map[string]*memReset),
	}
}

func (s *MemoryStore) Close() error { return nil }

// ----- USERS -----

func (s *MemoryStore) CreateUser(_ context.Context, u *User) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.byEmail[u.Email]; exists {
		return ErrAlreadyExists
	}
	cp := *u
	s.users[u.ID] = &cp
	s.byEmail[u.Email] = u.ID
	return nil
}

func (s *MemoryStore) GetUserByID(_ context.Context, id string) (*User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	u, ok := s.users[id]
	if !ok || u.DeletedAt != nil {
		return nil, ErrNotFound
	}
	cp := *u
	return &cp, nil
}

func (s *MemoryStore) GetUserByEmail(_ context.Context, email string) (*User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	id, ok := s.byEmail[email]
	if !ok {
		return nil, ErrNotFound
	}
	u := s.users[id]
	if u.DeletedAt != nil {
		return nil, ErrNotFound
	}
	cp := *u
	return &cp, nil
}

func (s *MemoryStore) GetUserByProvider(_ context.Context, provider, subject string) (*User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	key := providerKey(provider, subject)
	id, ok := s.byProvSub[key]
	if !ok {
		return nil, ErrNotFound
	}
	u := s.users[id]
	if u.DeletedAt != nil {
		return nil, ErrNotFound
	}
	cp := *u
	return &cp, nil
}

func (s *MemoryStore) LinkProvider(_ context.Context, userID, provider, subject string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.users[userID]; !ok {
		return ErrNotFound
	}
	key := providerKey(provider, subject)
	if existing, ok := s.byProvSub[key]; ok {
		if existing == userID {
			return nil
		}
		return ErrAlreadyExists
	}
	s.byProvSub[key] = userID
	return nil
}

func (s *MemoryStore) UpdateUser(_ context.Context, id string, mutate func(*User)) (*User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	u, ok := s.users[id]
	if !ok || u.DeletedAt != nil {
		return nil, ErrNotFound
	}
	cp := *u
	mutate(&cp)
	s.users[id] = &cp
	return &cp, nil
}

func (s *MemoryStore) UpdateUserPassword(_ context.Context, id, newHash string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	u, ok := s.users[id]
	if !ok || u.DeletedAt != nil {
		return ErrNotFound
	}
	cp := *u
	cp.PasswordHash = newHash
	s.users[id] = &cp
	return nil
}

// SoftDeleteUser anonymizes the user, drops oauth links, revokes keys,
// and stamps deleted_at. Idempotent: re-calling on an already-deleted
// user is a no-op.
func (s *MemoryStore) SoftDeleteUser(_ context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	u, ok := s.users[id]
	if !ok {
		return ErrNotFound
	}
	if u.DeletedAt != nil {
		return nil
	}
	now := time.Now().UTC()

	// release the email index so a future signup can reuse it
	delete(s.byEmail, u.Email)

	// drop oauth links pointing at this user
	for k, uid := range s.byProvSub {
		if uid == id {
			delete(s.byProvSub, k)
		}
	}

	// revoke active keys
	for _, k := range s.keys {
		if k.UserID == id && k.RevokedAt == nil {
			ts := now
			k.RevokedAt = &ts
		}
	}

	cp := *u
	cp.Email = "__deleted__:" + id
	cp.Name = ""
	cp.PasswordHash = ""
	cp.DeletedAt = &now
	s.users[id] = &cp
	return nil
}

// ----- API KEYS -----

func (s *MemoryStore) CreateAPIKey(_ context.Context, k *APIKey) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	cp := *k
	s.keys[k.ID] = &cp
	return nil
}

func (s *MemoryStore) ListAPIKeysByUser(_ context.Context, userID string) ([]*APIKey, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := []*APIKey{}
	for _, k := range s.keys {
		if k.UserID == userID {
			cp := *k
			out = append(out, &cp)
		}
	}
	return out, nil
}

func (s *MemoryStore) UpdateAPIKey(_ context.Context, userID, id string, mut APIKeyMutation) (*APIKey, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	k, ok := s.keys[id]
	if !ok || k.UserID != userID || k.RevokedAt != nil {
		return nil, ErrNotFound
	}
	if mut.Name != nil {
		k.Name = *mut.Name
	}
	if mut.Scopes != nil {
		k.Scopes = append([]string{}, mut.Scopes...)
	}
	if mut.IPAllowlist != nil {
		k.IPAllowlist = append([]string{}, (*mut.IPAllowlist)...)
	}
	if mut.AllowedOrigins != nil {
		k.AllowedOrigins = append([]string{}, (*mut.AllowedOrigins)...)
	}
	cp := *k
	return &cp, nil
}

func (s *MemoryStore) RevokeAPIKey(_ context.Context, userID, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	k, ok := s.keys[id]
	if !ok || k.UserID != userID {
		return ErrNotFound
	}
	now := time.Now().UTC()
	k.RevokedAt = &now
	return nil
}

func (s *MemoryStore) RevokeAllAPIKeysByUser(_ context.Context, userID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now().UTC()
	for _, k := range s.keys {
		if k.UserID == userID && k.RevokedAt == nil {
			ts := now
			k.RevokedAt = &ts
		}
	}
	return nil
}

// ----- LOCKOUT (in-memory equivalent of the Postgres schema) -----

func (s *MemoryStore) IncrementUserFailedLogin(_ context.Context, userID string, lockThreshold int, lockDuration time.Duration) error {
	if userID == "" {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.failedLogins[userID]++
	if s.failedLogins[userID] >= lockThreshold {
		s.lockedUntil[userID] = time.Now().UTC().Add(lockDuration)
	}
	return nil
}

func (s *MemoryStore) ResetUserFailedLogin(_ context.Context, userID string) error {
	if userID == "" {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.failedLogins, userID)
	delete(s.lockedUntil, userID)
	return nil
}

func (s *MemoryStore) IsUserLocked(_ context.Context, userID string) (bool, *time.Time, error) {
	if userID == "" {
		return false, nil, nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	until, ok := s.lockedUntil[userID]
	if !ok {
		return false, nil, nil
	}
	if until.Before(time.Now().UTC()) {
		delete(s.lockedUntil, userID)
		delete(s.failedLogins, userID)
		return false, nil, nil
	}
	t := until
	return true, &t, nil
}

// ----- REFRESH TOKENS -----

func (s *MemoryStore) CreateRefreshToken(_ context.Context, in RefreshTokenIssue) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	id := newMemoryID()
	row := &memRefresh{
		ID:        id,
		UserID:    in.UserID,
		IssuedAt:  in.IssuedAt,
		ExpiresAt: in.ExpiresAt,
	}
	if row.IssuedAt.IsZero() {
		row.IssuedAt = time.Now().UTC()
	}
	s.refresh[id] = row
	s.refreshHash[in.TokenHash] = id
	return id, nil
}

func (s *MemoryStore) RotateRefreshToken(_ context.Context, parentID string, in RefreshTokenIssue) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	parent, ok := s.refresh[parentID]
	if !ok || parent.RevokedAt != nil {
		return "", ErrNotFound
	}
	id := newMemoryID()
	row := &memRefresh{
		ID:        id,
		UserID:    in.UserID,
		IssuedAt:  in.IssuedAt,
		ExpiresAt: in.ExpiresAt,
	}
	if row.IssuedAt.IsZero() {
		row.IssuedAt = time.Now().UTC()
	}
	s.refresh[id] = row
	s.refreshHash[in.TokenHash] = id
	now := time.Now().UTC()
	parent.RevokedAt = &now
	parent.ReplacedBy = &id
	return id, nil
}

func (s *MemoryStore) GetRefreshTokenByHash(_ context.Context, hash string) (*RefreshTokenRow, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	id, ok := s.refreshHash[hash]
	if !ok {
		return nil, ErrNotFound
	}
	r := s.refresh[id]
	return &RefreshTokenRow{
		ID: r.ID, UserID: r.UserID,
		IssuedAt: r.IssuedAt, ExpiresAt: r.ExpiresAt,
		RevokedAt: r.RevokedAt, ReplacedBy: r.ReplacedBy,
	}, nil
}

func (s *MemoryStore) ConsumeRefreshToken(_ context.Context, id, replacedByID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.refresh[id]
	if !ok || r.RevokedAt != nil {
		return ErrNotFound
	}
	now := time.Now().UTC()
	r.RevokedAt = &now
	if replacedByID != "" {
		rid := replacedByID
		r.ReplacedBy = &rid
	}
	return nil
}

func (s *MemoryStore) RevokeRefreshTokensByUser(_ context.Context, userID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now().UTC()
	for _, r := range s.refresh {
		if r.UserID == userID && r.RevokedAt == nil {
			ts := now
			r.RevokedAt = &ts
		}
	}
	return nil
}

func (s *MemoryStore) RevokeRefreshTokenFamily(_ context.Context, startID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now().UTC()
	id := startID
	for {
		r, ok := s.refresh[id]
		if !ok {
			return nil
		}
		if r.RevokedAt == nil {
			ts := now
			r.RevokedAt = &ts
		}
		if r.ReplacedBy == nil {
			return nil
		}
		id = *r.ReplacedBy
	}
}

// ----- PASSWORD RESET TOKENS -----

func (s *MemoryStore) CreatePasswordResetToken(_ context.Context, in PasswordResetIssue) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pwReset[in.TokenHash] = &memReset{UserID: in.UserID, ExpiresAt: in.ExpiresAt}
	return nil
}

func (s *MemoryStore) ConsumePasswordResetToken(_ context.Context, hash string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	row, ok := s.pwReset[hash]
	if !ok || row.UsedAt != nil || row.ExpiresAt.Before(time.Now().UTC()) {
		return "", ErrNotFound
	}
	now := time.Now().UTC()
	row.UsedAt = &now
	return row.UserID, nil
}

// newMemoryID returns a short pseudo-UUID. Memory store is dev-only and
// never crosses a wire, so the format is irrelevant — we just need
// uniqueness within the running process.
func newMemoryID() string {
	return time.Now().UTC().Format("20060102T150405.000000000")
}
