// Code↔id_token store for the Login Social OAuth broker.
//
// After /callback exchanges the provider's `code` for an id_token, the broker
// must hold the id_token briefly so the tenant app can fetch it with
// POST /v1/oauth/token-exchange + a PKCE verifier. This file is that store.
//
// Backed by Redis with a short TTL (default 60s, max 300s). Each entry is
// keyed by sha256(short_code) — never by the raw code — so an operator with
// Redis read access cannot replay the codes seen in transit. The Get-and-Del
// is a single atomic Lua script: a code can be redeemed at most once.

package oauth

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

// Sentinel errors. Callers map these to client responses; the audit layer
// captures the real reason.
var (
	ErrCodeNotFound  = errors.New("oauth: code not found")
	ErrCodeExpired   = errors.New("oauth: code expired")
	ErrCodeMalformed = errors.New("oauth: code entry malformed")
)

// Entry is the value the broker stores against a short_code. The PKCE
// challenge stays here so the broker can verify the tenant's `code_verifier`
// at token-exchange without re-reading the cookie.
type Entry struct {
	// IDToken is the raw compact JWT received from Google/Apple. It is
	// passed back to the tenant app and then discarded.
	IDToken string `json:"id_token"`

	// Provider records which provider issued the id_token. Used only for
	// audit logging — the on-chain verifier rederives this from `iss`.
	Provider string `json:"provider"`

	// CodeChallenge is the PKCE S256 challenge bound to this code. The
	// tenant app proves possession of the matching verifier at
	// POST /v1/oauth/token-exchange (the broker recomputes sha256(verifier)
	// and constant-time compares it with this value).
	CodeChallenge string `json:"code_challenge"`

	// TenantID lets the token-exchange handler audit which tenant
	// claimed the id_token, even if the X-Api-Key on /token-exchange
	// belongs to a different key than /authorize started with.
	TenantID string `json:"tenant_id"`
}

// Store is the Redis-backed code↔id_token map used by the broker.
type Store struct {
	rdb *redis.Client
	ttl time.Duration
}

// NewStore builds a Store. `ttl` must be > 0; the broker validates the env
// value to [30s, 300s] before passing it in.
func NewStore(rdb *redis.Client, ttl time.Duration) (*Store, error) {
	if rdb == nil {
		return nil, fmt.Errorf("oauth.NewStore: redis client is required")
	}
	if ttl <= 0 {
		return nil, fmt.Errorf("oauth.NewStore: ttl must be > 0 (got %s)", ttl)
	}
	return &Store{rdb: rdb, ttl: ttl}, nil
}

// hashCode hashes a raw short_code to its Redis key suffix. Storing the
// hash (not the raw code) means a Redis dump cannot be replayed back into
// the broker.
func hashCode(rawCode string) string {
	sum := sha256.Sum256([]byte(rawCode))
	return hex.EncodeToString(sum[:])
}

func keyFor(rawCode string) string {
	return "oauth:code:" + hashCode(rawCode)
}

// Put stores an entry keyed by sha256(rawCode), with the configured TTL.
// SetNX guards against a degenerate collision where two callbacks ever
// produced the same short_code — the second one fails instead of silently
// overwriting the first.
func (s *Store) Put(ctx context.Context, rawCode string, e Entry) error {
	body, err := json.Marshal(e)
	if err != nil {
		return fmt.Errorf("oauth: marshal entry: %w", err)
	}
	ok, err := s.rdb.SetNX(ctx, keyFor(rawCode), body, s.ttl).Result()
	if err != nil {
		return fmt.Errorf("oauth: redis SETNX failed: %w", err)
	}
	if !ok {
		// 2^-128 collision plus already-present — treat as duplicate.
		return fmt.Errorf("oauth: code collision (should be ~impossible)")
	}
	return nil
}

// getAndDelScript atomically reads a key and deletes it. Returning the
// value before deletion keeps redeem single-use under concurrent token-
// exchange requests for the same code.
const getAndDelScript = `local v = redis.call("GET", KEYS[1]); if v then redis.call("DEL", KEYS[1]); end; return v`

// Take fetches the entry for `rawCode`, deletes it from Redis in the same
// round-trip, and returns the parsed entry. Returns ErrCodeNotFound when
// the code has already been redeemed or has expired.
func (s *Store) Take(ctx context.Context, rawCode string) (Entry, error) {
	var zero Entry
	res, err := s.rdb.Eval(ctx, getAndDelScript, []string{keyFor(rawCode)}).Result()
	if err != nil && !errors.Is(err, redis.Nil) {
		return zero, fmt.Errorf("oauth: redis EVAL failed: %w", err)
	}
	if res == nil {
		return zero, ErrCodeNotFound
	}
	raw, ok := res.(string)
	if !ok || len(raw) == 0 {
		return zero, ErrCodeMalformed
	}
	var e Entry
	if err := json.Unmarshal([]byte(raw), &e); err != nil {
		return zero, ErrCodeMalformed
	}
	return e, nil
}
