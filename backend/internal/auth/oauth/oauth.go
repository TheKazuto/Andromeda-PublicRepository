package oauth

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"net/mail"
	"strings"
	"sync"
	"time"
)

const (
	stateNonceLen = 16
	stateTTL      = 10 * time.Minute
)

var (
	ErrInvalidState    = errors.New("invalid oauth state")
	ErrExpiredState    = errors.New("expired oauth state")
	ErrConsumedState   = errors.New("oauth state already consumed")
	ErrUnknownProvider = errors.New("unknown oauth provider")
)

// Profile is the normalized identity returned by every provider.
type Profile struct {
	Provider string // "google" | "github"
	Subject  string // stable provider-side user id
	Email    string // verified email (we reject providers that don't supply one)
	Name     string // display name (may be empty)
}

// Validate guards against providers returning empty or malformed
// identities. Run before persisting a Profile to the users table.
func (p *Profile) Validate() error {
	if p == nil {
		return errors.New("nil profile")
	}
	if strings.TrimSpace(p.Subject) == "" {
		return errors.New("profile missing subject")
	}
	email := strings.TrimSpace(p.Email)
	if email == "" {
		return errors.New("profile missing email")
	}
	if _, err := mail.ParseAddress(email); err != nil {
		return errors.New("profile email is not a valid address")
	}
	return nil
}

// Provider abstracts the per-provider OAuth flow.
type Provider interface {
	Name() string
	AuthURL(state string) string
	Exchange(ctx context.Context, code string) (*Profile, error)
}

// consumedStates tracks state tokens that have already been redeemed so
// the same state cannot be replayed inside its TTL. Entries auto-expire
// at the state's expiry timestamp; the janitor removes them lazily.
var (
	consumedStatesMu sync.Mutex
	consumedStates   = map[string]int64{}
)

// markStateConsumed records that `nonce` was successfully verified. Returns
// false when the nonce was already consumed (replay) and true on first use.
func markStateConsumed(nonce []byte, expiryUnix int64) bool {
	key := base64.RawURLEncoding.EncodeToString(nonce)
	consumedStatesMu.Lock()
	defer consumedStatesMu.Unlock()

	if _, exists := consumedStates[key]; exists {
		return false
	}
	// Opportunistic GC: drop entries whose expiry passed.
	if len(consumedStates) > 1024 {
		now := time.Now().Unix()
		for k, exp := range consumedStates {
			if exp <= now {
				delete(consumedStates, k)
			}
		}
	}
	consumedStates[key] = expiryUnix
	return true
}

// NewState produces an opaque, HMAC-signed state token bound to the given
// secret. Layout: nonce(16) || expiry(8 bytes BE unix seconds) || hmac(32).
// The HMAC covers (nonce || expiry).
func NewState(secret []byte) (string, error) {
	nonce := make([]byte, stateNonceLen)
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	expiry := time.Now().Add(stateTTL).Unix()

	buf := make([]byte, 0, stateNonceLen+8+sha256.Size)
	buf = append(buf, nonce...)
	exp := make([]byte, 8)
	binary.BigEndian.PutUint64(exp, uint64(expiry))
	buf = append(buf, exp...)

	mac := hmac.New(sha256.New, secret)
	mac.Write(buf)
	buf = mac.Sum(buf)

	return base64.RawURLEncoding.EncodeToString(buf), nil
}

// VerifyState returns nil if the state is valid, unexpired and has not
// been consumed yet. Successful verification marks the state as
// consumed so subsequent calls with the same value fail with
// ErrConsumedState. This is the canonical CSRF defense for the OAuth
// callback — without it, an attacker who intercepts one valid state
// could replay it inside the 10 min TTL.
func VerifyState(secret []byte, state string) error {
	raw, err := base64.RawURLEncoding.DecodeString(state)
	if err != nil {
		return ErrInvalidState
	}
	if len(raw) != stateNonceLen+8+sha256.Size {
		return ErrInvalidState
	}
	signed := raw[:stateNonceLen+8]
	got := raw[stateNonceLen+8:]

	mac := hmac.New(sha256.New, secret)
	mac.Write(signed)
	want := mac.Sum(nil)
	if !hmac.Equal(got, want) {
		return ErrInvalidState
	}

	expiry := int64(binary.BigEndian.Uint64(signed[stateNonceLen:]))
	if time.Now().Unix() > expiry {
		return ErrExpiredState
	}
	nonce := signed[:stateNonceLen]
	if !markStateConsumed(nonce, expiry) {
		return ErrConsumedState
	}
	return nil
}

// Registry holds all enabled providers, keyed by name.
type Registry map[string]Provider

func (r Registry) Get(name string) (Provider, bool) {
	p, ok := r[name]
	return p, ok
}
