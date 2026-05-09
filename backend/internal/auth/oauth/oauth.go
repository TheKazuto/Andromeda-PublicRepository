package oauth

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"time"
)

const (
	stateNonceLen = 16
	stateTTL      = 10 * time.Minute
)

var (
	ErrInvalidState   = errors.New("invalid oauth state")
	ErrExpiredState   = errors.New("expired oauth state")
	ErrUnknownProvider = errors.New("unknown oauth provider")
)

// Profile is the normalized identity returned by every provider.
type Profile struct {
	Provider string // "google" | "github"
	Subject  string // stable provider-side user id
	Email    string // verified email (we reject providers that don't supply one)
	Name     string // display name (may be empty)
}

// Provider abstracts the per-provider OAuth flow.
type Provider interface {
	Name() string
	AuthURL(state string) string
	Exchange(ctx context.Context, code string) (*Profile, error)
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

// VerifyState returns nil if the state is valid and unexpired.
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
	return nil
}

// Registry holds all enabled providers, keyed by name.
type Registry map[string]Provider

func (r Registry) Get(name string) (Provider, bool) {
	p, ok := r[name]
	return p, ok
}
