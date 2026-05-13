package oauth

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
)

func newTestStore(t *testing.T, ttl time.Duration) (*Store, *miniredis.Miniredis, func()) {
	t.Helper()
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	s, err := NewStore(rdb, ttl)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	return s, mr, func() { _ = rdb.Close() }
}

func TestStore_PutTakeRoundTrip(t *testing.T) {
	s, _, cleanup := newTestStore(t, 60*time.Second)
	defer cleanup()
	ctx := context.Background()

	entry := Entry{
		IDToken:       "header.payload.sig",
		Provider:      "google",
		CodeChallenge: "abc",
		TenantID:      "tenant-1",
	}
	if err := s.Put(ctx, "code-A", entry); err != nil {
		t.Fatalf("Put: %v", err)
	}
	got, err := s.Take(ctx, "code-A")
	if err != nil {
		t.Fatalf("Take: %v", err)
	}
	if got != entry {
		t.Fatalf("got %+v, want %+v", got, entry)
	}
}

func TestStore_TakeIsSingleUse(t *testing.T) {
	s, _, cleanup := newTestStore(t, 60*time.Second)
	defer cleanup()
	ctx := context.Background()

	if err := s.Put(ctx, "code-B", Entry{IDToken: "tok"}); err != nil {
		t.Fatalf("Put: %v", err)
	}
	if _, err := s.Take(ctx, "code-B"); err != nil {
		t.Fatalf("first Take: %v", err)
	}
	if _, err := s.Take(ctx, "code-B"); !errors.Is(err, ErrCodeNotFound) {
		t.Fatalf("second Take should be not-found, got %v", err)
	}
}

func TestStore_TakeUnknownCode(t *testing.T) {
	s, _, cleanup := newTestStore(t, 60*time.Second)
	defer cleanup()
	if _, err := s.Take(context.Background(), "never-stored"); !errors.Is(err, ErrCodeNotFound) {
		t.Fatalf("expected ErrCodeNotFound, got %v", err)
	}
}

func TestStore_TakeAfterTTLExpired(t *testing.T) {
	s, mr, cleanup := newTestStore(t, 60*time.Second)
	defer cleanup()
	ctx := context.Background()

	if err := s.Put(ctx, "code-C", Entry{IDToken: "x"}); err != nil {
		t.Fatalf("Put: %v", err)
	}
	mr.FastForward(2 * time.Minute) // miniredis time travel
	if _, err := s.Take(ctx, "code-C"); !errors.Is(err, ErrCodeNotFound) {
		t.Fatalf("expected ErrCodeNotFound after TTL, got %v", err)
	}
}

func TestStore_PutRejectsDuplicate(t *testing.T) {
	s, _, cleanup := newTestStore(t, 60*time.Second)
	defer cleanup()
	ctx := context.Background()

	if err := s.Put(ctx, "code-D", Entry{IDToken: "a"}); err != nil {
		t.Fatalf("first Put: %v", err)
	}
	// Same code -> SETNX must refuse silently overwriting (collision guard).
	if err := s.Put(ctx, "code-D", Entry{IDToken: "b"}); err == nil {
		t.Fatalf("expected error on duplicate code, got nil")
	}
}

func TestNewStore_RejectsBadArgs(t *testing.T) {
	if _, err := NewStore(nil, time.Second); err == nil {
		t.Fatalf("expected error on nil redis client")
	}
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	defer rdb.Close()
	if _, err := NewStore(rdb, 0); err == nil {
		t.Fatalf("expected error on zero TTL")
	}
}
