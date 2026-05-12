package ratelimit

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
)

func newTestLimiter(t *testing.T, failOpen bool) (*redisLimiter, *miniredis.Miniredis) {
	t.Helper()
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("miniredis.Run: %v", err)
	}
	t.Cleanup(mr.Close)
	// Tight timeouts / no retries so the "redis down" cases fail fast.
	client := redis.NewClient(&redis.Options{
		Addr:        mr.Addr(),
		DialTimeout: 250 * time.Millisecond,
		MaxRetries:  -1,
	})
	t.Cleanup(func() { _ = client.Close() })
	return &redisLimiter{
		client:   client,
		failOpen: failOpen,
		logger:   slog.New(slog.NewTextHandler(io.Discard, nil)),
	}, mr
}

func TestNew_NoRedisIsNoop(t *testing.T) {
	l, err := New("", false, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("New(\"\"): %v", err)
	}
	if _, ok := l.(*noopLimiter); !ok {
		t.Fatalf("New(\"\") = %T, want *noopLimiter", l)
	}
	if err := l.Allow(context.Background(), "anything", 1, 1); err != nil {
		t.Fatalf("noop Allow returned %v, want nil", err)
	}
	if err := l.Ping(context.Background()); err != nil {
		t.Fatalf("noop Ping returned %v, want nil", err)
	}
}

func TestAllow_UnlimitedWhenNoLimits(t *testing.T) {
	l, _ := newTestLimiter(t, false)
	for i := 0; i < 1000; i++ {
		if err := l.Allow(context.Background(), "k", 0, 0); err != nil {
			t.Fatalf("call %d: rps=0,burst=0 should always pass, got %v", i, err)
		}
	}
}

func TestAllow_BurstThenLimited(t *testing.T) {
	l, mr := newTestLimiter(t, false)
	ctx := context.Background()
	const burst = 5
	for i := 0; i < burst; i++ {
		if err := l.Allow(ctx, "tenant-a:tx", 1, burst); err != nil {
			t.Fatalf("call %d within burst should pass, got %v", i+1, err)
		}
	}
	// Next one (still "now") must be limited.
	if err := l.Allow(ctx, "tenant-a:tx", 1, burst); !errors.Is(err, ErrLimited) {
		t.Fatalf("call %d = %v, want ErrLimited", burst+1, err)
	}
	// A different key has its own bucket.
	if err := l.Allow(ctx, "tenant-b:tx", 1, burst); err != nil {
		t.Fatalf("different key should not be limited, got %v", err)
	}
	// After the bucket TTL elapses the key is gone → fresh burst.
	mr.FastForward(30 * time.Second)
	if err := l.Allow(ctx, "tenant-a:tx", 1, burst); err != nil {
		t.Fatalf("after window reset Allow should pass, got %v", err)
	}
}

func TestAllow_DefaultsRpsBurstFromEachOther(t *testing.T) {
	l, _ := newTestLimiter(t, false)
	ctx := context.Background()
	// burst only (rps derived = burst). 3 calls allowed, 4th limited.
	for i := 0; i < 3; i++ {
		if err := l.Allow(ctx, "burst-only", 0, 3); err != nil {
			t.Fatalf("call %d: %v", i+1, err)
		}
	}
	if err := l.Allow(ctx, "burst-only", 0, 3); !errors.Is(err, ErrLimited) {
		t.Fatalf("4th call = %v, want ErrLimited", err)
	}
	// rps only (burst derived = rps).
	for i := 0; i < 2; i++ {
		if err := l.Allow(ctx, "rps-only", 2, 0); err != nil {
			t.Fatalf("call %d: %v", i+1, err)
		}
	}
	if err := l.Allow(ctx, "rps-only", 2, 0); !errors.Is(err, ErrLimited) {
		t.Fatalf("3rd call = %v, want ErrLimited", err)
	}
}

func TestAllow_RedisDown(t *testing.T) {
	t.Run("fail open", func(t *testing.T) {
		l, mr := newTestLimiter(t, true)
		mr.Close() // simulate Redis outage
		if err := l.Allow(context.Background(), "k", 1, 5); err != nil {
			t.Fatalf("failOpen=true should pass on redis error, got %v", err)
		}
	})
	t.Run("fail closed", func(t *testing.T) {
		l, mr := newTestLimiter(t, false)
		mr.Close()
		if err := l.Allow(context.Background(), "k", 1, 5); err == nil {
			t.Fatal("failOpen=false should error on redis outage")
		}
	})
}

func TestPing(t *testing.T) {
	l, mr := newTestLimiter(t, false)
	if err := l.Ping(context.Background()); err != nil {
		t.Fatalf("Ping on live redis: %v", err)
	}
	mr.Close()
	if err := l.Ping(context.Background()); err == nil {
		t.Fatal("Ping should fail when redis is down")
	}
}
