// Package ratelimit implements a per-API-key token-bucket rate limiter
// backed by Redis. When Redis is not configured or unreachable the limiter
// falls back to allow-all by default, controlled by the failOpen flag.
package ratelimit

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
)

var ErrLimited = errors.New("rate limited")

// Observer is the minimum metrics surface the rate limiter uses. Lets us
// record Lua-eval latency, errors and fail-open events without dragging
// the gateway metrics package as a hard dependency. Nil-safe.
type Observer interface {
	ObserveOpLatency(op string, seconds float64)
	IncError(op, kind string)
	IncFailOpen(op string)
}

type Limiter interface {
	// Allow checks whether one request can be admitted for key.
	// rps is the sustained refill rate; burst is the bucket capacity.
	Allow(ctx context.Context, key string, rps, burst int) error
	Ping(ctx context.Context) error
	// WithObserver attaches a metrics observer. Returns the same Limiter
	// to allow fluent wiring at boot.
	WithObserver(o Observer) Limiter
}

func New(redisURL string, failOpen bool, logger *slog.Logger) (Limiter, error) {
	if redisURL == "" {
		logger.Warn("rate limit disabled - REDIS_URL is empty")
		return &noopLimiter{}, nil
	}
	opt, err := redis.ParseURL(redisURL)
	if err != nil {
		return nil, fmt.Errorf("parse redis url: %w", err)
	}
	client := redis.NewClient(opt)
	pingCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := client.Ping(pingCtx).Err(); err != nil {
		logger.Warn("redis ping failed at boot", "err", err)
	}
	return &redisLimiter{client: client, failOpen: failOpen, logger: logger}, nil
}

type noopLimiter struct{}

func (n *noopLimiter) Allow(context.Context, string, int, int) error { return nil }
func (n *noopLimiter) Ping(context.Context) error                    { return nil }
func (n *noopLimiter) WithObserver(Observer) Limiter                 { return n }

type redisLimiter struct {
	client   *redis.Client
	failOpen bool
	logger   *slog.Logger
	obs      Observer
}

func (l *redisLimiter) Ping(ctx context.Context) error {
	return l.client.Ping(ctx).Err()
}

func (l *redisLimiter) WithObserver(o Observer) Limiter {
	l.obs = o
	return l
}

// classifyRedisErr maps a Redis error to a coarse kind label for metrics.
func classifyRedisErr(err error) string {
	if err == nil {
		return ""
	}
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		return "timeout"
	}
	s := err.Error()
	switch {
	case strings.Contains(s, "i/o timeout"), strings.Contains(s, "deadline exceeded"):
		return "timeout"
	case strings.Contains(s, "connect"), strings.Contains(s, "EOF"), strings.Contains(s, "broken pipe"), strings.Contains(s, "reset"):
		return "conn"
	default:
		return "other"
	}
}

const tokenBucketScript = `
local key = KEYS[1]
local now = tonumber(ARGV[1])
local rate = tonumber(ARGV[2])
local burst = tonumber(ARGV[3])

local data = redis.call("HMGET", key, "tokens", "ts")
local tokens = tonumber(data[1])
local ts = tonumber(data[2])
if tokens == nil then
  tokens = burst
end
if ts == nil then
  ts = now
end

local elapsed = math.max(0, now - ts)
tokens = math.min(burst, tokens + (elapsed * rate / 1000))
if tokens < 1 then
  redis.call("HMSET", key, "tokens", tokens, "ts", now)
  redis.call("PEXPIRE", key, math.max(2000, math.ceil((burst / rate) * 2000)))
  return 0
end

tokens = tokens - 1
redis.call("HMSET", key, "tokens", tokens, "ts", now)
redis.call("PEXPIRE", key, math.max(2000, math.ceil((burst / rate) * 2000)))
return 1
`

func (l *redisLimiter) Allow(ctx context.Context, key string, rps, burst int) error {
	if rps <= 0 && burst <= 0 {
		return nil
	}
	if rps <= 0 {
		rps = burst
	}
	if burst <= 0 {
		burst = rps
	}

	bucket := fmt.Sprintf("rl:%s", key)
	started := time.Now()
	allowed, err := l.client.Eval(ctx, tokenBucketScript, []string{bucket},
		time.Now().UnixMilli(), rps, burst).Int()
	elapsed := time.Since(started).Seconds()
	if l.obs != nil {
		l.obs.ObserveOpLatency("ratelimit_eval", elapsed)
	}
	if err != nil {
		if l.obs != nil {
			l.obs.IncError("ratelimit_eval", classifyRedisErr(err))
		}
		if l.failOpen {
			if l.obs != nil {
				l.obs.IncFailOpen("ratelimit_eval")
			}
			l.logger.Warn("rate limit redis error - failing open", "err", err)
			return nil
		}
		return fmt.Errorf("rate limit backend unavailable: %w", err)
	}
	if allowed != 1 {
		return ErrLimited
	}
	return nil
}
