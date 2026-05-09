// Package ratelimit implements a per-API-key token-bucket rate limiter
// backed by Redis. When Redis is not configured or unreachable the limiter
// falls back to allow-all by default, controlled by the failOpen flag.
package ratelimit

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/redis/go-redis/v9"
)

var ErrLimited = errors.New("rate limited")

type Limiter interface {
	// Allow checks whether one request can be admitted for key.
	// rps is the sustained refill rate; burst is the bucket capacity.
	Allow(ctx context.Context, key string, rps, burst int) error
	Ping(ctx context.Context) error
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

func (*noopLimiter) Allow(context.Context, string, int, int) error { return nil }
func (*noopLimiter) Ping(context.Context) error                    { return nil }

type redisLimiter struct {
	client   *redis.Client
	failOpen bool
	logger   *slog.Logger
}

func (l *redisLimiter) Ping(ctx context.Context) error {
	return l.client.Ping(ctx).Err()
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
	allowed, err := l.client.Eval(ctx, tokenBucketScript, []string{bucket},
		time.Now().UnixMilli(), rps, burst).Int()
	if err != nil {
		if l.failOpen {
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
