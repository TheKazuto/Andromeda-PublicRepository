// Package redisclient builds a shared *redis.Client from REDIS_URL.
// Returned client is nil when REDIS_URL is empty — callers must handle
// nil as "feature disabled, fall back to no-op".
package redisclient

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/redis/go-redis/v9"
)

func New(redisURL string, logger *slog.Logger) (*redis.Client, error) {
	if redisURL == "" {
		return nil, nil
	}
	opt, err := redis.ParseURL(redisURL)
	if err != nil {
		return nil, fmt.Errorf("parse redis url: %w", err)
	}
	client := redis.NewClient(opt)
	pingCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := client.Ping(pingCtx).Err(); err != nil {
		// Configured but unreachable on boot. Surface so the operator
		// notices, but don't crash — features depending on Redis
		// fail-open per their own policy.
		logger.Warn("redis ping failed at boot", "err", err)
	}
	return client, nil
}
