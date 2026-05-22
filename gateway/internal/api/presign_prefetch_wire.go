package api

// Wiring for the policy Service's async presign prefetch (Update 2 Part A):
// a dispatcher that calls the ika-backend presign over the in-process upstream
// path, a Redis-backed ephemeral cache, and the tenant resolver. All best-effort.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/redis/go-redis/v9"

	gwmetrics "github.com/shinkalabs/andromeda-gateway/internal/metrics"
	"github.com/shinkalabs/andromeda-gateway/internal/upstream"
)

// presignMetricsAdapter maps the policy.PresignMetrics hook to the gateway's
// Prometheus counters.
type presignMetricsAdapter struct{ m *gwmetrics.Metrics }

func (a presignMetricsAdapter) PrefetchDispatched(ok bool) { a.m.RecordPresignPrefetch(ok) }
func (a presignMetricsAdapter) PrefetchHarvest(hit bool)   { a.m.RecordPresignHarvest(hit) }

// presignDispatcher allocates a single-use presign on the ika-backend for a
// tenant. Target.Call sets the engine auth header automatically; we add
// X-Andromeda-User-Id so the tenant-scoped engine route accepts the call.
type presignDispatcher struct{ ika *upstream.Target }

func (d presignDispatcher) Presign(ctx context.Context, tenant, dwalletAddress string) (string, error) {
	body, err := json.Marshal(map[string]string{"dwalletAddress": dwalletAddress})
	if err != nil {
		return "", err
	}
	res, err := d.ika.Call(ctx, http.MethodPost, "/v1/dwallet/presign", nil, body,
		map[string]string{"X-Andromeda-User-Id": tenant})
	if err != nil {
		return "", err
	}
	if res.StatusCode != http.StatusOK {
		return "", fmt.Errorf("presign upstream status %d", res.StatusCode)
	}
	var parsed struct {
		Success bool `json:"success"`
		Data    struct {
			PresignSessionIDHex string `json:"presignSessionIdHex"`
		} `json:"data"`
	}
	if err := json.Unmarshal(res.Body, &parsed); err != nil {
		return "", fmt.Errorf("presign decode: %w", err)
	}
	if !parsed.Success || parsed.Data.PresignSessionIDHex == "" {
		return "", fmt.Errorf("presign upstream returned no session id")
	}
	return parsed.Data.PresignSessionIDHex, nil
}

// presignRedisCache is the ephemeral (tenant, challenge) → presignSessionIdHex
// store. Single-use via GETDEL; short TTL. Failures are swallowed (best-effort).
type presignRedisCache struct{ rdb *redis.Client }

func (c presignRedisCache) Put(ctx context.Context, key, presignHex string, ttl time.Duration) {
	if c.rdb == nil {
		return
	}
	_ = c.rdb.Set(ctx, key, presignHex, ttl).Err()
}

func (c presignRedisCache) GetDel(ctx context.Context, key string) string {
	if c.rdb == nil {
		return ""
	}
	v, err := c.rdb.GetDel(ctx, key).Result()
	if err != nil {
		// redis.Nil = cache miss (the common, expected case). Anything else is
		// a real Redis problem worth surfacing so the harvest "miss" metric
		// isn't silently inflated by an outage.
		if !errors.Is(err, redis.Nil) {
			slog.Warn("presign cache GETDEL failed", "err", err)
		}
		return ""
	}
	return v
}

// tenantFromRequest returns the authenticated tenant (user) id, or "" when the
// request was not authenticated. Mirrors the X-Andromeda-User-Id the proxy sends.
func tenantFromRequest(r *http.Request) string {
	a := authFrom(r)
	if a == nil || a.User == nil {
		return ""
	}
	return a.User.ID
}
