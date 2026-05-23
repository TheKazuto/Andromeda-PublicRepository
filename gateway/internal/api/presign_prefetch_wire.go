package api

// Wiring for the policy Service's async presign prefetch (Update 2 Part A,
// hardened in Update 5 / F1): a dispatcher that calls the ika-backend presign
// over the in-process upstream path, a Redis-backed ephemeral cache with the
// idempotency lock + per-tenant budget + epoch tracking the policy layer needs,
// and the tenant resolver. All best-effort — every Redis op fails open.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/redis/go-redis/v9"

	gwmetrics "github.com/shinkalabs/andromeda-gateway/internal/metrics"
	"github.com/shinkalabs/andromeda-gateway/internal/policy"
	"github.com/shinkalabs/andromeda-gateway/internal/upstream"
)

// presignEpochKey holds the latest network epoch the gateway has observed,
// updated (monotonically) on every successful prefetch and read on harvest to
// drop presigns whose epoch has passed.
//
// Single-network today (devnet). When F4 multi-network is wired into the hot
// path, scope this key per network (e.g. "presign:epoch:current:<network>") so
// one network's epoch can't be compared against another's.
const presignEpochKey = "presign:epoch:current"

// presignMetricsAdapter maps the policy.PresignMetrics hook to the gateway's
// Prometheus counters.
type presignMetricsAdapter struct{ m *gwmetrics.Metrics }

func (a presignMetricsAdapter) PrefetchDispatched(ok bool)   { a.m.RecordPresignPrefetch(ok) }
func (a presignMetricsAdapter) PrefetchHarvest(hit bool)     { a.m.RecordPresignHarvest(hit) }
func (a presignMetricsAdapter) PrefetchLeaked(reason string) { a.m.RecordPresignLeaked(reason) }

// presignDispatcher allocates a single-use presign on the ika-backend for a
// tenant. Target.Call sets the engine auth header automatically; we add
// X-Andromeda-User-Id so the tenant-scoped engine route accepts the call.
type presignDispatcher struct{ ika *upstream.Target }

func (d presignDispatcher) Presign(ctx context.Context, tenant, dwalletAddress string) (policy.PresignResult, error) {
	body, err := json.Marshal(map[string]string{"dwalletAddress": dwalletAddress})
	if err != nil {
		return policy.PresignResult{}, err
	}
	res, err := d.ika.Call(ctx, http.MethodPost, "/v1/dwallet/presign", nil, body,
		map[string]string{"X-Andromeda-User-Id": tenant})
	if err != nil {
		return policy.PresignResult{}, err
	}
	if res.StatusCode != http.StatusOK {
		return policy.PresignResult{}, fmt.Errorf("presign upstream status %d", res.StatusCode)
	}
	var parsed struct {
		Success bool `json:"success"`
		Data    struct {
			PresignSessionIDHex string `json:"presignSessionIdHex"`
			// Epoch the presign was allocated in (string-encoded uint64 to avoid
			// JSON number precision loss). Optional/additive.
			Epoch string `json:"epoch"`
		} `json:"data"`
	}
	if err := json.Unmarshal(res.Body, &parsed); err != nil {
		return policy.PresignResult{}, fmt.Errorf("presign decode: %w", err)
	}
	if !parsed.Success || parsed.Data.PresignSessionIDHex == "" {
		return policy.PresignResult{}, fmt.Errorf("presign upstream returned no session id")
	}
	var epoch uint64
	if parsed.Data.Epoch != "" {
		epoch, _ = strconv.ParseUint(parsed.Data.Epoch, 10, 64)
	}
	return policy.PresignResult{Hex: parsed.Data.PresignSessionIDHex, Epoch: epoch}, nil
}

// presignRedisCache is the ephemeral (tenant, challenge) presign store plus the
// F1 guards. Failures are swallowed (best-effort) and fail open.
type presignRedisCache struct{ rdb *redis.Client }

// Lock claims the in-flight dispatch slot via SET NX. Fails open (returns true,
// i.e. "dispatch anyway") on Redis errors so a Redis blip never blocks signing.
func (c presignRedisCache) Lock(ctx context.Context, key string, ttl time.Duration) bool {
	if c.rdb == nil {
		return true
	}
	ok, err := c.rdb.SetNX(ctx, key, "1", ttl).Result()
	if err != nil {
		slog.Warn("presign lock SETNX failed; dispatching anyway", "err", err)
		return true
	}
	return ok
}

// Unlock releases a dispatch lock. Best-effort (errors swallowed).
func (c presignRedisCache) Unlock(ctx context.Context, key string) {
	if c.rdb == nil {
		return
	}
	_ = c.rdb.Del(ctx, key).Err()
}

// AllowDispatch enforces a per-tenant per-minute budget via a fixed-window
// INCR. Fails open on Redis errors.
func (c presignRedisCache) AllowDispatch(ctx context.Context, tenant string, max int) bool {
	if c.rdb == nil || max <= 0 {
		return true
	}
	minute := time.Now().Unix() / 60
	key := fmt.Sprintf("presign:rate:%s:%d", tenant, minute)
	n, err := c.rdb.Incr(ctx, key).Result()
	if err != nil {
		slog.Warn("presign budget INCR failed; allowing", "err", err)
		return true
	}
	if n == 1 {
		// First hit in this window — set the window's expiry (a touch over 60s).
		_ = c.rdb.Expire(ctx, key, 70*time.Second).Err()
	}
	return n <= int64(max)
}

func (c presignRedisCache) Put(ctx context.Context, key string, r policy.PresignResult, ttl time.Duration) {
	if c.rdb == nil {
		return
	}
	buf, err := json.Marshal(r)
	if err != nil {
		return
	}
	_ = c.rdb.Set(ctx, key, buf, ttl).Err()
	if r.Epoch > 0 {
		c.observeEpoch(ctx, r.Epoch)
	}
}

// observeEpoch records the latest seen network epoch (monotonic). A plain Set
// is fine: epoch only advances and a slightly stale value just makes the
// harvest staleness check more lenient, never wrong.
func (c presignRedisCache) observeEpoch(ctx context.Context, epoch uint64) {
	cur, err := c.rdb.Get(ctx, presignEpochKey).Uint64()
	if err != nil && !errors.Is(err, redis.Nil) {
		return
	}
	if epoch > cur {
		_ = c.rdb.Set(ctx, presignEpochKey, epoch, 0).Err()
	}
}

func (c presignRedisCache) GetDel(ctx context.Context, key string) (policy.PresignResult, bool) {
	if c.rdb == nil {
		return policy.PresignResult{}, false
	}
	v, err := c.rdb.GetDel(ctx, key).Result()
	if err != nil {
		// redis.Nil = cache miss (the common, expected case). Anything else is
		// a real Redis problem worth surfacing so the harvest "miss" metric
		// isn't silently inflated by an outage.
		if !errors.Is(err, redis.Nil) {
			slog.Warn("presign cache GETDEL failed", "err", err)
		}
		return policy.PresignResult{}, false
	}
	var r policy.PresignResult
	if err := json.Unmarshal([]byte(v), &r); err != nil {
		// Back-compat: a bare-hex value written before the JSON change.
		return policy.PresignResult{Hex: v}, true
	}
	return r, true
}

func (c presignRedisCache) CurrentEpoch(ctx context.Context) uint64 {
	if c.rdb == nil {
		return 0
	}
	n, err := c.rdb.Get(ctx, presignEpochKey).Uint64()
	if err != nil {
		return 0
	}
	return n
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
