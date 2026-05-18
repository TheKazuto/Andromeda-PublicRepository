package api

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"
	"golang.org/x/time/rate"

	bemetrics "github.com/shinkalabs/andromeda-backend/internal/metrics"
)

// authRateLimiter is a per-IP token-bucket limiter applied to the public
// auth endpoints (login, signup, admin login, TOTP). It is deliberately
// in-memory: defending against credential stuffing only requires bounding
// the rate per source — the stricter per-account lockout for known bad
// passwords is enforced separately at the store layer.
//
// Buckets are evicted lazily after `ttl` of inactivity AND a hard ceiling
// (`maxBuckets`) is enforced so a process under DDoS does not grow the
// map without bound — when the cap is reached we evict the oldest entry
// before inserting the new one.
type authRateLimiter struct {
	rps        rate.Limit // requests per second sustained
	burst      int        // initial bucket capacity
	ttl        time.Duration
	maxBuckets int

	mu      sync.Mutex
	buckets map[string]*ipBucket

	metrics *bemetrics.Metrics

	// P0.3: Redis-backed bucket shared across replicas. When nil the
	// limiter is per-process (legacy). When set, Redis is the
	// authoritative bucket and the in-memory map is the cold path used
	// only when Redis returns an error AND failOpen is true.
	redis    *redis.Client
	failOpen bool
	logger   *slog.Logger
}

// withMetrics attaches a metrics recorder so the middleware can increment
// backend_auth_rate_limit_blocked_total when a request is rejected.
// Fluent for boot-time wiring.
func (rl *authRateLimiter) withMetrics(m *bemetrics.Metrics) *authRateLimiter {
	rl.metrics = m
	return rl
}

// withRedis attaches the cross-replica backend. Pass nil to revert to
// per-process mode. The same Lua token-bucket script as the gateway is
// used, so the operational semantics stay consistent across services.
func (rl *authRateLimiter) withRedis(c *redis.Client, failOpen bool, logger *slog.Logger) *authRateLimiter {
	rl.redis = c
	rl.failOpen = failOpen
	rl.logger = logger
	return rl
}

// tokenBucketScript: matches gateway/internal/ratelimit/ratelimit.go.
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

// allowRedis runs the Lua token bucket against Redis. Returns true when
// the request is admitted, false when blocked, and (false, err) when
// Redis itself failed — caller honours failOpen in that case.
func (rl *authRateLimiter) allowRedis(ctx context.Context, key string, rps, burst int) (bool, error) {
	bucket := fmt.Sprintf("auth_rl:%s", key)
	result, err := rl.redis.Eval(ctx, tokenBucketScript, []string{bucket},
		time.Now().UnixMilli(), rps, burst).Int()
	if err != nil {
		return false, err
	}
	return result == 1, nil
}

type ipBucket struct {
	limiter *rate.Limiter
	lastHit time.Time
}

// newAuthRateLimiter returns a limiter calibrated for interactive auth.
// Defaults: 10 attempts/min sustained, 10-burst — enough that a real user
// fat-fingering passwords stays well under the bound, but credential
// stuffers are throttled to a useless rate.
func newAuthRateLimiter() *authRateLimiter {
	rl := &authRateLimiter{
		rps:        rate.Every(6 * time.Second), // 10 / minute
		burst:      10,
		ttl:        30 * time.Minute,
		maxBuckets: 50_000,
		buckets:    make(map[string]*ipBucket),
	}
	go rl.gcLoop()
	return rl
}

// allow reports whether the request from this IP is permitted right now.
func (rl *authRateLimiter) allow(ip string) bool {
	rl.mu.Lock()
	b, ok := rl.buckets[ip]
	if !ok {
		if len(rl.buckets) >= rl.maxBuckets {
			rl.evictOldestLocked()
		}
		b = &ipBucket{limiter: rate.NewLimiter(rl.rps, rl.burst)}
		rl.buckets[ip] = b
	}
	b.lastHit = time.Now()
	rl.mu.Unlock()
	return b.limiter.Allow()
}

// evictOldestLocked drops the bucket with the oldest lastHit. Caller
// must hold rl.mu.
func (rl *authRateLimiter) evictOldestLocked() {
	var (
		oldestKey  string
		oldestTime time.Time
		first      = true
	)
	for k, b := range rl.buckets {
		if first || b.lastHit.Before(oldestTime) {
			oldestKey = k
			oldestTime = b.lastHit
			first = false
		}
	}
	if oldestKey != "" {
		delete(rl.buckets, oldestKey)
	}
}

func (rl *authRateLimiter) gcLoop() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		cutoff := time.Now().Add(-rl.ttl)

		// Snapshot the keys under lock, then evict in a second pass to
		// minimise time holding the lock and avoid concurrent-iteration
		// concerns (although the lock would already prevent that).
		rl.mu.Lock()
		stale := make([]string, 0, len(rl.buckets)/8)
		for ip, b := range rl.buckets {
			if b.lastHit.Before(cutoff) {
				stale = append(stale, ip)
			}
		}
		for _, ip := range stale {
			delete(rl.buckets, ip)
		}
		rl.mu.Unlock()
	}
}

// middleware returns a chi-compatible middleware that 429s requests beyond
// the configured rate. Uses the direct peer IP from clientIP. The route
// label is best-effort (URL path without query); chi RoutePattern is only
// available after Routes match, which happens after this middleware.
//
// When Redis is wired, the bucket is shared across replicas and a Redis
// hiccup is governed by failOpen — false means deny, true means allow and
// log. The local in-memory bucket is still used as a backstop on
// Redis-allow so even a temporary Redis cache stampede cannot let a hot
// IP exceed N×rate per replica.
func (rl *authRateLimiter) middleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ip := normalizeIP(clientIP(r))
			if ip == "" {
				ip = "unknown"
			}

			blocked := false
			if rl.redis != nil {
				// Convert the local rate.Limit (events/sec) to integer rps.
				rps := int(float64(rl.rps) + 0.5)
				if rps < 1 {
					rps = 1
				}
				ctx, cancel := context.WithTimeout(r.Context(), 200*time.Millisecond)
				ok, err := rl.allowRedis(ctx, ip, rps, rl.burst)
				cancel()
				if err != nil {
					if rl.logger != nil {
						rl.logger.Warn("auth rate limit redis error", "err", err, "fail_open", rl.failOpen)
					}
					if !rl.failOpen {
						blocked = true
					} else {
						// Redis down + fail-open: fall back to local
						// bucket so we still rate-limit per replica.
						blocked = !rl.allow(ip)
					}
				} else {
					blocked = !ok
				}
			} else {
				blocked = !rl.allow(ip)
			}

			if blocked {
				if rl.metrics != nil {
					rl.metrics.AuthRateLimitBlockedTotal.WithLabelValues(r.URL.Path).Inc()
				}
				w.Header().Set("Retry-After", "60")
				writeError(w, http.StatusTooManyRequests, "too many requests, please retry in a minute")
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// normalizeIP folds a textual IP (possibly with brackets / port already
// stripped by clientIP) into a canonical form so duplicate buckets do not
// stack up for "127.0.0.1" vs "::ffff:127.0.0.1".
func normalizeIP(addr string) string {
	if addr == "" {
		return ""
	}
	addr = strings.TrimPrefix(strings.TrimSuffix(addr, "]"), "[")
	if ip := net.ParseIP(addr); ip != nil {
		return ip.String()
	}
	return addr
}
