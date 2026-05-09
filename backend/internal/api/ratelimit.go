package api

import (
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// authRateLimiter is a per-IP token-bucket limiter applied to the public
// auth endpoints (login, signup, admin login, TOTP). It is deliberately
// in-memory: defending against credential stuffing only requires bounding
// the rate per source — the stricter per-account lockout for known bad
// passwords is enforced separately at the store layer.
//
// Buckets are evicted lazily after `ttl` of inactivity so a long-running
// process does not hoard memory for IPs that have stopped probing.
type authRateLimiter struct {
	rps   rate.Limit // requests per second sustained
	burst int        // initial bucket capacity
	ttl   time.Duration

	mu      sync.Mutex
	buckets map[string]*ipBucket
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
		rps:     rate.Every(6 * time.Second), // 10 / minute
		burst:   10,
		ttl:     30 * time.Minute,
		buckets: make(map[string]*ipBucket),
	}
	go rl.gcLoop()
	return rl
}

// allow reports whether the request from this IP is permitted right now.
func (rl *authRateLimiter) allow(ip string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	b, ok := rl.buckets[ip]
	if !ok {
		b = &ipBucket{limiter: rate.NewLimiter(rl.rps, rl.burst)}
		rl.buckets[ip] = b
	}
	b.lastHit = time.Now()
	return b.limiter.Allow()
}

func (rl *authRateLimiter) gcLoop() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		cutoff := time.Now().Add(-rl.ttl)
		rl.mu.Lock()
		for ip, b := range rl.buckets {
			if b.lastHit.Before(cutoff) {
				delete(rl.buckets, ip)
			}
		}
		rl.mu.Unlock()
	}
}

// middleware returns a chi-compatible middleware that 429s requests beyond
// the configured rate. Uses the direct peer IP from clientIP.
func (rl *authRateLimiter) middleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ip := normalizeIP(clientIP(r))
			if ip == "" {
				ip = "unknown"
			}
			if !rl.allow(ip) {
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
