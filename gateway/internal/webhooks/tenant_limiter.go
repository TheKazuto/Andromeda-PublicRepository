package webhooks

import (
	"sync"
	"time"

	"github.com/google/uuid"
)

// tenantLimiter is an in-memory token-bucket rate limiter keyed by
// api_key_id. The Solana log listener uses one of these to make sure
// a single noisy tenant cannot drown the dispatch queue with on-chain
// events. Buckets are evicted lazily after `idleTTL` of inactivity.
//
// Default budget: 10 events/sec sustained, burst 20. The numbers are
// tuned for Andromeda's expected Solana event rate (typically dozens
// per minute per tenant) — anything higher is almost certainly a
// stuck program emitting in a tight loop.
type tenantLimiter struct {
	mu       sync.Mutex
	buckets  map[uuid.UUID]*tenantBucket
	rate     float64       // tokens added per second
	burst    float64       // bucket capacity
	idleTTL  time.Duration // evict idle buckets after this
	lastSwep time.Time
}

type tenantBucket struct {
	tokens   float64
	lastFill time.Time
	lastSeen time.Time
}

// newTenantLimiter returns a fresh limiter. Pass <=0 to either rate
// or burst to disable the limiter entirely.
func newTenantLimiter(rate, burst float64) *tenantLimiter {
	return &tenantLimiter{
		buckets: map[uuid.UUID]*tenantBucket{},
		rate:    rate,
		burst:   burst,
		idleTTL: 10 * time.Minute,
	}
}

// Allow returns true when the tenant has spare budget for one event.
// On false, the caller should drop and increment a metric.
func (l *tenantLimiter) Allow(tenant uuid.UUID) bool {
	if l.rate <= 0 || l.burst <= 0 {
		return true
	}
	l.mu.Lock()
	defer l.mu.Unlock()

	now := time.Now()
	b, ok := l.buckets[tenant]
	if !ok {
		b = &tenantBucket{tokens: l.burst, lastFill: now, lastSeen: now}
		l.buckets[tenant] = b
	} else {
		// Refill — pro-rated against time since last touch, capped at burst.
		elapsed := now.Sub(b.lastFill).Seconds()
		if elapsed > 0 {
			b.tokens = clampFloat(b.tokens+elapsed*l.rate, 0, l.burst)
			b.lastFill = now
		}
	}
	b.lastSeen = now

	if b.tokens >= 1 {
		b.tokens -= 1
		l.maybeSweep(now)
		return true
	}
	l.maybeSweep(now)
	return false
}

// maybeSweep evicts idle buckets every minute. Called inside the mutex.
func (l *tenantLimiter) maybeSweep(now time.Time) {
	if now.Sub(l.lastSwep) < time.Minute {
		return
	}
	l.lastSwep = now
	for k, b := range l.buckets {
		if now.Sub(b.lastSeen) > l.idleTTL {
			delete(l.buckets, k)
		}
	}
}

func clampFloat(v, lo, hi float64) float64 {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}
