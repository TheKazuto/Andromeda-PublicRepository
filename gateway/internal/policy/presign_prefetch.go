package policy

// Async presign prefetch (Update 2 Part A, hardened in Update 5 / F1). The
// presign is independent of the message, so it can run while the user reviews
// and signs the challenge. We dispatch it on the signing challenge, cache the
// single-use result in Redis keyed by (tenant, challenge) with a short TTL, and
// harvest it (GETDEL) on the submit so the client can pass it straight to
// /v1/dwallet/sign.
//
// This is NOT a presign pool: always exactly one presign per signing request,
// single-use, short TTL, tenant-scoped, never a reusable stock. Every step is
// non-fatal — any failure just falls back to the /sign inline allocation.
//
// F1 hardening (mpckit lessons, single-shot kept):
//   - A. epoch awareness — the engine reports the presign's epoch; on harvest,
//     if the network epoch has advanced past it, the presign is dead, so we
//     drop it and let /sign allocate inline rather than hand back an id the
//     network would reject with an opaque error. The drop is a measured leak.
//   - B. idempotent dispatch — a Redis lock on (tenant, challenge) stops a
//     re-issued challenge from firing (and orphaning) a second presign.
//   - C. economic anti-DoS — a per-tenant per-minute dispatch budget bounds the
//     sponsored gas spend across distinct digests (the challenge route is
//     already per-key rate-limited).
//   - D. leak observability — presigns paid for and never used are counted.
//
// Pre-alpha note: the engine signer is a mock, so presign is instant and this
// hides no latency yet. The win lands at Alpha when presign costs real time;
// the env flag (IKA_PRESIGN_PREFETCH_ENABLED) keeps it off until then.

import (
	"context"
	"log/slog"
	"net/http"
	"time"
)

// PresignResult is a prefetched presign plus the network epoch it was allocated
// in. Epoch 0 means "unknown" (the engine did not report one) — the staleness
// check is then skipped and the TTL is the only bound.
type PresignResult struct {
	Hex   string `json:"hex"`
	Epoch uint64 `json:"epoch,omitempty"`
}

// PresignDispatcher allocates a single-use presign on the engine for a tenant's
// dWallet. Implemented in the api package over the ika-backend upstream.
// Best-effort: errors are non-fatal.
type PresignDispatcher interface {
	Presign(ctx context.Context, tenant, dwalletAddress string) (PresignResult, error)
}

// PresignCache is the ephemeral (tenant, challenge) presign store plus the
// cross-pod guards F1 needs. Backed by Redis; every method fails open so a
// Redis problem only degrades to the pre-prefetch behaviour, never blocks
// signing.
type PresignCache interface {
	// Lock claims the single in-flight dispatch slot for `key`. Returns true
	// when the caller may dispatch, false when one is already in flight/cached.
	Lock(ctx context.Context, key string, ttl time.Duration) bool
	// Unlock releases a dispatch slot early (e.g. when dispatch failed) so a
	// later challenge can retry the prefetch before the lock TTL expires.
	Unlock(ctx context.Context, key string)
	// AllowDispatch enforces a per-tenant per-minute presign budget. Returns
	// true when under the cap; max <= 0 disables the cap.
	AllowDispatch(ctx context.Context, tenant string, max int) bool
	// Put stores the prefetched presign under `key` with `ttl` and records its
	// epoch as the latest network epoch the gateway has seen.
	Put(ctx context.Context, key string, r PresignResult, ttl time.Duration)
	// GetDel atomically reads + deletes the prefetched presign for `key`.
	GetDel(ctx context.Context, key string) (PresignResult, bool)
	// CurrentEpoch returns the latest network epoch the gateway has observed
	// (0 = unknown).
	CurrentEpoch(ctx context.Context) uint64
}

// PresignMetrics is an optional observability hook (Prometheus in prod).
type PresignMetrics interface {
	// PrefetchDispatched records a completed prefetch attempt (ok=false on failure).
	PrefetchDispatched(ok bool)
	// PrefetchHarvest records a submit lookup (hit=true when a usable presign was cached).
	PrefetchHarvest(hit bool)
	// PrefetchLeaked records a presign that was paid for but never used, by reason.
	PrefetchLeaked(reason string)
}

const (
	defaultPresignPrefetchTTL = 120 * time.Second
	// presignDispatchTimeout caps the detached background presign call and is
	// reused as the idempotency lock TTL (B).
	presignDispatchTimeout = 90 * time.Second
	// presignMaxInflight bounds concurrent background prefetch goroutines (per pod).
	presignMaxInflight = 512
	// presignMaxDispatchPerMinute bounds sponsored presigns per tenant per
	// minute (C). Generous — the challenge route is already per-key rate-limited.
	presignMaxDispatchPerMinute = 120
	// presignGateTimeout bounds the quick synchronous Redis gates (lock/budget).
	presignGateTimeout = 2 * time.Second
)

// WithPresignPrefetch enables async presign prefetch. Opt-in: when not wired (or
// any dependency is nil) signing behaves exactly as before.
func (s *Service) WithPresignPrefetch(
	d PresignDispatcher, c PresignCache, resolveTenant func(*http.Request) string, ttl time.Duration,
) *Service {
	s.presignDispatcher = d
	s.presignCache = c
	s.resolveTenant = resolveTenant
	if ttl <= 0 {
		ttl = defaultPresignPrefetchTTL
	}
	s.presignTTL = ttl
	s.presignMaxPerMinute = presignMaxDispatchPerMinute
	s.presignSem = make(chan struct{}, presignMaxInflight)
	return s
}

// WithPresignMetrics attaches the optional observability hook.
func (s *Service) WithPresignMetrics(m PresignMetrics) *Service {
	s.presignMetrics = m
	return s
}

func (s *Service) presignPrefetchEnabled() bool {
	return s.presignDispatcher != nil && s.presignCache != nil && s.resolveTenant != nil
}

func presignCacheKey(tenant, challengeHex string) string {
	return "presign:" + tenant + ":" + challengeHex
}

func presignLockKey(tenant, challengeHex string) string {
	return "presign:lock:" + tenant + ":" + challengeHex
}

// firePresignPrefetch dispatches a presign in the background and caches it under
// (tenant, challengeHex). Fully non-fatal.
func (s *Service) firePresignPrefetch(r *http.Request, dwalletAddress, challengeHex string) {
	if !s.presignPrefetchEnabled() || dwalletAddress == "" || challengeHex == "" {
		return
	}
	tenant := s.resolveTenant(r)
	if tenant == "" {
		return
	}
	key := presignCacheKey(tenant, challengeHex)
	lockKey := presignLockKey(tenant, challengeHex)

	// Non-blocking acquire: if the in-flight cap is reached, drop this prefetch
	// (best-effort) rather than pile up goroutines. /sign allocates inline.
	select {
	case s.presignSem <- struct{}{}:
	default:
		s.recordPrefetch(false)
		return
	}

	// Quick Redis gates run synchronously — they decide whether to spend gas.
	gateCtx, gateCancel := context.WithTimeout(context.Background(), presignGateTimeout)
	defer gateCancel()

	// B — idempotent dispatch: one in-flight/cached presign per (tenant,
	// challenge), so a re-issued challenge for the same digest cannot orphan a
	// second presign. The lock must outlive the cached result, so its TTL covers
	// the dispatch window PLUS the result lifetime; it is released early on
	// dispatch failure. A held lock is a dedup (not a failure) → no metric.
	lockTTL := s.presignTTL + presignDispatchTimeout
	if !s.presignCache.Lock(gateCtx, lockKey, lockTTL) {
		<-s.presignSem
		return
	}
	// C — economic anti-DoS: cap presign dispatches per tenant per minute.
	if !s.presignCache.AllowDispatch(gateCtx, tenant, s.presignMaxPerMinute) {
		s.presignCache.Unlock(gateCtx, lockKey)
		<-s.presignSem
		slog.Debug("presign prefetch skipped: per-tenant budget exhausted", "tenant", tenant)
		return
	}

	go func() {
		defer func() { <-s.presignSem }()
		// Detached from the request context: the challenge response returns
		// immediately, so the prefetch must not be cancelled when it ends.
		ctx, cancel := context.WithTimeout(context.Background(), presignDispatchTimeout)
		defer cancel()
		res, err := s.presignDispatcher.Presign(ctx, tenant, dwalletAddress)
		if err != nil || res.Hex == "" {
			if err != nil {
				slog.Warn("presign prefetch failed", "err", err)
			}
			// Release the lock so a later challenge can retry the prefetch
			// instead of being blocked for the full lock TTL.
			uctx, ucancel := context.WithTimeout(context.Background(), presignGateTimeout)
			defer ucancel()
			s.presignCache.Unlock(uctx, lockKey)
			s.recordPrefetch(false)
			return
		}
		s.presignCache.Put(ctx, key, res, s.presignTTL)
		s.recordPrefetch(true)
	}()
}

// harvestPresign atomically reads (and deletes) the prefetched presign for this
// submit, or "" when none is cached (miss / disabled / no tenant) or when the
// cached presign's epoch has gone stale.
func (s *Service) harvestPresign(r *http.Request, challengeHex string) string {
	if !s.presignPrefetchEnabled() || challengeHex == "" {
		return ""
	}
	tenant := s.resolveTenant(r)
	if tenant == "" {
		return ""
	}
	res, ok := s.presignCache.GetDel(r.Context(), presignCacheKey(tenant, challengeHex))
	if !ok || res.Hex == "" {
		s.recordHarvest(false)
		return ""
	}
	// A — epoch staleness: if the network epoch advanced past the one this
	// presign was allocated in, it is dead. Hand back "" so /sign allocates
	// inline instead of forwarding an id the network would reject opaquely.
	// We paid for it and never used it → count the leak.
	if res.Epoch > 0 {
		if cur := s.presignCache.CurrentEpoch(r.Context()); cur > res.Epoch {
			s.recordHarvest(false)
			s.recordLeak("stale_epoch")
			return ""
		}
	}
	s.recordHarvest(true)
	return res.Hex
}

func (s *Service) recordPrefetch(ok bool) {
	if s.presignMetrics != nil {
		s.presignMetrics.PrefetchDispatched(ok)
	}
}

func (s *Service) recordHarvest(hit bool) {
	if s.presignMetrics != nil {
		s.presignMetrics.PrefetchHarvest(hit)
	}
}

func (s *Service) recordLeak(reason string) {
	if s.presignMetrics != nil {
		s.presignMetrics.PrefetchLeaked(reason)
	}
}
