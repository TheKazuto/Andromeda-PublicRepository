package policy

// Async presign prefetch (Update 2 Part A). The presign is independent of the
// message, so it can run while the user reviews and signs the challenge. We
// dispatch it on the signing challenge, cache the single-use result in Redis
// keyed by (tenant, challenge) with a short TTL, and harvest it (GETDEL) on the
// submit so the client can pass it straight to /v1/dwallet/sign.
//
// This is NOT a presign pool: always exactly one presign per signing request,
// single-use, short TTL, tenant-scoped, never a reusable stock. Every step is
// non-fatal — any failure just falls back to the /sign inline allocation.
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

// PresignDispatcher allocates a single-use presign on the engine for a tenant's
// dWallet, returning the presignSessionIdHex. Implemented in the api package
// over the ika-backend upstream. Best-effort: errors are non-fatal.
type PresignDispatcher interface {
	Presign(ctx context.Context, tenant, dwalletAddress string) (string, error)
}

// PresignCache is the ephemeral (tenant, challenge) → presignSessionIdHex store.
// Backed by Redis: Put with a short TTL, GetDel for atomic single-use reads.
type PresignCache interface {
	Put(ctx context.Context, key, presignHex string, ttl time.Duration)
	GetDel(ctx context.Context, key string) string
}

// PresignMetrics is an optional observability hook (Prometheus in prod).
type PresignMetrics interface {
	// PrefetchDispatched records a completed prefetch attempt (ok=false on failure).
	PrefetchDispatched(ok bool)
	// PrefetchHarvest records a submit lookup (hit=true when a presign was cached).
	PrefetchHarvest(hit bool)
}

const (
	defaultPresignPrefetchTTL = 120 * time.Second
	// presignDispatchTimeout caps the detached background presign call.
	presignDispatchTimeout = 90 * time.Second
	// presignMaxInflight bounds concurrent background prefetch goroutines.
	presignMaxInflight = 512
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
	// Non-blocking acquire: if the in-flight cap is reached, drop this prefetch
	// (best-effort) rather than pile up goroutines. /sign allocates inline.
	select {
	case s.presignSem <- struct{}{}:
	default:
		s.recordPrefetch(false)
		return
	}
	go func() {
		defer func() { <-s.presignSem }()
		// Detached from the request context: the challenge response returns
		// immediately, so the prefetch must not be cancelled when it ends.
		ctx, cancel := context.WithTimeout(context.Background(), presignDispatchTimeout)
		defer cancel()
		hexID, err := s.presignDispatcher.Presign(ctx, tenant, dwalletAddress)
		if err != nil || hexID == "" {
			if err != nil {
				slog.Warn("presign prefetch failed", "err", err)
			}
			s.recordPrefetch(false)
			return
		}
		s.presignCache.Put(ctx, key, hexID, s.presignTTL)
		s.recordPrefetch(true)
	}()
}

// harvestPresign atomically reads (and deletes) the prefetched presign for this
// submit, or "" when none is cached (miss / disabled / no tenant).
func (s *Service) harvestPresign(r *http.Request, challengeHex string) string {
	if !s.presignPrefetchEnabled() || challengeHex == "" {
		return ""
	}
	tenant := s.resolveTenant(r)
	if tenant == "" {
		return ""
	}
	v := s.presignCache.GetDel(r.Context(), presignCacheKey(tenant, challengeHex))
	s.recordHarvest(v != "")
	return v
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
