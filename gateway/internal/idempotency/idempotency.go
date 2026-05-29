// Package idempotency implements Stripe-compatible Idempotency-Key support.
//
// Contract:
//   - The client supplies the `Idempotency-Key` header on POST/PATCH/DELETE.
//   - The first request with a given (api_key_id, route, key) tuple runs and
//     its 2xx/4xx response is cached for 24h (configurable). 5xx is NOT cached.
//   - Replays return the cached response with `Idempotent-Replay: true`.
//   - A retry with the same key but a different body returns 422
//     (request-body collision).
//   - Concurrent requests with the same key — the first acquires the lock and
//     proceeds, others get 409 in_progress.
//
// Backend: Redis. Without Redis the middleware no-ops with a startup warning,
// preserving local-dev ergonomics (already the policy of the rate limiter).
package idempotency

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	chimw "github.com/go-chi/chi/v5/middleware"
	"github.com/redis/go-redis/v9"

	"github.com/shinkalabs/andromeda-gateway/internal/httpx"
)

// HeaderName is the request header carrying the idempotency key.
const HeaderName = "Idempotency-Key"

// ReplayHeader is set on the response when the result was served from cache.
const ReplayHeader = "Idempotent-Replay"

// Default lock TTL — protects the in-flight slot from indefinite holds.
const lockTTL = 60 * time.Second

// Default response cache TTL — 24h matches Stripe's docs.
const defaultResponseTTL = 24 * time.Hour

// Maximum body size we will hash for collision detection (1 MiB).
const maxBodyHashBytes = 1 << 20

// MiddlewareOptions configures the middleware factory.
type MiddlewareOptions struct {
	Redis           *redis.Client
	Logger          *slog.Logger
	ResponseTTL     time.Duration // 0 means defaultResponseTTL
	APIKeyIDFromCtx func(*http.Request) string
	// OnReplay, if set, is called after a cached entry is replayed. Use it to
	// audit-log the replay. Errors from the callback are logged but never
	// fail the response.
	OnReplay func(r *http.Request, key string, status int)
	// RequireKey, when set and returning true for the request, makes the
	// `Idempotency-Key` header MANDATORY: missing header → 400
	// `missing_idempotency_key`. Wire this from the route catalogue so
	// destructive mutating routes (init, add/update/remove rule,
	// pause/resume/revoke, request-signature submit, sign/presign submit,
	// recovery primary submit, DKG submit, future-sign submit) cannot be
	// retried without a key.
	RequireKey func(*http.Request) bool
	// FailClosed, when true, makes a Redis outage reject RequireKey routes
	// with 503 instead of passing them through unprotected. Non-RequireKey
	// routes always fail open (idempotency is best-effort there). The DB
	// token_ledger is the last line of defence regardless.
	FailClosed bool
}

// New returns a chi-style middleware. When Redis is nil it returns a no-op
// pass-through with a single boot warning.
func New(opts MiddlewareOptions) func(http.Handler) http.Handler {
	if opts.Logger == nil {
		opts.Logger = slog.Default()
	}
	if opts.Redis == nil {
		opts.Logger.Warn("idempotency disabled — REDIS_URL is empty")
		return func(next http.Handler) http.Handler { return next }
	}
	if opts.ResponseTTL == 0 {
		opts.ResponseTTL = defaultResponseTTL
	}
	if opts.APIKeyIDFromCtx == nil {
		opts.APIKeyIDFromCtx = func(_ *http.Request) string { return "" }
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			handle(w, r, next, opts)
		})
	}
}

func handle(w http.ResponseWriter, r *http.Request, next http.Handler, opts MiddlewareOptions) {
	if !shouldApply(r) {
		next.ServeHTTP(w, r)
		return
	}
	required := opts.RequireKey != nil && opts.RequireKey(r)
	key := strings.TrimSpace(r.Header.Get(HeaderName))
	if key == "" {
		// Hard-fail when the route requires the header. Keeps dashboard
		// retries from accidentally submitting the same destructive
		// mutation twice on a transient network blip.
		if required {
			writeJSONError(w, http.StatusBadRequest, "missing_idempotency_key",
				"Idempotency-Key header is required for this route")
			return
		}
		next.ServeHTTP(w, r)
		return
	}
	if len(key) < 8 || len(key) > 200 {
		writeJSONError(w, http.StatusBadRequest, "invalid_idempotency_key",
			"Idempotency-Key must be between 8 and 200 characters")
		return
	}

	apiKeyID := opts.APIKeyIDFromCtx(r)
	if apiKeyID == "" {
		// No tenancy context yet — apply key globally per route.
		apiKeyID = "anon"
	}

	bodyBytes, err := readBodyForHash(r)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "body_too_large",
			"request body exceeds idempotency hash limit")
		return
	}
	bodyHash := hashBody(bodyBytes)

	cacheKey := fmt.Sprintf("idem:%s:%s:%s", apiKeyID, r.Method+" "+r.URL.Path, key)
	lockKey := cacheKey + ":lock"

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	// Try to read a previously cached entry first.
	cached, err := opts.Redis.Get(ctx, cacheKey).Bytes()
	if err == nil {
		var entry storedEntry
		jerr := json.Unmarshal(cached, &entry)
		if jerr == nil {
			if entry.RequestHash != bodyHash {
				writeJSONError(w, http.StatusUnprocessableEntity, "idempotency_collision",
					"Idempotency-Key reused with a different request body")
				return
			}
			replayCached(w, &entry)
			if opts.OnReplay != nil {
				func() {
					defer func() {
						if rec := recover(); rec != nil {
							opts.Logger.Warn("idempotency OnReplay panic", "recover", rec)
						}
					}()
					opts.OnReplay(r, key, entry.Status)
				}()
			}
			return
		}
		opts.Logger.Warn("idempotency cache decode failed; ignoring", "err", jerr)
	} else if !errors.Is(err, redis.Nil) {
		if opts.FailClosed && required {
			opts.Logger.Warn("idempotency redis get failed; failing closed", "err", err)
			writeJSONError(w, http.StatusServiceUnavailable, "idempotency_unavailable",
				"idempotency backend unavailable — retry shortly")
			return
		}
		opts.Logger.Warn("idempotency redis get failed; failing open", "err", err)
		next.ServeHTTP(w, r)
		return
	}

	// Acquire lock for concurrent-request detection.
	acquired, err := opts.Redis.SetNX(ctx, lockKey, bodyHash, lockTTL).Result()
	if err != nil {
		if opts.FailClosed && required {
			opts.Logger.Warn("idempotency lock acquire failed; failing closed", "err", err)
			writeJSONError(w, http.StatusServiceUnavailable, "idempotency_unavailable",
				"idempotency backend unavailable — retry shortly")
			return
		}
		opts.Logger.Warn("idempotency lock acquire failed; failing open", "err", err)
		next.ServeHTTP(w, r)
		return
	}
	if !acquired {
		writeJSONError(w, http.StatusConflict, "idempotency_in_progress",
			"another request with the same Idempotency-Key is in progress")
		return
	}

	// Wrap with chi's response writer so we keep http.Flusher / http.Hijacker
	// passthrough (a bare struct wrapper would break SSE and WebSocket
	// upgrades on idempotent routes), and Tee the body into a buffer for the
	// cache snapshot.
	var bodyBuf bytes.Buffer
	rec := chimw.NewWrapResponseWriter(w, r.ProtoMajor)
	rec.Tee(&bodyBuf)
	next.ServeHTTP(rec, r)

	status := rec.Status()
	if status == 0 {
		status = http.StatusOK
	}

	// Only persist 2xx/4xx — 5xx must allow legitimate retries.
	if status >= 200 && status < 500 {
		entry := storedEntry{
			Status:      status,
			Body:        bodyBuf.Bytes(),
			Header:      flattenHeader(w.Header()),
			RequestHash: bodyHash,
			SavedAt:     time.Now().UTC().Format(time.RFC3339),
		}
		buf, err := json.Marshal(entry)
		if err == nil {
			setCtx, setCancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer setCancel()
			if err := opts.Redis.Set(setCtx, cacheKey, buf, opts.ResponseTTL).Err(); err != nil {
				opts.Logger.Warn("idempotency cache set failed", "err", err)
			}
		}
	}

	// Release the in-flight lock regardless of cache outcome.
	rmCtx, rmCancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer rmCancel()
	_ = opts.Redis.Del(rmCtx, lockKey).Err()
}

func shouldApply(r *http.Request) bool {
	switch r.Method {
	case http.MethodPost, http.MethodPatch, http.MethodPut, http.MethodDelete:
		return true
	default:
		return false
	}
}

func readBodyForHash(r *http.Request) ([]byte, error) {
	if r.Body == nil {
		return nil, nil
	}
	limited := io.LimitReader(r.Body, maxBodyHashBytes+1)
	bodyBytes, err := io.ReadAll(limited)
	if err != nil {
		return nil, fmt.Errorf("read body: %w", err)
	}
	if len(bodyBytes) > maxBodyHashBytes {
		return nil, errors.New("body too large for idempotency hashing")
	}
	r.Body = io.NopCloser(bytes.NewReader(bodyBytes))
	return bodyBytes, nil
}

func hashBody(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

type storedEntry struct {
	Status      int               `json:"status"`
	Body        []byte            `json:"body"`
	Header      map[string]string `json:"header"`
	RequestHash string            `json:"request_hash"`
	SavedAt     string            `json:"saved_at"`
}

// skipCachedHeader reports headers that must never be persisted in the
// idempotency cache nor replayed: hop-by-hop headers we recompute, plus
// credential-bearing headers (defence in depth — a handler should not be
// emitting these on an idempotent route, but if one ever does we neither store
// it in Redis nor hand it back to the client on replay).
func skipCachedHeader(k string) bool {
	switch strings.ToLower(k) {
	case "content-length", "transfer-encoding",
		"set-cookie", "authorization", "www-authenticate",
		"proxy-authenticate", "x-api-key":
		return true
	default:
		return false
	}
}

func replayCached(w http.ResponseWriter, entry *storedEntry) {
	for k, v := range entry.Header {
		if skipCachedHeader(k) {
			continue
		}
		w.Header().Set(k, v)
	}
	w.Header().Set(ReplayHeader, "true")
	w.WriteHeader(entry.Status)
	_, _ = w.Write(entry.Body)
}

func flattenHeader(h http.Header) map[string]string {
	out := make(map[string]string, len(h))
	for k, v := range h {
		// Never persist credential/hop-by-hop headers to Redis.
		if skipCachedHeader(k) {
			continue
		}
		if len(v) > 0 {
			out[k] = v[0]
		}
	}
	return out
}

func writeJSONError(w http.ResponseWriter, code int, errCode, msg string) {
	httpx.WriteError(w, code, errCode, msg)
}
