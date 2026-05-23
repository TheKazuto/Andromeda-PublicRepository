package api

import (
	"context"
	"net/http"
	"time"
)

// =============================================================================
// /health         — liveness (cheap, returns 200 if process alive)
// /health/ready   — readiness (deep checks: DB + Redis + upstreams)
// =============================================================================
//
// Liveness signals the process is alive — used by Railway to decide
// whether to restart the container. We keep it cheap so a transient DB
// outage doesn't trigger restart loops.
//
// Readiness signals "should this instance accept traffic?" — used by
// load balancers, deploy gates, and operators inspecting health. It
// runs the deep checks; partial failures return 503 with a per-check
// breakdown so ops can see exactly what's wrong.

type checkStatus struct {
	OK        bool   `json:"ok"`
	LatencyMs int    `json:"latencyMs,omitempty"`
	Error     string `json:"error,omitempty"`
	Skipped   bool   `json:"skipped,omitempty"`
	// Detail is a tiny structured payload a check may attach for ops.
	// Keep it free of sensitive figures — /health/ready is public, so
	// anything secret (e.g. the gas sponsor balance) goes on /metrics.
	Detail map[string]any `json:"detail,omitempty"`
}

type readyResponse struct {
	OK          bool                   `json:"ok"`
	GeneratedAt time.Time              `json:"generatedAt"`
	Checks      map[string]checkStatus `json:"checks"`
	UsageBuffer usageBufferStatus      `json:"usageBuffer"`
}

type usageBufferStatus struct {
	Depth    int    `json:"depth"`
	Capacity int    `json:"capacity"`
	Drops    uint64 `json:"drops"`
}

// handleHealthLiveness is the cheap "is the process alive" probe.
// Returns 200 unconditionally — Railway's healthcheck hits this.
func (s *Server) handleHealthLiveness(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// handleHealthReadiness runs the deep checks. Critical (DB) failure
// returns 503; non-critical (Redis fail-open, optional upstreams)
// return 200 with the per-check status flagged not-ok.
func (s *Server) handleHealthReadiness(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 8*time.Second)
	defer cancel()

	checks := map[string]checkStatus{}
	criticalFailed := false

	// Postgres — critical.
	checks["postgres"] = pingDB(ctx, s)
	if !checks["postgres"].OK {
		criticalFailed = true
	}

	// Redis — non-critical when RATE_LIMIT_FAIL_OPEN.
	checks["redis"] = pingRedis(ctx, s)
	if !checks["redis"].OK && !checks["redis"].Skipped && !s.cfg.RateLimitFailOpen {
		criticalFailed = true
	}

	// Upstreams — non-critical (gateway can still serve admin/billing
	// even if the engines are temporarily down).
	checks["ika_upstream"] = pingUpstream(ctx, s, "ika")
	checks["encrypt_upstream"] = pingUpstream(ctx, s, "encrypt")

	// Gas sponsor balance — non-critical (gateway still serves read-only
	// flows when depleted), but surfaced so ops can refill before tenants
	// hit "insufficient lamports" mid-flow.
	checks["gas_sponsor"] = checkGasSponsor(ctx, s)

	resp := readyResponse{
		OK:          !criticalFailed,
		GeneratedAt: time.Now().UTC(),
		Checks:      checks,
		UsageBuffer: usageBufferStatus{
			Depth:    s.usage.BufferDepth(),
			Capacity: s.usage.BufferCapacity(),
			Drops:    s.usage.Drops(),
		},
	}

	status := http.StatusOK
	if criticalFailed {
		status = http.StatusServiceUnavailable
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, status, resp)
}

func pingDB(ctx context.Context, s *Server) checkStatus {
	start := time.Now()
	if err := s.store.Pool().Ping(ctx); err != nil {
		return checkStatus{OK: false, Error: err.Error(),
			LatencyMs: int(time.Since(start).Milliseconds())}
	}
	return checkStatus{OK: true, LatencyMs: int(time.Since(start).Milliseconds())}
}

func pingRedis(ctx context.Context, s *Server) checkStatus {
	if s.cfg.RedisURL == "" {
		return checkStatus{OK: true, Skipped: true}
	}
	start := time.Now()
	if err := s.limiter.Ping(ctx); err != nil {
		return checkStatus{OK: false, Error: err.Error(),
			LatencyMs: int(time.Since(start).Milliseconds())}
	}
	return checkStatus{OK: true, LatencyMs: int(time.Since(start).Milliseconds())}
}

func pingUpstream(ctx context.Context, s *Server, name string) checkStatus {
	target := s.upstreams.Get(name)
	if target == nil || target.BaseURL == nil {
		return checkStatus{OK: true, Skipped: true}
	}
	probeCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	start := time.Now()
	res, err := target.Call(probeCtx, "GET", "/health", nil, nil, nil)
	if err != nil {
		return checkStatus{OK: false, Error: err.Error(),
			LatencyMs: int(time.Since(start).Milliseconds())}
	}
	if res.StatusCode >= 500 {
		return checkStatus{OK: false, Error: "upstream returned " + httpStatusText(res.StatusCode),
			LatencyMs: int(time.Since(start).Milliseconds())}
	}
	return checkStatus{OK: true, LatencyMs: int(time.Since(start).Milliseconds())}
}

func checkGasSponsor(ctx context.Context, s *Server) checkStatus {
	if s.policyV3Service == nil || s.policyV3Service.GasSponsor == nil {
		return checkStatus{OK: true, Skipped: true}
	}
	start := time.Now()
	probeCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	healthy, bal, err := s.policyV3Service.GasSponsor.Healthy(probeCtx)
	latency := int(time.Since(start).Milliseconds())
	if err != nil {
		// Network error talking to Solana RPC — surface as not-ok but do
		// NOT leak the underlying RPC URL/host in the message.
		return checkStatus{OK: false, Error: "balance probe failed", LatencyMs: latency}
	}
	// /health/ready is public, so the raw balance never goes in the response
	// body — exposing it lets anyone time attacks for when the sponsor runs
	// low. The figure is recorded on the admin-gated /metrics instead.
	s.metrics.SetGasSponsorBalance(bal)
	if !healthy {
		return checkStatus{
			OK: false, LatencyMs: latency,
			Error: "gas sponsor balance below minimum",
		}
	}
	return checkStatus{OK: true, LatencyMs: latency}
}

func httpStatusText(code int) string {
	if t := http.StatusText(code); t != "" {
		return t
	}
	return "HTTP error"
}
