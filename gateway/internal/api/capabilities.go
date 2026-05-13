package api

import (
	"net/http"

	"github.com/shinkalabs/andromeda-gateway/internal/routes"
)

// capabilitiesPayload is the public-facing snapshot returned by GET
// /capabilities. It tells clients which engines and feature modules are
// wired in this deployment so they can render an accurate capability
// matrix without out-of-band knowledge.
//
// Only safe metadata is included — no secrets, no internal hostnames.
type capabilitiesPayload struct {
	Service  string                  `json:"service"`
	Version  string                  `json:"version"`
	Env      string                  `json:"env"`
	Engines  map[string]engineStatus `json:"engines"`
	Features featureFlags            `json:"features"`
	MCP      mcpStatus               `json:"mcp"`
	Routes   routesSummary           `json:"routes"`
}

type engineStatus struct {
	Configured bool `json:"configured"`
}

type featureFlags struct {
	// `audit`/`webhooks`/`policies` reflect: store/recorder/service wired in.
	Audit    bool `json:"audit"`
	Webhooks bool `json:"webhooks"`
	Policies bool `json:"policies"`
	// `futureSign` is ONLY true when the watcher goroutines are running.
	// Having the store alone is not enough — without the watcher, armed
	// triggers never fire.
	FutureSign bool `json:"futureSign"`
	// `rateLimit` and `idempotency` are true only when Redis is configured;
	// without Redis the middleware is a no-op. See `rateLimitMode` and
	// `redisBackedIdempotency` below for the operational nuance the client
	// needs to make routing decisions.
	RateLimit   bool `json:"rateLimit"`
	Idempotency bool `json:"idempotency"`

	// FutureSignWatcher mirrors `FutureSign` — kept as a separate field so
	// clients/devs can grep capability JSON for the explicit watcher state.
	FutureSignWatcher bool `json:"futureSignWatcher"`

	// RedisBackedIdempotency is true ONLY when both Redis is configured AND
	// the idempotency middleware is the real (Redis-backed) implementation.
	// When false the gateway accepts the `Idempotency-Key` header but does
	// not actually deduplicate — callers must not rely on it.
	RedisBackedIdempotency bool `json:"redisBackedIdempotency"`

	// RateLimitMode is one of "disabled" | "fail_open" | "fail_closed":
	//   - "disabled":    Redis unconfigured; every request is admitted.
	//   - "fail_open":   Redis configured; on Redis outage the limiter
	//                    admits requests (default).
	//   - "fail_closed": Redis configured; on Redis outage the limiter
	//                    REJECTS requests.
	RateLimitMode string `json:"rateLimitMode"`
}

type mcpStatus struct {
	Enabled   bool   `json:"enabled"`
	Transport string `json:"transport"`
	Path      string `json:"path"`
	ToolCount int    `json:"toolCount"`
}

type routesSummary struct {
	Total   int `json:"total"`
	Ika     int `json:"ika"`
	Encrypt int `json:"encrypt"`
}

func (s *Server) handleCapabilities(w http.ResponseWriter, _ *http.Request) {
	ikaCount, encCount := 0, 0
	for _, rt := range routes.All {
		switch rt.Upstream {
		case routes.UpstreamIka:
			ikaCount++
		case routes.UpstreamEncrypt:
			encCount++
		}
	}

	redisConfigured := s.cfg.RedisURL != ""
	watcherRunning := s.futureSignWatcherRunning

	rateLimitMode := "disabled"
	if redisConfigured {
		if s.cfg.RateLimitFailOpen {
			rateLimitMode = "fail_open"
		} else {
			rateLimitMode = "fail_closed"
		}
	}

	payload := capabilitiesPayload{
		Service: "andromeda-gateway",
		Version: "0.1.0",
		Env:     s.cfg.Env,
		Engines: map[string]engineStatus{
			routes.UpstreamIka: {
				Configured: s.cfg.IkaUpstreamURL != "" && s.cfg.InternalAPIKey != "",
			},
			routes.UpstreamEncrypt: {
				Configured: s.cfg.EncryptUpstreamURL != "" && s.cfg.InternalAPIKey != "",
			},
		},
		Features: featureFlags{
			Audit:                  s.auditRecorder != nil,
			Webhooks:               s.webhookStore != nil,
			Policies:               s.policyService != nil,
			FutureSign:             s.futureSignStore != nil && watcherRunning,
			RateLimit:              redisConfigured,
			Idempotency:            redisConfigured,
			FutureSignWatcher:      watcherRunning,
			RedisBackedIdempotency: redisConfigured && s.idempotencyChain != nil,
			RateLimitMode:          rateLimitMode,
		},
		MCP: mcpStatus{
			Enabled:   s.mcpTools != nil,
			Transport: "http",
			Path:      "/mcp",
			ToolCount: mcpToolCount(s),
		},
		Routes: routesSummary{
			Total:   len(routes.All),
			Ika:     ikaCount,
			Encrypt: encCount,
		},
	}

	writeJSON(w, http.StatusOK, payload)
}

func mcpToolCount(s *Server) int {
	if s == nil || s.mcpTools == nil {
		return 0
	}
	return s.mcpTools.Count()
}
