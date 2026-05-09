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
	Audit       bool `json:"audit"`
	Webhooks    bool `json:"webhooks"`
	Policies    bool `json:"policies"`
	FutureSign  bool `json:"futureSign"`
	RateLimit   bool `json:"rateLimit"`
	Idempotency bool `json:"idempotency"`
}

type mcpStatus struct {
	Enabled   bool   `json:"enabled"`
	Transport string `json:"transport"`
	Path      string `json:"path"`
	ToolCount int    `json:"toolCount"`
}

type routesSummary struct {
	Total int `json:"total"`
	Ika   int `json:"ika"`
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
			Audit:       s.auditRecorder != nil,
			Webhooks:    s.webhookStore != nil,
			Policies:    s.policyService != nil,
			FutureSign:  s.futureSignStore != nil,
			RateLimit:   s.cfg.RedisURL != "",
			Idempotency: s.idempotencyChain != nil,
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
