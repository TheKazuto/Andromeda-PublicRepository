package api

import (
	"encoding/json"
	"io"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/shinkalabs/andromeda-gateway/internal/routes"
)

// =============================================================================
// Public reference data
// =============================================================================

// BalconCentsPer1k is the reference rate the dashboard surfaces to devs:
// $4 per 1.000 tokens. Used for usd-equivalent estimates in pricing
// responses. Per-plan effective rates are visible in `plans.priceCents
// / plans.monthlyTokens`.
const BalconCentsPer1k = 400

// publicRoute is the catalogue projection returned by GET /v1/pricing.
type publicRoute struct {
	Method     string `json:"method"`
	Path       string `json:"path"`
	Key        string `json:"key"`
	Upstream   string `json:"upstream"`
	RateClass  string `json:"rateClass"`
	Idempotent bool   `json:"idempotent"`
	CostTokens int    `json:"costTokens"`
}

type pricingCatalogPayload struct {
	Service      string        `json:"service"`
	TokenSymbol  string        `json:"tokenSymbol"`
	Rate         pricingRate   `json:"rate"`
	DefaultCost  int           `json:"defaultCostTokens"`
	GeneratedAt  time.Time     `json:"generatedAt"`
	Routes       []publicRoute `json:"routes"`
	TotalRoutes  int           `json:"totalRoutes"`
}

type pricingRate struct {
	BalconCentsPer1k int    `json:"balconCentsPer1k"`
	BalconUSDPer1k   string `json:"balconUsdPer1k"`
	Note             string `json:"note"`
}

func (s *Server) handlePricingCatalog(w http.ResponseWriter, r *http.Request) {
	costs, err := s.store.ListRequestCosts(r.Context())
	if err != nil {
		s.logger.Error("pricing list failed", "err", err)
		writeError(w, http.StatusInternalServerError, "internal_error", "internal error")
		return
	}
	costByKey := make(map[string]int, len(costs))
	for _, c := range costs {
		costByKey[c.RouteKey] = c.CostTokens
	}

	out := make([]publicRoute, 0, len(routes.All))
	for _, rt := range routes.All {
		c, ok := costByKey[rt.Key]
		if !ok {
			c = s.cfg.DefaultRequestCost
		}
		out = append(out, publicRoute{
			Method:     rt.Method,
			Path:       rt.Path,
			Key:        rt.Key,
			Upstream:   rt.Upstream,
			RateClass:  rt.EffectiveRateClass(),
			Idempotent: rt.Idempotent,
			CostTokens: c,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Key < out[j].Key })

	w.Header().Set("Cache-Control", "public, max-age=60")
	writeJSON(w, http.StatusOK, pricingCatalogPayload{
		Service:     "andromeda-gateway",
		TokenSymbol: "ANDROMEDA_TOKEN",
		Rate: pricingRate{
			BalconCentsPer1k: BalconCentsPer1k,
			BalconUSDPer1k:   "$4.00",
			Note:             "Symbolic rate. Plans offer additional discount; overage is billed at this rate.",
		},
		DefaultCost: s.cfg.DefaultRequestCost,
		GeneratedAt: time.Now().UTC(),
		Routes:      out,
		TotalRoutes: len(out),
	})
}

// =============================================================================
// POST /v1/pricing/estimate — sum of route costs for a hypothetical workload
// =============================================================================

type pricingEstimateRequest struct {
	Routes []pricingEstimateItem `json:"routes"`
}

type pricingEstimateItem struct {
	Key   string `json:"key"`
	Count int    `json:"count"` // 0 -> 1
}

type pricingEstimateResponse struct {
	Items             []pricingEstimateItemOut `json:"items"`
	TotalTokens       int64                    `json:"totalTokens"`
	EstimatedUSDCents int64                    `json:"estimatedUsdCents"`
	Rate              pricingRate              `json:"rate"`
	UnknownRoutes     []string                 `json:"unknownRoutes,omitempty"`
}

type pricingEstimateItemOut struct {
	Key        string `json:"key"`
	Count      int    `json:"count"`
	CostTokens int    `json:"costTokens"`
	Subtotal   int64  `json:"subtotal"`
}

func (s *Server) handlePricingEstimate(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, 64<<10))
	if err != nil {
		writeError(w, http.StatusBadRequest, "bad_request", "could not read body")
		return
	}
	var req pricingEstimateRequest
	if err := json.Unmarshal(body, &req); err != nil {
		writeError(w, http.StatusBadRequest, "bad_request", "invalid JSON body")
		return
	}
	if len(req.Routes) == 0 {
		writeError(w, http.StatusBadRequest, "bad_request", "routes required")
		return
	}
	if len(req.Routes) > 1000 {
		writeError(w, http.StatusBadRequest, "bad_request", "too many routes (max 1000)")
		return
	}

	costs, err := s.store.ListRequestCosts(r.Context())
	if err != nil {
		s.logger.Error("pricing estimate cost lookup failed", "err", err)
		writeError(w, http.StatusInternalServerError, "internal_error", "internal error")
		return
	}
	costByKey := make(map[string]int, len(costs))
	for _, c := range costs {
		costByKey[c.RouteKey] = c.CostTokens
	}

	resp := pricingEstimateResponse{
		Items: make([]pricingEstimateItemOut, 0, len(req.Routes)),
		Rate: pricingRate{
			BalconCentsPer1k: BalconCentsPer1k,
			BalconUSDPer1k:   "$4.00",
			Note:             "Symbolic rate. Plan discount applies on actual consumption.",
		},
	}
	var (
		total   int64
		unknown []string
		seen    = map[string]bool{}
	)
	for _, item := range req.Routes {
		key := strings.TrimSpace(item.Key)
		if key == "" {
			continue
		}
		count := item.Count
		if count <= 0 {
			count = 1
		}
		c, ok := costByKey[key]
		if !ok {
			c = s.cfg.DefaultRequestCost
			if !seen[key] {
				unknown = append(unknown, key)
				seen[key] = true
			}
		}
		sub := int64(c) * int64(count)
		resp.Items = append(resp.Items, pricingEstimateItemOut{
			Key:        key,
			Count:      count,
			CostTokens: c,
			Subtotal:   sub,
		})
		total += sub
	}
	resp.TotalTokens = total
	resp.EstimatedUSDCents = total * int64(BalconCentsPer1k) / 1000
	resp.UnknownRoutes = unknown

	writeJSON(w, http.StatusOK, resp)
}

// /v1/me/balance and /v1/me/usage moved to the backend in M3.
