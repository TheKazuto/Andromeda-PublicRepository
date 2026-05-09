package api

import (
	"net/http"
	"sort"
	"time"
)

// =============================================================================
// GET /v1/pricing/plans — public plan catalogue (consumed by the dashboard)
//
// Note: /v1/pricing (route catalogue) and /v1/pricing/estimate stay on the
// gateway because they depend on the gateway's compile-time route registry
// (`routes.All`) and the per-route cost map. Backend exposes /plans only.
// =============================================================================

type publicPlan struct {
	Code              string         `json:"code"`
	Name              string         `json:"name"`
	MonthlyTokens     int64          `json:"monthlyTokens"`
	PriceCents        int            `json:"priceCents"`
	AnnualPriceCents  int            `json:"annualPriceCents"`
	OveragePer1kCents int            `json:"overagePer1kCents"`
	ReadRPS           int            `json:"readRps"`
	ReadBurst         int            `json:"readBurst"`
	TxRPS             int            `json:"txRps"`
	TxBurst           int            `json:"txBurst"`
	Features          map[string]any `json:"features"`
	IsGiftable        bool           `json:"isGiftable"`
	SortOrder         int            `json:"sortOrder"`
}

type publicPlansPayload struct {
	Plans       []publicPlan `json:"plans"`
	GeneratedAt time.Time    `json:"generatedAt"`
}

func (s *Server) handlePricingPlans(w http.ResponseWriter, r *http.Request) {
	plans, err := s.store.ListPlans(r.Context())
	if err != nil {
		writeInternal(w)
		return
	}
	out := make([]publicPlan, 0, len(plans))
	for _, p := range plans {
		if !p.IsActive {
			continue
		}
		out = append(out, publicPlan{
			Code:              p.Code,
			Name:              p.Name,
			MonthlyTokens:     p.MonthlyTokens,
			PriceCents:        p.PriceCents,
			AnnualPriceCents:  p.AnnualPriceCents,
			OveragePer1kCents: p.OveragePer1kCents,
			ReadRPS:           p.ReadRPS,
			ReadBurst:         p.ReadBurst,
			TxRPS:             p.TxRPS,
			TxBurst:           p.TxBurst,
			Features:          p.Features,
			IsGiftable:        p.IsGiftable,
			SortOrder:         p.SortOrder,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].SortOrder < out[j].SortOrder })

	w.Header().Set("Cache-Control", "public, max-age=60")
	writeJSON(w, http.StatusOK, publicPlansPayload{
		Plans:       out,
		GeneratedAt: time.Now().UTC(),
	})
}
