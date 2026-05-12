package api

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/shinkalabs/andromeda-gateway/internal/mcp"
	"github.com/shinkalabs/andromeda-gateway/internal/store"
)

// mcpCharger implements mcp.ToolCharger using the same pricer + store
// pipeline the REST chargeQuota middleware uses. Per-tool cost mirrors
// the request_costs catalogue (mcp `ika.sign.submit` = REST cost of
// `ika.sign.submit`).
type mcpCharger struct {
	srv *Server
}

func newMCPCharger(s *Server) *mcpCharger { return &mcpCharger{srv: s} }

// Charge looks up the cost for `toolKey`, deducts it from the active
// subscription, and returns a Refundable backed by RefundTokensV2.
//
// Returned errors:
//   - mcp.QuotaError when the user is out of quota
//   - generic internal error wrapping the store layer otherwise
func (c *mcpCharger) Charge(ctx context.Context, r *http.Request, toolKey string) (mcp.Refundable, error) {
	a := authFrom(r)
	if a == nil || a.User == nil || a.Subscription == nil {
		return nil, errors.New("charge: no active subscription")
	}
	cost := c.srv.pricer.Cost(toolKey)
	if cost < 1 {
		cost = 1
	}

	// Bound the consume the same way the REST chargeQuota middleware does —
	// the inbound ctx is the request context and may be cancelled by the
	// MCP client mid-call.
	cctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	result, err := c.srv.store.ConsumeTokensV2(cctx, a.Subscription.ID, cost)
	switch {
	case err == nil:
	case errors.Is(err, store.ErrQuotaExceeded):
		if c.srv.metrics != nil {
			c.srv.metrics.QuotaExceededTotal.WithLabelValues(a.Subscription.PlanCode).Inc()
		}
		return nil, mcp.QuotaError("token quota exceeded — upgrade plan, wait for rollover, or enable overage")
	default:
		c.srv.logger.Error("mcp consume tokens failed",
			"err", err, "user", a.User.ID, "tool", toolKey)
		return nil, errors.New("internal error")
	}

	// Same per-bucket counters as REST.
	if c.srv.metrics != nil {
		if result.FromCredits > 0 {
			c.srv.metrics.QuotaConsumedTotal.WithLabelValues(a.Subscription.PlanCode, "credits").
				Add(float64(result.FromCredits))
		}
		if result.FromMonthly > 0 {
			c.srv.metrics.QuotaConsumedTotal.WithLabelValues(a.Subscription.PlanCode, "monthly").
				Add(float64(result.FromMonthly))
		}
		if result.FromOverage > 0 {
			c.srv.metrics.QuotaConsumedTotal.WithLabelValues(a.Subscription.PlanCode, "overage").
				Add(float64(result.FromOverage))
		}
	}

	return &mcpRefund{
		srv:            c.srv,
		subscriptionID: a.Subscription.ID,
		consumption:    result,
	}, nil
}

type mcpRefund struct {
	srv            *Server
	subscriptionID string
	consumption    *store.ConsumptionResult
}

func (r *mcpRefund) Refund(ctx context.Context) {
	if r == nil || r.consumption == nil {
		return
	}
	// Detach from the request context (the MCP client may have disconnected,
	// which is exactly when we still need to put the tokens back) but keep
	// any trace span for correlation, and bound it with a short timeout —
	// same posture as the REST proxy's refund().
	rctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 3*time.Second)
	defer cancel()
	if err := r.srv.store.RefundTokensV2(rctx, r.subscriptionID, *r.consumption); err != nil {
		r.srv.logger.Warn("mcp refund failed",
			"err", err, "subscription", r.subscriptionID,
			"from_monthly", r.consumption.FromMonthly,
			"from_overage", r.consumption.FromOverage)
	}
}
