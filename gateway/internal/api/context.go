package api

import (
	"context"
	"net/http"

	"github.com/shinkalabs/andromeda-gateway/internal/store"
)

type ctxKey int

const (
	ctxKeyAuth ctxKey = iota
	ctxKeyRoute
	ctxKeyCost
	ctxKeyConsumption
	ctxKeyOpID
)

type authedRequest struct {
	User         *store.User
	APIKey       *store.APIKey
	Subscription *store.Subscription
}

type routedRequest struct {
	Key string
}

func withAuth(r *http.Request, a *authedRequest) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), ctxKeyAuth, a))
}

func authFrom(r *http.Request) *authedRequest {
	v, _ := r.Context().Value(ctxKeyAuth).(*authedRequest)
	return v
}

func withRoute(r *http.Request, rt *routedRequest) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), ctxKeyRoute, rt))
}

func withCost(r *http.Request, cost int) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), ctxKeyCost, cost))
}

func costFrom(r *http.Request) int {
	v, _ := r.Context().Value(ctxKeyCost).(int)
	return v
}

// withConsumption stashes the per-bucket breakdown produced by
// ConsumeTokensV2. The proxy reads it in refund() to know how much to
// undo per bucket on upstream failure.
func withConsumption(r *http.Request, c *store.ConsumptionResult) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), ctxKeyConsumption, c))
}

func consumptionFrom(r *http.Request) *store.ConsumptionResult {
	v, _ := r.Context().Value(ctxKeyConsumption).(*store.ConsumptionResult)
	return v
}

// withOpID stashes the billing op id used to charge this request so the
// proxy's refund() reverses the exact same ledger operation (idempotent +
// clamped). Set by chargeQuota alongside the consumption breakdown.
func withOpID(r *http.Request, opID string) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), ctxKeyOpID, opID))
}

func opIDFrom(r *http.Request) string {
	v, _ := r.Context().Value(ctxKeyOpID).(string)
	return v
}
