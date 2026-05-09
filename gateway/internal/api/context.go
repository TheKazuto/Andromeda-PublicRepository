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
)

type authedRequest struct {
	User         *store.User
	APIKey       *store.APIKey
	Subscription *store.Subscription
}

type routedRequest struct {
	Key      string
	Upstream string
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

func routeFrom(r *http.Request) *routedRequest {
	v, _ := r.Context().Value(ctxKeyRoute).(*routedRequest)
	return v
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
