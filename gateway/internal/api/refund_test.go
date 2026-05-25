package api

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/shinkalabs/andromeda-gateway/internal/store"
)

// TestRefundOnError verifies the Local-route refund middleware: a 5xx technical
// failure refunds the charge; a 2xx does not. (Local routes — PolicyEngine,
// oracle, intents — don't get the proxy's auto-refund, so this middleware does.)
func TestRefundOnError(t *testing.T) {
	fs := &fakeStore{bundle: authedBundle([]string{"write"}, nil)}
	s := &Server{store: fs, logger: slog.New(slog.NewTextHandler(io.Discard, nil))}

	// Build a request carrying the auth + consumption + opID that chargeQuota
	// stashes upstream of the refund middleware.
	mkReq := func() *http.Request {
		r := httptest.NewRequest(http.MethodPost, "/v1/intents/swap/submit", nil)
		r = withAuth(r, &authedRequest{User: fs.bundle.User, APIKey: fs.bundle.APIKey, Subscription: fs.bundle.Subscription})
		r = withConsumption(r, &store.ConsumptionResult{Cost: 1, FromMonthly: 1})
		r = withOpID(r, "op-1")
		return r
	}

	// 5xx → refund.
	h500 := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusBadGateway) })
	s.refundOnError(h500).ServeHTTP(httptest.NewRecorder(), mkReq())
	if got := atomic.LoadInt32(&fs.refunded); got != 1 {
		t.Fatalf("expected 1 refund on 5xx, got %d", got)
	}

	// 2xx → no additional refund.
	h200 := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	s.refundOnError(h200).ServeHTTP(httptest.NewRecorder(), mkReq())
	if got := atomic.LoadInt32(&fs.refunded); got != 1 {
		t.Errorf("expected no extra refund on 2xx, total refunds = %d", got)
	}

	// 4xx (caller's fault) → no refund either.
	h400 := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusBadRequest) })
	s.refundOnError(h400).ServeHTTP(httptest.NewRecorder(), mkReq())
	if got := atomic.LoadInt32(&fs.refunded); got != 1 {
		t.Errorf("4xx must not refund, total refunds = %d", got)
	}
}
