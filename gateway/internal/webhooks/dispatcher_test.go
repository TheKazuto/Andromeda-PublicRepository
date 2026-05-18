package webhooks

import (
	"log/slog"
	"testing"
	"time"

	"golang.org/x/time/rate"
)

// newTestDispatcher returns a Dispatcher with no store / no http client.
// Only the bits we test (endpoint limiter + janitor) need to exist.
func newTestDispatcher() *Dispatcher {
	return &Dispatcher{
		logger:           slog.Default(),
		endpointLimiters: map[string]*endpointLimiter{},
	}
}

func TestAllowEndpoint_AllowsBelowBurst(t *testing.T) {
	d := newTestDispatcher()
	// Both default values (50/100) live in package-level vars and are
	// read by allowEndpoint. The first `perEndpointBurst` calls must
	// pass regardless of timing.
	const id = "ep-1"
	for i := 0; i < perEndpointBurst; i++ {
		if !d.allowEndpoint(id) {
			t.Fatalf("call %d should be allowed (within burst)", i)
		}
	}
}

func TestAllowEndpoint_DeniesAfterBurst(t *testing.T) {
	d := newTestDispatcher()
	const id = "ep-2"
	// Drain the burst.
	for i := 0; i < perEndpointBurst; i++ {
		_ = d.allowEndpoint(id)
	}
	// Next call: within the same instant, tokens are still 0 → denied.
	if d.allowEndpoint(id) {
		t.Errorf("call after burst exhausted should be denied")
	}
}

func TestAllowEndpoint_IsolatedPerEndpoint(t *testing.T) {
	d := newTestDispatcher()
	// Exhaust endpoint A.
	for i := 0; i < perEndpointBurst; i++ {
		_ = d.allowEndpoint("ep-a")
	}
	if d.allowEndpoint("ep-a") {
		t.Error("ep-a should be denied")
	}
	// ep-b has its own bucket — should be allowed.
	if !d.allowEndpoint("ep-b") {
		t.Error("ep-b should be allowed independently of ep-a")
	}
}

func TestAllowEndpoint_LimiterCreatedOnFirstCall(t *testing.T) {
	d := newTestDispatcher()
	if _, ok := d.endpointLimiters["new-endpoint"]; ok {
		t.Fatal("precondition: map should be empty")
	}
	_ = d.allowEndpoint("new-endpoint")
	if _, ok := d.endpointLimiters["new-endpoint"]; !ok {
		t.Error("limiter should be created on first allowEndpoint")
	}
}

func TestAllowEndpoint_UpdatesLastSeen(t *testing.T) {
	d := newTestDispatcher()
	_ = d.allowEndpoint("ep-3")
	first := d.endpointLimiters["ep-3"].lastSeen
	time.Sleep(20 * time.Millisecond)
	_ = d.allowEndpoint("ep-3")
	second := d.endpointLimiters["ep-3"].lastSeen
	if !second.After(first) {
		t.Errorf("lastSeen should advance: first=%v second=%v", first, second)
	}
}

func TestPruneEndpointLimiters_KeepsRecent(t *testing.T) {
	d := newTestDispatcher()
	// Seed two endpoints: one fresh, one stale.
	d.endpointLimiters["fresh"] = &endpointLimiter{
		limiter:  rate.NewLimiter(10, 10),
		lastSeen: time.Now(),
	}
	d.endpointLimiters["stale"] = &endpointLimiter{
		limiter:  rate.NewLimiter(10, 10),
		lastSeen: time.Now().Add(-2 * time.Duration(endpointLimiterIdleSec) * time.Second),
	}
	d.pruneEndpointLimiters()
	if _, ok := d.endpointLimiters["fresh"]; !ok {
		t.Error("fresh endpoint should survive prune")
	}
	if _, ok := d.endpointLimiters["stale"]; ok {
		t.Error("stale endpoint should be evicted")
	}
}

func TestPruneEndpointLimiters_NoOpOnEmptyMap(t *testing.T) {
	d := newTestDispatcher()
	// Must not panic.
	d.pruneEndpointLimiters()
	if len(d.endpointLimiters) != 0 {
		t.Error("empty map should remain empty")
	}
}

// statusOutcome is the small helper used to label dispatcher metrics by
// HTTP status class. Worth a sanity test because the label cardinality
// would explode if someone broke the bucketing.
func TestStatusOutcome_Buckets(t *testing.T) {
	cases := map[int]string{
		200: "2xx",
		201: "2xx",
		299: "2xx",
		301: "other",
		400: "4xx",
		404: "4xx",
		499: "4xx",
		500: "5xx",
		504: "5xx",
		0:   "other",
	}
	for code, want := range cases {
		if got := statusOutcome(code); got != want {
			t.Errorf("statusOutcome(%d) = %q, want %q", code, got, want)
		}
	}
}
