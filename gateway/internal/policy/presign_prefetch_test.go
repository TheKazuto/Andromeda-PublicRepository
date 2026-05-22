package policy

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

type fakeDispatcher struct {
	mu    sync.Mutex
	calls [][2]string // {tenant, dwallet}
	ret   string
	err   error
}

func (f *fakeDispatcher) Presign(_ context.Context, tenant, dwallet string) (string, error) {
	f.mu.Lock()
	f.calls = append(f.calls, [2]string{tenant, dwallet})
	f.mu.Unlock()
	return f.ret, f.err
}

type fakeCache struct {
	mu sync.Mutex
	m  map[string]string
}

func newFakeCache() *fakeCache { return &fakeCache{m: map[string]string{}} }

func (c *fakeCache) Put(_ context.Context, key, val string, _ time.Duration) {
	c.mu.Lock()
	c.m[key] = val
	c.mu.Unlock()
}

func (c *fakeCache) GetDel(_ context.Context, key string) string {
	c.mu.Lock()
	defer c.mu.Unlock()
	v := c.m[key]
	delete(c.m, key)
	return v
}

// fakeMetrics signals goroutine completion so tests are deterministic.
type fakeMetrics struct {
	dispatched chan bool
	harvest    chan bool
}

func newFakeMetrics() *fakeMetrics {
	return &fakeMetrics{dispatched: make(chan bool, 4), harvest: make(chan bool, 4)}
}
func (m *fakeMetrics) PrefetchDispatched(ok bool) { m.dispatched <- ok }
func (m *fakeMetrics) PrefetchHarvest(hit bool)   { m.harvest <- hit }

func tenantHeaderResolver(r *http.Request) string { return r.Header.Get("X-Test-Tenant") }

func reqWithTenant(tenant string) *http.Request {
	r := httptest.NewRequest(http.MethodPost, "/x", nil)
	if tenant != "" {
		r.Header.Set("X-Test-Tenant", tenant)
	}
	return r
}

func wiredService(d PresignDispatcher, c PresignCache, m PresignMetrics) *Service {
	s := &Service{}
	s.WithPresignPrefetch(d, c, tenantHeaderResolver, time.Minute)
	s.WithPresignMetrics(m)
	return s
}

func waitDispatch(t *testing.T, m *fakeMetrics) bool {
	t.Helper()
	select {
	case ok := <-m.dispatched:
		return ok
	case <-time.After(2 * time.Second):
		t.Fatal("presign prefetch did not complete")
		return false
	}
}

func TestPresignPrefetch_DispatchCacheHarvest(t *testing.T) {
	disp := &fakeDispatcher{ret: "deadbeef"}
	cache := newFakeCache()
	m := newFakeMetrics()
	s := wiredService(disp, cache, m)

	s.firePresignPrefetch(reqWithTenant("tenantA"), "DwAddr", "challenge1")
	if ok := waitDispatch(t, m); !ok {
		t.Fatal("expected successful dispatch")
	}
	if len(disp.calls) != 1 || disp.calls[0] != [2]string{"tenantA", "DwAddr"} {
		t.Fatalf("dispatcher got %v", disp.calls)
	}

	got := s.harvestPresign(reqWithTenant("tenantA"), "challenge1")
	if got != "deadbeef" {
		t.Fatalf("harvest = %q, want deadbeef", got)
	}
	// Single-use: a second harvest finds nothing.
	if again := s.harvestPresign(reqWithTenant("tenantA"), "challenge1"); again != "" {
		t.Fatalf("second harvest = %q, want empty (single-use)", again)
	}
}

func TestPresignPrefetch_NonFatalOnError(t *testing.T) {
	disp := &fakeDispatcher{err: errors.New("engine down")}
	cache := newFakeCache()
	m := newFakeMetrics()
	s := wiredService(disp, cache, m)

	s.firePresignPrefetch(reqWithTenant("tenantA"), "DwAddr", "challenge1")
	if ok := waitDispatch(t, m); ok {
		t.Fatal("expected failed dispatch")
	}
	// Nothing cached → submit harvest is empty (the /sign fallback kicks in).
	if got := s.harvestPresign(reqWithTenant("tenantA"), "challenge1"); got != "" {
		t.Fatalf("harvest after error = %q, want empty", got)
	}
}

func TestPresignPrefetch_TenantIsolation(t *testing.T) {
	disp := &fakeDispatcher{ret: "deadbeef"}
	cache := newFakeCache()
	m := newFakeMetrics()
	s := wiredService(disp, cache, m)

	s.firePresignPrefetch(reqWithTenant("tenantA"), "DwAddr", "challenge1")
	waitDispatch(t, m)

	// A different tenant must not harvest tenantA's presign.
	if got := s.harvestPresign(reqWithTenant("tenantB"), "challenge1"); got != "" {
		t.Fatalf("cross-tenant harvest = %q, want empty", got)
	}
	// The rightful tenant still gets it.
	if got := s.harvestPresign(reqWithTenant("tenantA"), "challenge1"); got != "deadbeef" {
		t.Fatalf("owner harvest = %q, want deadbeef", got)
	}
}

func TestPresignPrefetch_DisabledIsNoop(t *testing.T) {
	s := &Service{} // nothing wired
	// Must not panic and must not block (no goroutine work).
	s.firePresignPrefetch(reqWithTenant("tenantA"), "DwAddr", "challenge1")
	if got := s.harvestPresign(reqWithTenant("tenantA"), "challenge1"); got != "" {
		t.Fatalf("disabled harvest = %q, want empty", got)
	}
}

func TestPresignCacheKey(t *testing.T) {
	if k := presignCacheKey("tenantA", "abcd"); k != "presign:tenantA:abcd" {
		t.Fatalf("key = %q", k)
	}
}
