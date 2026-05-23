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
	ret   PresignResult
	err   error
}

func (f *fakeDispatcher) Presign(_ context.Context, tenant, dwallet string) (PresignResult, error) {
	f.mu.Lock()
	f.calls = append(f.calls, [2]string{tenant, dwallet})
	f.mu.Unlock()
	return f.ret, f.err
}

func (f *fakeDispatcher) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.calls)
}

type fakeCache struct {
	mu       sync.Mutex
	m        map[string]PresignResult
	locks    map[string]bool
	curEpoch uint64
	dispatch int
}

func newFakeCache() *fakeCache {
	return &fakeCache{m: map[string]PresignResult{}, locks: map[string]bool{}}
}

func (c *fakeCache) Lock(_ context.Context, key string, _ time.Duration) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.locks[key] {
		return false
	}
	c.locks[key] = true
	return true
}

func (c *fakeCache) Unlock(_ context.Context, key string) {
	c.mu.Lock()
	delete(c.locks, key)
	c.mu.Unlock()
}

func (c *fakeCache) AllowDispatch(_ context.Context, _ string, max int) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.dispatch++
	if max <= 0 {
		return true
	}
	return c.dispatch <= max
}

func (c *fakeCache) Put(_ context.Context, key string, r PresignResult, _ time.Duration) {
	c.mu.Lock()
	c.m[key] = r
	if r.Epoch > c.curEpoch {
		c.curEpoch = r.Epoch
	}
	c.mu.Unlock()
}

func (c *fakeCache) GetDel(_ context.Context, key string) (PresignResult, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	v, ok := c.m[key]
	delete(c.m, key)
	return v, ok
}

func (c *fakeCache) CurrentEpoch(_ context.Context) uint64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.curEpoch
}

func (c *fakeCache) setEpoch(e uint64) {
	c.mu.Lock()
	c.curEpoch = e
	c.mu.Unlock()
}

// fakeMetrics signals goroutine completion so tests are deterministic.
type fakeMetrics struct {
	dispatched chan bool
	harvest    chan bool
	leaked     chan string
}

func newFakeMetrics() *fakeMetrics {
	return &fakeMetrics{
		dispatched: make(chan bool, 4),
		harvest:    make(chan bool, 4),
		leaked:     make(chan string, 4),
	}
}
func (m *fakeMetrics) PrefetchDispatched(ok bool)   { m.dispatched <- ok }
func (m *fakeMetrics) PrefetchHarvest(hit bool)     { m.harvest <- hit }
func (m *fakeMetrics) PrefetchLeaked(reason string) { m.leaked <- reason }

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
	disp := &fakeDispatcher{ret: PresignResult{Hex: "deadbeef"}}
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
	disp := &fakeDispatcher{ret: PresignResult{Hex: "deadbeef"}}
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
	if k := presignLockKey("tenantA", "abcd"); k != "presign:lock:tenantA:abcd" {
		t.Fatalf("lock key = %q", k)
	}
}

// B — a re-issued challenge for the same (tenant, digest) must not fire a
// second presign (the lock is held), so the first prefetch is never orphaned.
func TestPresignPrefetch_IdempotentDispatch(t *testing.T) {
	disp := &fakeDispatcher{ret: PresignResult{Hex: "deadbeef"}}
	cache := newFakeCache()
	m := newFakeMetrics()
	s := wiredService(disp, cache, m)

	s.firePresignPrefetch(reqWithTenant("tenantA"), "DwAddr", "challenge1")
	waitDispatch(t, m)

	// Same (tenant, challenge) again — the lock is still held, so no dispatch.
	s.firePresignPrefetch(reqWithTenant("tenantA"), "DwAddr", "challenge1")
	if n := disp.callCount(); n != 1 {
		t.Fatalf("dispatcher called %d times, want 1 (idempotent dispatch)", n)
	}
}

// A — a presign whose epoch has been overtaken by the network must be dropped
// at harvest (client allocates inline) and counted as a leak.
func TestPresignPrefetch_StaleEpochDropped(t *testing.T) {
	disp := &fakeDispatcher{ret: PresignResult{Hex: "deadbeef", Epoch: 5}}
	cache := newFakeCache()
	m := newFakeMetrics()
	s := wiredService(disp, cache, m)

	s.firePresignPrefetch(reqWithTenant("tenantA"), "DwAddr", "challenge1")
	waitDispatch(t, m)

	// Network epoch advances past the presign's epoch.
	cache.setEpoch(6)

	if got := s.harvestPresign(reqWithTenant("tenantA"), "challenge1"); got != "" {
		t.Fatalf("stale-epoch harvest = %q, want empty (drop → inline)", got)
	}
	select {
	case reason := <-m.leaked:
		if reason != "stale_epoch" {
			t.Fatalf("leak reason = %q, want stale_epoch", reason)
		}
	case <-time.After(time.Second):
		t.Fatal("expected a stale_epoch leak metric")
	}
}

// A — a presign still within its epoch is served normally.
func TestPresignPrefetch_FreshEpochServed(t *testing.T) {
	disp := &fakeDispatcher{ret: PresignResult{Hex: "deadbeef", Epoch: 5}}
	cache := newFakeCache()
	m := newFakeMetrics()
	s := wiredService(disp, cache, m)

	s.firePresignPrefetch(reqWithTenant("tenantA"), "DwAddr", "challenge1")
	waitDispatch(t, m)

	if got := s.harvestPresign(reqWithTenant("tenantA"), "challenge1"); got != "deadbeef" {
		t.Fatalf("fresh-epoch harvest = %q, want deadbeef", got)
	}
}
