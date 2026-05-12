package idempotency

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
)

func discardLogger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

// countingHandler responds with a fixed status/body and counts invocations.
func countingHandler(status int, body string, calls *int32) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(calls, 1)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = io.WriteString(w, body)
	})
}

func do(t *testing.T, mw func(http.Handler) http.Handler, h http.Handler, method, path string, body string, headers map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	mw(h).ServeHTTP(rec, req)
	return rec
}

func newMW(t *testing.T, opts MiddlewareOptions) (func(http.Handler) http.Handler, *miniredis.Miniredis) {
	t.Helper()
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("miniredis: %v", err)
	}
	t.Cleanup(mr.Close)
	if opts.Redis == nil {
		opts.Redis = redis.NewClient(&redis.Options{Addr: mr.Addr(), DialTimeout: 250 * time.Millisecond, MaxRetries: -1})
		t.Cleanup(func() { _ = opts.Redis.Close() })
	}
	if opts.Logger == nil {
		opts.Logger = discardLogger()
	}
	if opts.APIKeyIDFromCtx == nil {
		opts.APIKeyIDFromCtx = func(*http.Request) string { return "key-1" }
	}
	return New(opts), mr
}

func TestNoRedisIsPassthrough(t *testing.T) {
	var calls int32
	mw := New(MiddlewareOptions{Logger: discardLogger()}) // Redis nil
	rec := do(t, mw, countingHandler(200, `{"ok":true}`, &calls), http.MethodPost, "/x", `{}`,
		map[string]string{HeaderName: "abcdefgh"})
	if rec.Code != 200 || calls != 1 {
		t.Fatalf("code=%d calls=%d, want 200/1", rec.Code, calls)
	}
}

func TestGETIsNotIntercepted(t *testing.T) {
	var calls int32
	mw, _ := newMW(t, MiddlewareOptions{})
	rec := do(t, mw, countingHandler(200, `body`, &calls), http.MethodGet, "/x", "",
		map[string]string{HeaderName: "abcdefgh"})
	if rec.Code != 200 || calls != 1 || rec.Header().Get(ReplayHeader) != "" {
		t.Fatalf("GET should pass straight through: code=%d calls=%d replay=%q", rec.Code, calls, rec.Header().Get(ReplayHeader))
	}
}

func TestMissingKeyIsPassthrough(t *testing.T) {
	var calls int32
	mw, _ := newMW(t, MiddlewareOptions{})
	rec := do(t, mw, countingHandler(201, `{}`, &calls), http.MethodPost, "/x", `{}`, nil)
	if rec.Code != 201 || calls != 1 {
		t.Fatalf("no Idempotency-Key should pass through: code=%d calls=%d", rec.Code, calls)
	}
}

func TestKeyLengthBounds(t *testing.T) {
	var calls int32
	mw, _ := newMW(t, MiddlewareOptions{})
	for _, key := range []string{"short", strings.Repeat("x", 201)} {
		rec := do(t, mw, countingHandler(200, `{}`, &calls), http.MethodPost, "/x", `{}`,
			map[string]string{HeaderName: key})
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("key %q: code=%d, want 400", key, rec.Code)
		}
		if !strings.Contains(rec.Body.String(), "invalid_idempotency_key") {
			t.Fatalf("key %q: body=%q, want invalid_idempotency_key", key, rec.Body.String())
		}
	}
	if calls != 0 {
		t.Fatalf("handler should not run on bad key, ran %d times", calls)
	}
}

func TestReplaySameBody(t *testing.T) {
	var calls int32
	mw, _ := newMW(t, MiddlewareOptions{})
	h := countingHandler(200, `{"result":42}`, &calls)
	hdrs := map[string]string{HeaderName: "idem-key-aaaa", "Content-Type": "application/json"}

	r1 := do(t, mw, h, http.MethodPost, "/op", `{"a":1}`, hdrs)
	if r1.Code != 200 || r1.Header().Get(ReplayHeader) == "true" {
		t.Fatalf("first call: code=%d replay=%q", r1.Code, r1.Header().Get(ReplayHeader))
	}
	r2 := do(t, mw, h, http.MethodPost, "/op", `{"a":1}`, hdrs)
	if r2.Code != 200 || r2.Header().Get(ReplayHeader) != "true" {
		t.Fatalf("replay: code=%d replay=%q", r2.Code, r2.Header().Get(ReplayHeader))
	}
	if r2.Body.String() != `{"result":42}` {
		t.Fatalf("replay body=%q, want cached body", r2.Body.String())
	}
	if calls != 1 {
		t.Fatalf("handler ran %d times, want 1 (replay must not re-execute)", calls)
	}
}

func TestCollisionDifferentBody(t *testing.T) {
	var calls int32
	mw, _ := newMW(t, MiddlewareOptions{})
	h := countingHandler(200, `{}`, &calls)
	hdrs := map[string]string{HeaderName: "idem-key-bbbb"}

	if r := do(t, mw, h, http.MethodPost, "/op", `{"a":1}`, hdrs); r.Code != 200 {
		t.Fatalf("first call code=%d", r.Code)
	}
	r := do(t, mw, h, http.MethodPost, "/op", `{"a":2}`, hdrs)
	if r.Code != http.StatusUnprocessableEntity {
		t.Fatalf("collision code=%d, want 422", r.Code)
	}
	if !strings.Contains(r.Body.String(), "idempotency_collision") {
		t.Fatalf("collision body=%q", r.Body.String())
	}
	if calls != 1 {
		t.Fatalf("handler ran %d times on collision, want 1", calls)
	}
}

func TestConcurrentInFlight(t *testing.T) {
	mw, _ := newMW(t, MiddlewareOptions{})
	entered := make(chan struct{})
	release := make(chan struct{})
	h := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		close(entered)
		<-release
		w.WriteHeader(200)
		_, _ = io.WriteString(w, `{}`)
	})
	hdrs := map[string]string{HeaderName: "idem-key-cccc"}

	go func() { _ = do(t, mw, h, http.MethodPost, "/op", `{}`, hdrs) }()
	<-entered // first request is now inside the handler, holding the lock

	r2 := do(t, mw, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Error("second request must not reach the handler while the first holds the lock")
	}), http.MethodPost, "/op", `{}`, hdrs)
	if r2.Code != http.StatusConflict {
		t.Fatalf("in-flight second request code=%d, want 409", r2.Code)
	}
	if !strings.Contains(r2.Body.String(), "idempotency_in_progress") {
		t.Fatalf("body=%q", r2.Body.String())
	}
	close(release)
}

func TestServerErrorNotCached(t *testing.T) {
	var calls int32
	mw, _ := newMW(t, MiddlewareOptions{})
	h := countingHandler(503, `{"error":"upstream"}`, &calls)
	hdrs := map[string]string{HeaderName: "idem-key-dddd"}

	if r := do(t, mw, h, http.MethodPost, "/op", `{}`, hdrs); r.Code != 503 {
		t.Fatalf("first call code=%d", r.Code)
	}
	r2 := do(t, mw, h, http.MethodPost, "/op", `{}`, hdrs)
	if r2.Code != 503 || r2.Header().Get(ReplayHeader) == "true" {
		t.Fatalf("5xx must not replay from cache: code=%d replay=%q", r2.Code, r2.Header().Get(ReplayHeader))
	}
	if calls != 2 {
		t.Fatalf("handler ran %d times, want 2 (5xx re-executes)", calls)
	}
}

func TestRedisDownFailsOpen(t *testing.T) {
	var calls int32
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatal(err)
	}
	client := redis.NewClient(&redis.Options{Addr: mr.Addr(), DialTimeout: 250 * time.Millisecond, MaxRetries: -1})
	defer client.Close()
	mr.Close() // outage
	mw := New(MiddlewareOptions{Redis: client, Logger: discardLogger(), APIKeyIDFromCtx: func(*http.Request) string { return "k" }})
	r := do(t, mw, countingHandler(200, `{}`, &calls), http.MethodPost, "/op", `{}`,
		map[string]string{HeaderName: "idem-key-eeee"})
	if r.Code != 200 || calls != 1 {
		t.Fatalf("redis down should fail open: code=%d calls=%d", r.Code, calls)
	}
}

func TestBodyTooLarge(t *testing.T) {
	var calls int32
	mw, _ := newMW(t, MiddlewareOptions{})
	big := bytes.Repeat([]byte("a"), (1<<20)+1)
	rec := do(t, mw, countingHandler(200, `{}`, &calls), http.MethodPost, "/op", string(big),
		map[string]string{HeaderName: "idem-key-ffff"})
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "body_too_large") {
		t.Fatalf("oversized body: code=%d body=%q", rec.Code, rec.Body.String())
	}
	if calls != 0 {
		t.Fatalf("handler ran %d times on oversized body, want 0", calls)
	}
}

func TestOnReplayCallback(t *testing.T) {
	var calls int32
	var replays atomic.Int32
	mw, _ := newMW(t, MiddlewareOptions{
		OnReplay: func(_ *http.Request, key string, status int) {
			if key != "idem-key-gggg" || status != 200 {
				t.Errorf("OnReplay got key=%q status=%d", key, status)
			}
			replays.Add(1)
		},
	})
	h := countingHandler(200, `{}`, &calls)
	hdrs := map[string]string{HeaderName: "idem-key-gggg"}
	_ = do(t, mw, h, http.MethodPost, "/op", `{}`, hdrs)
	_ = do(t, mw, h, http.MethodPost, "/op", `{}`, hdrs)
	if replays.Load() != 1 {
		t.Fatalf("OnReplay fired %d times, want 1", replays.Load())
	}
}

// Sanity: a couple of well-formed cached entries round-trip through JSON
// (guards against accidental shape changes to storedEntry).
func TestStoredEntryRoundTrip(t *testing.T) {
	e := storedEntry{Status: 200, Body: []byte(`{"x":1}`), Header: map[string]string{"Content-Type": "application/json"}, RequestHash: "deadbeef", SavedAt: time.Now().UTC().Format(time.RFC3339)}
	b, err := json.Marshal(e)
	if err != nil {
		t.Fatal(err)
	}
	var back storedEntry
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatal(err)
	}
	if back.Status != 200 || string(back.Body) != `{"x":1}` || back.RequestHash != "deadbeef" {
		t.Fatalf("round-trip mismatch: %+v", back)
	}
}
