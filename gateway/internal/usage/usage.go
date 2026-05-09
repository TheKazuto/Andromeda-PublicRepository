// Package usage records per-request usage events. Writes are buffered
// through a channel and flushed by a background worker so the request
// hot-path never blocks on the database.
package usage

import (
	"context"
	"log/slog"
	"sync/atomic"
	"time"

	"github.com/shinkalabs/andromeda-gateway/internal/store"
)

const defaultBufferSize = 4096

type Recorder struct {
	store  store.Store
	logger *slog.Logger
	ch     chan store.UsageEvent
	done   chan struct{}
	drops  atomic.Uint64
}

func NewRecorder(s store.Store, logger *slog.Logger) *Recorder {
	return &Recorder{
		store:  s,
		logger: logger,
		ch:     make(chan store.UsageEvent, defaultBufferSize),
		done:   make(chan struct{}),
	}
}

// Start spawns the writer goroutine. Cancel ctx to stop, then wait on
// Done() to confirm the buffer was drained.
func (r *Recorder) Start(ctx context.Context) {
	go func() {
		defer close(r.done)
		for {
			select {
			case <-ctx.Done():
				r.drain()
				return
			case ev := <-r.ch:
				r.write(ev)
			}
		}
	}()
}

func (r *Recorder) Done() <-chan struct{} { return r.done }

// Drops returns the cumulative count of events that were silently
// discarded because the buffer was full. Surfaced by /health/ready and
// (eventually) Prometheus to detect sustained backpressure.
func (r *Recorder) Drops() uint64 { return r.drops.Load() }

// BufferDepth reports the number of queued events waiting to be flushed.
// Compare to BufferCapacity() to see how close we are to dropping.
func (r *Recorder) BufferDepth() int { return len(r.ch) }

// BufferCapacity returns the channel's buffer size.
func (r *Recorder) BufferCapacity() int { return cap(r.ch) }

// Record enqueues an event. Drops the event with a warning if the buffer
// is full — usage data is best-effort, not load-bearing for billing
// integrity (the canonical counter is subscriptions.tokens_used).
func (r *Recorder) Record(ev store.UsageEvent) {
	select {
	case r.ch <- ev:
	default:
		dropped := r.drops.Add(1)
		// Log every drop while drops are rare; throttle once we cross
		// 100 to avoid log floods under sustained backpressure.
		if dropped <= 100 || dropped%1000 == 0 {
			r.logger.Warn("usage buffer full — dropping event",
				"route", ev.RouteKey,
				"user", ev.UserID,
				"total_drops", dropped,
				"depth", len(r.ch),
				"capacity", cap(r.ch))
		}
	}
}

func (r *Recorder) write(ev store.UsageEvent) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := r.store.InsertUsageEvent(ctx, ev); err != nil {
		r.logger.Warn("usage insert failed",
			"route", ev.RouteKey, "user", ev.UserID, "err", err)
	}
}

func (r *Recorder) drain() {
	for {
		select {
		case ev := <-r.ch:
			r.write(ev)
		default:
			return
		}
	}
}
