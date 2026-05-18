// Package leader runs a function only on the elected Postgres advisory-
// lock holder. Use it to guard workers whose side effects (emails,
// billing, pricing announcements) must execute exactly once per cluster.
//
// Design:
//   - One Acquire() per worker; lock and worker share the same backend
//     so the lock auto-releases on connection death (no zombie locks).
//   - Lock IDs are int64 constants per worker (see WorkerLocks below).
//   - On contention (lock held by another replica), Run waits
//     `pollInterval` and tries again.
//   - When the lock is lost mid-run (network blip, leader killed), the
//     loop exits and another replica picks it up on the next poll.
//
// This is *defence-in-depth*. Per-tenant claims with `FOR UPDATE SKIP
// LOCKED` should still protect the actual notification/billing rows so
// duplicate execution is impossible even if leader election somehow
// drifts.
package leader

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// WorkerLocks is the canonical registry of advisory-lock IDs used by
// the backend's leader-elected workers. Picking IDs by hand keeps the
// values stable across deploys; a hash would change if names ever
// shifted. Numbers below are simple incrementing constants under a
// shared 0x416E64726F65 ('Androe') prefix.
const (
	OverageWorkerLockID         int64 = 0x416E64726F6501
	QuotaWorkerLockID           int64 = 0x416E64726F6502
	PricingNotifyWorkerLockID   int64 = 0x416E64726F6503
	PricingApplierWorkerLockID  int64 = 0x416E64726F6504
)

// Runner runs Func only when this process owns the advisory lock for Name.
type Runner struct {
	Pool         *pgxpool.Pool
	Name         string
	LockID       int64
	Func         func(ctx context.Context)
	Logger       *slog.Logger
	PollInterval time.Duration // how often to retry acquiring the lock
}

// Start blocks until ctx is cancelled. While holding the lock, Func is
// invoked exactly once; when Func returns, Start re-enters the acquire
// loop so a transient panic in Func doesn't permanently disable the
// worker. Pool conn is held for the entire leader lifetime so the lock
// stays bound to this backend session.
func (r *Runner) Start(ctx context.Context) {
	if r.PollInterval <= 0 {
		r.PollInterval = 30 * time.Second
	}
	logger := r.Logger
	if logger == nil {
		logger = slog.Default()
	}

	for {
		if ctx.Err() != nil {
			return
		}
		if err := r.runOnce(ctx, logger); err != nil {
			if errors.Is(err, context.Canceled) {
				return
			}
			logger.Warn("leader runner failed; retrying after backoff",
				"worker", r.Name, "err", err, "backoff", r.PollInterval)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(r.PollInterval):
		}
	}
}

func (r *Runner) runOnce(ctx context.Context, logger *slog.Logger) error {
	conn, err := r.Pool.Acquire(ctx)
	if err != nil {
		return fmt.Errorf("acquire conn: %w", err)
	}
	// Hold the conn until we exit — release in defer.
	defer conn.Release()

	// pg_try_advisory_lock is non-blocking: returns false when another
	// session already holds the lock. Loser sleeps and retries.
	var locked bool
	if err := conn.QueryRow(ctx, `SELECT pg_try_advisory_lock($1)`, r.LockID).Scan(&locked); err != nil {
		return fmt.Errorf("try lock: %w", err)
	}
	if !locked {
		logger.Debug("leader lock unavailable", "worker", r.Name)
		return nil
	}
	logger.Info("leader acquired", "worker", r.Name, "lock_id", r.LockID)

	// Best-effort unlock when we exit voluntarily. If the process dies
	// before this runs Postgres releases the lock on connection close.
	defer func() {
		ctxUnlock, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		if _, err := conn.Exec(ctxUnlock, `SELECT pg_advisory_unlock($1)`, r.LockID); err != nil {
			logger.Warn("leader unlock failed (lock will drop with conn)", "worker", r.Name, "err", err)
		} else {
			logger.Info("leader released", "worker", r.Name)
		}
	}()

	// Periodically verify the conn is still alive — if it isn't, we may
	// have silently lost the lock without Func noticing.
	heartbeatCtx, heartbeatCancel := context.WithCancel(ctx)
	defer heartbeatCancel()
	go r.heartbeat(heartbeatCtx, conn.Conn(), logger)

	r.Func(heartbeatCtx)
	return nil
}

// heartbeat pings the leader connection every 30s. A failed ping cancels
// the worker context so the run loop drops out and another replica can
// take over.
func (r *Runner) heartbeat(ctx context.Context, conn *pgx.Conn, logger *slog.Logger) {
	t := time.NewTicker(30 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			pingCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
			err := conn.Ping(pingCtx)
			cancel()
			if err != nil {
				logger.Warn("leader heartbeat failed — leader will exit",
					"worker", r.Name, "err", err)
				return
			}
		}
	}
}
