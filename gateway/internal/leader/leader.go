// Package leader runs a function only on the elected Postgres advisory-
// lock holder. Use it to guard workers whose side effects (Solana log
// ingestion, future-sign trigger watcher) must execute exactly once per
// cluster — without this, multi-replica gateway deployments would
// duplicate every on-chain webhook fan-out and every future-sign
// completion attempt.
//
// Mirrors backend/internal/leader. Kept as separate code because Go
// modules don't cross between gateway and backend.
//
// Design:
//   - One pool.Acquire() per worker; lock and worker share the same
//     backend so the lock auto-releases on connection death (no zombie
//     locks).
//   - Lock IDs are int64 constants per worker (see WorkerLocks below).
//   - On contention (lock held by another replica), Run waits
//     `pollInterval` and tries again.
//   - When the lock is lost mid-run (network blip, leader killed), the
//     loop exits and another replica picks it up on the next poll.
//
// Defence-in-depth note: workers that already have row-level claims
// (e.g. webhook dispatcher with `FOR UPDATE SKIP LOCKED` + lease) keep
// running multi-replica because the per-row claim is the authoritative
// dedup primitive there. Leader election here covers workers without
// such a claim (listener that fans Solana events into webhook publish,
// future-sign watcher that completes a sign once).
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
// the gateway's leader-elected workers. Picked manually so values stay
// stable across deploys; a hash would shift if names ever changed.
const (
	SolanaListenerLockID    int64 = 0x416E64726F6701
	FutureSignWatcherLockID int64 = 0x416E64726F6702
	AuditSnapshotLockID     int64 = 0x416E64726F6703
	OracleRelayLockID       int64 = 0x416E64726F6704
	OracleMonitorLockID     int64 = 0x416E64726F6705
	RiskIngestorLockID      int64 = 0x416E64726F6706
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

	defer func() {
		ctxUnlock, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		if _, err := conn.Exec(ctxUnlock, `SELECT pg_advisory_unlock($1)`, r.LockID); err != nil {
			logger.Warn("leader unlock failed (lock will drop with conn)", "worker", r.Name, "err", err)
		} else {
			logger.Info("leader released", "worker", r.Name)
		}
	}()

	heartbeatCtx, heartbeatCancel := context.WithCancel(ctx)
	defer heartbeatCancel()
	go r.heartbeat(heartbeatCtx, conn.Conn(), logger)

	r.Func(heartbeatCtx)
	return nil
}

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
