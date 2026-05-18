package audit

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// SignerWorker drains the audit_log outbox: rows inserted by Recorder.Append
// with signature NULL are signed by this worker and the signature written
// back. Safe to run on every gateway replica — FOR UPDATE SKIP LOCKED
// partitions work between them without coordination.
//
// Why a worker:
//   - Vault Transit can take 5-50ms per signature; doing it inline blocks
//     a request thread holding a Postgres transaction.
//   - Per-tenant chains still serialise correctly because chain integrity
//     depends on prev_hash + entry_hash (computed inline by Append), not
//     the signature.
//   - Replay on boot: the first tick picks up everything signature-NULL,
//     so a process that crashed mid-flush catches up automatically.
//
// Operational posture:
//   - Vault degraded → audit_outbox depth grows → `gateway_audit_degraded`
//     gauge flips to 1, alert fires. Hot path is unaffected because Append
//     no longer signs.
//   - Worker error → tick continues; metrics surface the failure rate.
type SignerWorker struct {
	pool   *pgxpool.Pool
	signer Signer
	logger *slog.Logger
	obs    Observer

	batch        int
	tick         time.Duration
	degradedAge  time.Duration
}

// SignerWorkerOptions tunes the worker. Zero values fall back to defaults.
type SignerWorkerOptions struct {
	Batch        int           // rows per tick (default 100)
	Tick         time.Duration // poll cadence (default 500ms)
	DegradedAge  time.Duration // outbox older than this flips `degraded=1` (default 30s)
	Observer     Observer
}

// NewSignerWorker wires the worker. The Signer is shared with the
// Recorder so PublicKey() stays consistent across the chain.
func NewSignerWorker(pool *pgxpool.Pool, signer Signer, logger *slog.Logger, opts SignerWorkerOptions) *SignerWorker {
	if logger == nil {
		logger = slog.Default()
	}
	w := &SignerWorker{
		pool:        pool,
		signer:      signer,
		logger:      logger,
		obs:         opts.Observer,
		batch:       envInt("AUDIT_SIGNER_BATCH", opts.Batch, 100),
		tick:        envDur("AUDIT_SIGNER_TICK_MS", opts.Tick, 500*time.Millisecond),
		degradedAge: envDur("AUDIT_SIGNER_DEGRADED_AGE_SEC", opts.DegradedAge, 30*time.Second),
	}
	return w
}

// Run blocks until ctx is cancelled. Each tick: claim → sign → update.
func (w *SignerWorker) Run(ctx context.Context) {
	w.logger.Info("audit signer worker started",
		"batch", w.batch, "tick", w.tick.String(), "degraded_age", w.degradedAge.String())
	t := time.NewTicker(w.tick)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			w.logger.Info("audit signer worker stopped")
			return
		case <-t.C:
			w.tickOnce(ctx)
		}
	}
}

type pendingRow struct {
	Seq             int64
	EntryHash       []byte
	PendingSignedAt time.Time
}

func (w *SignerWorker) tickOnce(ctx context.Context) {
	signed, oldestAgeSec, depth := w.processBatch(ctx)
	if w.obs != nil {
		w.obs.SetAuditOutboxDepth(depth)
		w.obs.SetAuditOutboxOldestSeconds(oldestAgeSec)
		if oldestAgeSec > w.degradedAge.Seconds() {
			w.obs.SetAuditDegraded(true)
		} else {
			w.obs.SetAuditDegraded(false)
		}
	}
	_ = signed
}

// processBatch claims up to w.batch rows pending signature, signs each,
// and updates the row. Returns (signed_count, oldest_pending_age_seconds,
// outbox_depth).
func (w *SignerWorker) processBatch(ctx context.Context) (int, float64, int64) {
	tx, err := w.pool.Begin(ctx)
	if err != nil {
		w.logger.Warn("audit signer: begin tx failed", "err", err)
		return 0, 0, 0
	}
	rollback := func() {
		if err := tx.Rollback(ctx); err != nil && !errors.Is(err, pgx.ErrTxClosed) {
			_ = err
		}
	}

	rows, err := tx.Query(ctx, `
		WITH picked AS (
			SELECT seq FROM audit_log
			WHERE signature IS NULL
			ORDER BY seq
			FOR UPDATE SKIP LOCKED
			LIMIT $1
		)
		SELECT seq, entry_hash, COALESCE(pending_signed_at, NOW())
		FROM audit_log
		WHERE seq IN (SELECT seq FROM picked)
		ORDER BY seq
	`, w.batch)
	if err != nil {
		rollback()
		w.logger.Warn("audit signer: claim query failed", "err", err)
		return 0, 0, 0
	}

	var pending []pendingRow
	for rows.Next() {
		var p pendingRow
		if err := rows.Scan(&p.Seq, &p.EntryHash, &p.PendingSignedAt); err != nil {
			rows.Close()
			rollback()
			w.logger.Warn("audit signer: scan failed", "err", err)
			return 0, 0, 0
		}
		pending = append(pending, p)
	}
	rows.Close()

	if len(pending) == 0 {
		// Even with nothing to sign, refresh the depth gauge so an outbox
		// of zero is reported (not just stale).
		_ = tx.Commit(ctx)
		depth := w.outboxDepth(ctx)
		return 0, 0, depth
	}

	oldestAgeSec := time.Since(pending[0].PendingSignedAt).Seconds()

	signed := 0
	for _, p := range pending {
		signStart := time.Now()
		sig, err := w.signer.Sign(ctx, p.EntryHash)
		if w.obs != nil {
			w.obs.ObserveAuditSign(w.signerBackend(), time.Since(signStart).Seconds())
		}
		if err != nil {
			if w.obs != nil {
				w.obs.IncAuditFailure("sign")
			}
			w.logger.Warn("audit signer: sign failed", "seq", p.Seq, "err", err)
			// Stop this batch — Vault is probably down. The rows are
			// still locked in this tx; rollback releases them so the
			// next tick re-tries (or another replica picks them up).
			rollback()
			depth := w.outboxDepth(ctx)
			return signed, oldestAgeSec, depth
		}
		if _, err := tx.Exec(ctx, `
			UPDATE audit_log
			SET signature = $2, pending_signed_at = NULL
			WHERE seq = $1
		`, p.Seq, sig); err != nil {
			rollback()
			if w.obs != nil {
				w.obs.IncAuditFailure("update")
			}
			w.logger.Warn("audit signer: update failed", "seq", p.Seq, "err", err)
			depth := w.outboxDepth(ctx)
			return signed, oldestAgeSec, depth
		}
		signed++
	}

	if err := tx.Commit(ctx); err != nil {
		if w.obs != nil {
			w.obs.IncAuditFailure("commit")
		}
		w.logger.Warn("audit signer: commit failed", "err", err)
		depth := w.outboxDepth(ctx)
		return 0, oldestAgeSec, depth
	}

	depth := w.outboxDepth(ctx)
	return signed, oldestAgeSec, depth
}

// outboxDepth counts remaining pending rows. Cheap thanks to the
// partial index idx_audit_log_pending.
func (w *SignerWorker) outboxDepth(ctx context.Context) int64 {
	depthCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	var n int64
	if err := w.pool.QueryRow(depthCtx, `SELECT COUNT(*) FROM audit_log WHERE signature IS NULL`).Scan(&n); err != nil {
		w.logger.Warn("audit signer: outbox depth query failed", "err", err)
		return 0
	}
	return n
}

func (w *SignerWorker) signerBackend() string {
	switch w.signer.(type) {
	case *VaultTransitSigner:
		return "vault"
	default:
		return "env"
	}
}

func envInt(key string, override int, fallback int) int {
	if override > 0 {
		return override
	}
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			return n
		}
	}
	return fallback
}

func envDur(key string, override time.Duration, fallback time.Duration) time.Duration {
	if override > 0 {
		return override
	}
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		// Tolerate both bare integers (interpreted by key suffix) and Go
		// duration strings. Keep it simple: integer-only here.
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			if strings.HasSuffix(key, "_MS") {
				return time.Duration(n) * time.Millisecond
			}
			if strings.HasSuffix(key, "_SEC") {
				return time.Duration(n) * time.Second
			}
			return time.Duration(n) * time.Millisecond
		}
	}
	if fallback > 0 {
		return fallback
	}
	return 500 * time.Millisecond
}

