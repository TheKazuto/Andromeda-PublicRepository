package audit

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Snapshotter periodically dumps audit_log to an S3-compatible bucket
// (Cloudflare R2 by default) as a defence-in-depth measure. If the DB
// is compromised, an operator can still re-verify the ed25519 chain
// against the offline snapshot.
//
// Flow per tick:
//  1. Read the highest seq from audit_log.
//  2. Read the last snapshotted seq from audit_snapshot_log.
//  3. If the gap is non-empty, fetch rows (first_seq..last_seq) and
//     stream-write them as NDJSON, then gzip the buffer in memory.
//  4. PUT to R2: `<prefix>/<YYYY-MM-DD>-<first_seq>-<last_seq>.ndjson.gz`.
//  5. Record the row in audit_snapshot_log.
//
// Memory note: the whole batch is buffered in memory. For a 50 KB
// average row × 100k rows = 5 GB — too much. The default batch cap is
// `SNAPSHOT_MAX_ROWS=100000` with `SNAPSHOT_MAX_BYTES_MB=512` so each
// upload stays bounded. If the gap exceeds the cap, the worker uploads
// one batch and re-runs on the next tick.
//
// Wire via leader runner (see backend/internal/leader or
// gateway/internal/leader) — running this on every replica would waste
// bandwidth and duplicate rows.
type Snapshotter struct {
	pool     *pgxpool.Pool
	s3       *S3Client
	prefix   string
	logger   *slog.Logger
	obs      SnapshotObserver
	maxRows  int
	maxBytes int64
	tick     time.Duration
}

// SnapshotObserver is the minimum metrics surface the snapshotter uses.
// Nil-safe.
type SnapshotObserver interface {
	ObserveSnapshotUpload(rows int, bytes int64)
	IncSnapshotFailure(stage string)
	SetSnapshotLastSuccessUnix(unix int64)
}

// SnapshotterOptions wires runtime knobs.
type SnapshotterOptions struct {
	Prefix   string // object key prefix, e.g. "audit/"
	MaxRows  int
	MaxBytes int64
	Tick     time.Duration
	Observer SnapshotObserver
}

// NewSnapshotter constructs a Snapshotter. The S3Client is required —
// the caller must validate env vars before constructing.
func NewSnapshotter(pool *pgxpool.Pool, s3 *S3Client, logger *slog.Logger, opts SnapshotterOptions) *Snapshotter {
	if logger == nil {
		logger = slog.Default()
	}
	prefix := strings.Trim(opts.Prefix, "/")
	if prefix != "" {
		prefix = prefix + "/"
	}
	return &Snapshotter{
		pool:     pool,
		s3:       s3,
		prefix:   prefix,
		logger:   logger,
		obs:      opts.Observer,
		maxRows:  envIntSnap("AUDIT_SNAPSHOT_MAX_ROWS", opts.MaxRows, 100_000),
		maxBytes: int64(envIntSnap("AUDIT_SNAPSHOT_MAX_BYTES_MB", int(opts.MaxBytes/(1024*1024)), 512)) * 1024 * 1024,
		tick:     envDurSnap("AUDIT_SNAPSHOT_INTERVAL_HOURS", opts.Tick, 24*time.Hour),
	}
}

// Run blocks until ctx is cancelled, ticking every `tick`. The first
// tick fires after a small initial delay so boot doesn't race with the
// signer worker draining the outbox.
func (s *Snapshotter) Run(ctx context.Context) {
	s.logger.Info("audit snapshotter started",
		"tick", s.tick.String(), "max_rows", s.maxRows, "max_bytes_mb", s.maxBytes/(1024*1024))
	// Initial delay (5 min): let the signer worker stabilise + give
	// boot some headroom before adding upload bandwidth.
	select {
	case <-ctx.Done():
		return
	case <-time.After(5 * time.Minute):
	}
	s.runOnce(ctx)
	t := time.NewTicker(s.tick)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			s.logger.Info("audit snapshotter stopped")
			return
		case <-t.C:
			s.runOnce(ctx)
		}
	}
}

type snapshotRow struct {
	Seq             int64           `json:"seq"`
	APIKeyID        string          `json:"api_key_id"`
	TS              time.Time       `json:"ts"`
	EventType       string          `json:"event_type"`
	ResourceType    string          `json:"resource_type"`
	ResourceID      string          `json:"resource_id"`
	Actor           string          `json:"actor"`
	Payload         json.RawMessage `json:"payload"`
	CUConsumed      *int            `json:"cu_consumed,omitempty"`
	PrevHashHex     string          `json:"prev_hash_hex"`
	EntryHashHex    string          `json:"entry_hash_hex"`
	SignatureHex    string          `json:"signature_hex,omitempty"`
	PendingSignedAt *time.Time      `json:"pending_signed_at,omitempty"`
}

func (s *Snapshotter) runOnce(ctx context.Context) {
	// 1. cursor
	lastSeq, err := s.lastSnapshottedSeq(ctx)
	if err != nil {
		s.fail("cursor", err)
		return
	}
	// 2. range
	rows, totalBytes, firstSeq, batchLast, err := s.fetchRange(ctx, lastSeq)
	if err != nil {
		s.fail("fetch", err)
		return
	}
	if len(rows) == 0 {
		s.logger.Debug("audit snapshotter: no new rows", "from_seq", lastSeq)
		if s.obs != nil {
			s.obs.SetSnapshotLastSuccessUnix(time.Now().Unix())
		}
		return
	}
	// 3. build NDJSON.gz
	body, err := buildNDJSONGzip(rows)
	if err != nil {
		s.fail("build", err)
		return
	}
	// 4. upload
	objectKey := fmt.Sprintf("%s%s-%d-%d.ndjson.gz",
		s.prefix,
		time.Now().UTC().Format("2006-01-02"),
		firstSeq, batchLast)
	if err := s.s3.PutObject(ctx, objectKey, body, "application/gzip"); err != nil {
		s.fail("upload", err)
		return
	}
	// 5. record
	if err := s.recordSnapshot(ctx, firstSeq, batchLast, int64(len(rows)), totalBytes, objectKey); err != nil {
		// Object was uploaded; failing here means we'll re-upload the
		// same range next tick. The unique index on (date, last_seq)
		// catches the duplicate insert.
		s.fail("record", err)
		return
	}
	s.logger.Info("audit snapshotter uploaded",
		"object_key", objectKey, "rows", len(rows),
		"first_seq", firstSeq, "last_seq", batchLast)
	if s.obs != nil {
		s.obs.ObserveSnapshotUpload(len(rows), int64(len(body)))
		s.obs.SetSnapshotLastSuccessUnix(time.Now().Unix())
	}
}

func (s *Snapshotter) fail(stage string, err error) {
	s.logger.Warn("audit snapshotter failed", "stage", stage, "err", err)
	if s.obs != nil {
		s.obs.IncSnapshotFailure(stage)
	}
}

func (s *Snapshotter) lastSnapshottedSeq(ctx context.Context) (int64, error) {
	var seq int64
	err := s.pool.QueryRow(ctx, `
		SELECT COALESCE(MAX(last_seq), 0) FROM audit_snapshot_log
	`).Scan(&seq)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return 0, fmt.Errorf("last snapshotted seq: %w", err)
	}
	return seq, nil
}

func (s *Snapshotter) fetchRange(ctx context.Context, fromSeq int64) (rows []snapshotRow, totalBytes int64, firstSeq, lastSeq int64, err error) {
	q := `
		SELECT seq, api_key_id, ts, event_type, resource_type, resource_id, actor,
		       payload::text, cu_consumed, prev_hash, entry_hash, signature, pending_signed_at
		FROM audit_log
		WHERE seq > $1
		ORDER BY seq
		LIMIT $2
	`
	cur, err := s.pool.Query(ctx, q, fromSeq, s.maxRows)
	if err != nil {
		return nil, 0, 0, 0, fmt.Errorf("query: %w", err)
	}
	defer cur.Close()
	for cur.Next() {
		var r snapshotRow
		var apiKeyID string
		var payload string
		var prev, hash, sig []byte
		if err := cur.Scan(&r.Seq, &apiKeyID, &r.TS, &r.EventType, &r.ResourceType, &r.ResourceID, &r.Actor,
			&payload, &r.CUConsumed, &prev, &hash, &sig, &r.PendingSignedAt); err != nil {
			return nil, 0, 0, 0, fmt.Errorf("scan: %w", err)
		}
		r.APIKeyID = apiKeyID
		r.Payload = json.RawMessage(payload)
		r.PrevHashHex = hexEncodeBytes(prev)
		r.EntryHashHex = hexEncodeBytes(hash)
		if len(sig) > 0 {
			r.SignatureHex = hexEncodeBytes(sig)
		}
		totalBytes += int64(len(payload))
		if totalBytes >= s.maxBytes {
			break
		}
		if len(rows) == 0 {
			firstSeq = r.Seq
		}
		lastSeq = r.Seq
		rows = append(rows, r)
	}
	if err := cur.Err(); err != nil {
		return nil, 0, 0, 0, fmt.Errorf("rows err: %w", err)
	}
	return rows, totalBytes, firstSeq, lastSeq, nil
}

func (s *Snapshotter) recordSnapshot(ctx context.Context, firstSeq, lastSeq, rowCount, byteCount int64, objectKey string) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO audit_snapshot_log
		    (snapshot_date, first_seq, last_seq, row_count, byte_count, object_key)
		VALUES (CURRENT_DATE, $1, $2, $3, $4, $5)
		ON CONFLICT ON CONSTRAINT uq_audit_snapshot_log_date_seq DO NOTHING
	`, firstSeq, lastSeq, rowCount, byteCount, objectKey)
	return err
}

func buildNDJSONGzip(rows []snapshotRow) ([]byte, error) {
	var raw bytes.Buffer
	enc := json.NewEncoder(&raw)
	enc.SetEscapeHTML(false)
	for _, r := range rows {
		if err := enc.Encode(r); err != nil {
			return nil, fmt.Errorf("encode row: %w", err)
		}
	}
	var gz bytes.Buffer
	w, err := gzip.NewWriterLevel(&gz, gzip.BestCompression)
	if err != nil {
		return nil, fmt.Errorf("gzip writer: %w", err)
	}
	if _, err := w.Write(raw.Bytes()); err != nil {
		_ = w.Close()
		return nil, fmt.Errorf("gzip write: %w", err)
	}
	if err := w.Close(); err != nil {
		return nil, fmt.Errorf("gzip close: %w", err)
	}
	return gz.Bytes(), nil
}

func hexEncodeBytes(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	// re-use the helper from routes.go via package-internal call
	return hexEncode(b)
}

func envIntSnap(key string, override, fallback int) int {
	if override > 0 {
		return override
	}
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		var n int
		_, err := fmt.Sscanf(v, "%d", &n)
		if err == nil && n > 0 {
			return n
		}
	}
	return fallback
}

func envDurSnap(key string, override time.Duration, fallback time.Duration) time.Duration {
	if override > 0 {
		return override
	}
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		var n int
		_, err := fmt.Sscanf(v, "%d", &n)
		if err == nil && n > 0 {
			if strings.HasSuffix(key, "_HOURS") {
				return time.Duration(n) * time.Hour
			}
			if strings.HasSuffix(key, "_MINUTES") {
				return time.Duration(n) * time.Minute
			}
			if strings.HasSuffix(key, "_SEC") {
				return time.Duration(n) * time.Second
			}
		}
	}
	return fallback
}
