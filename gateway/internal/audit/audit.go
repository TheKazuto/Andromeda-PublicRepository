// Package audit implements the per-tenant signed hash-chain ledger
// described in CLAUDE.md §6 / Andromeda Features Roadmap §6.
//
// Each entry is appended atomically:
//
//	prev_hash  = entry_hash of the previous record for the same api_key_id
//	             (or 32 zero bytes for the first record).
//	entry_hash = SHA-256(prev_hash || canonical(record))
//	signature  = ed25519_sign(audit_key, entry_hash)
//
// The audit signing key is loaded from ANDROMEDA_AUDIT_PRIVATE_KEY (base64,
// 64-byte ed25519 seed-or-private-key). For production this MUST be migrated
// to a KMS (Cloudflare KMS or equivalent) — the env-var path is local-dev
// only and emits a startup warning.
package audit

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Event is the application-facing audit envelope. Resource and Actor are
// free-form, but the catalogue used by the system lives in events.go.
type Event struct {
	APIKeyID     uuid.UUID
	EventType    string
	ResourceType string
	ResourceID   string
	Actor        string
	Payload      map[string]any
	CUConsumed   *int
}

// Entry is the durable form persisted to audit_log.
type Entry struct {
	Seq          int64
	APIKeyID     uuid.UUID
	TS           time.Time
	EventType    string
	ResourceType string
	ResourceID   string
	Actor        string
	Payload      json.RawMessage
	CUConsumed   *int
	PrevHash     []byte
	EntryHash    []byte
	Signature    []byte
}

// Observer is the minimum metrics surface the Recorder + SignerWorker
// use. Lets us export Vault/env signer latency, append-stage failure
// counters, and the outbox depth/age without depending on the gateway
// metrics package directly. Nil-safe.
type Observer interface {
	ObserveAuditSign(backend string, seconds float64)
	ObserveAuditAppend(seconds float64)
	IncAuditFailure(stage string)
	SetAuditOutboxDepth(depth int64)
	SetAuditOutboxOldestSeconds(seconds float64)
	SetAuditDegraded(degraded bool)
}

// Recorder appends signed entries to audit_log. Safe for concurrent use.
type Recorder struct {
	pool   *pgxpool.Pool
	signer Signer
	logger *slog.Logger
	obs    Observer

	// chainLocks serialises Append within this process, per api_key_id,
	// ahead of the transactional pg_advisory_xact_lock (which serialises
	// across instances). Without it, concurrent appends for one tenant
	// would each open a transaction and queue on the advisory lock,
	// holding pool connections for nothing. Keyed by api_key_id string;
	// entries are never evicted (bounded by the tenant count).
	chainLocks sync.Map // string -> *sync.Mutex
}

// WithObserver attaches a metrics observer. Returns the Recorder for
// fluent boot-time wiring. Nil observer is a no-op.
func (r *Recorder) WithObserver(o Observer) *Recorder {
	r.obs = o
	return r
}

// signerBackend returns a short label for the active Signer implementation,
// used as a Prometheus label. Keeps cardinality bounded to {env,vault}.
func (r *Recorder) signerBackend() string {
	switch r.signer.(type) {
	case *VaultTransitSigner:
		return "vault"
	default:
		return "env"
	}
}

func (r *Recorder) tenantLock(apiKeyID string) *sync.Mutex {
	v, _ := r.chainLocks.LoadOrStore(apiKeyID, &sync.Mutex{})
	return v.(*sync.Mutex)
}

// NewRecorder returns a Recorder using an in-process EnvSigner. Kept for
// backwards compatibility with callers that pass `privateKeyB64` directly.
// New code should construct a Signer explicitly and call NewRecorderWithSigner.
func NewRecorder(pool *pgxpool.Pool, privateKeyB64 string, logger *slog.Logger) (*Recorder, error) {
	if logger == nil {
		logger = slog.Default()
	}
	signer, transient, err := NewEnvSigner(privateKeyB64)
	if err != nil {
		return nil, err
	}
	if transient {
		logger.Warn("audit signing key not configured — generated transient ed25519 key (DEV ONLY)",
			"public_key_b64", base64.StdEncoding.EncodeToString(signer.PublicKey()))
	}
	return NewRecorderWithSigner(pool, signer, logger), nil
}

// NewRecorderWithSigner returns a Recorder backed by the supplied Signer. Use
// this with VaultTransitSigner (or other KMS-backed implementations) in
// production.
func NewRecorderWithSigner(pool *pgxpool.Pool, signer Signer, logger *slog.Logger) *Recorder {
	if logger == nil {
		logger = slog.Default()
	}
	return &Recorder{pool: pool, signer: signer, logger: logger}
}

// PublicKeyBase64 returns the audit signer pubkey for inclusion in
// `GET /v1/audit/log/verify` responses and external verification.
func (r *Recorder) PublicKeyBase64() string {
	return base64.StdEncoding.EncodeToString(r.signer.PublicKey())
}

// SignerForWorker exposes the underlying Signer so the asynchronous
// SignerWorker can share the same key material. Returns the Recorder's
// configured signer (env or Vault); the caller MUST NOT swap it out
// mid-flight or the chain's external proof becomes unverifiable.
func (r *Recorder) SignerForWorker() Signer {
	return r.signer
}

// Append writes one signed entry. Errors are returned to the caller; audit
// failure should not silently succeed.
func (r *Recorder) Append(ctx context.Context, ev Event) (*Entry, error) {
	appendStart := time.Now()
	if r.obs != nil {
		defer func() { r.obs.ObserveAuditAppend(time.Since(appendStart).Seconds()) }()
	}
	if ev.EventType == "" || ev.ResourceType == "" {
		return nil, errors.New("audit: event_type and resource_type are required")
	}
	// Allowlist before persistence — anything outside the per-event-type
	// allowlist is dropped so the immutable audit chain never absorbs PII
	// or secrets the caller passed in by accident. See sanitize.go.
	payload := sanitizePayload(ev.EventType, ev.Payload)
	payloadJSON, err := canonicalJSON(payload)
	if err != nil {
		return nil, fmt.Errorf("audit canonical payload: %w", err)
	}

	// Per-tenant chain. Two layers of serialisation:
	//   1. in-process mutex keyed by api_key_id (avoids piling pool
	//      connections on the advisory lock under same-tenant concurrency)
	//   2. pg_advisory_xact_lock(hashtext(api_key_id)) inside the tx below
	//      (authoritative; also serialises across gateway instances)
	lock := r.tenantLock(ev.APIKeyID.String())
	lock.Lock()
	defer lock.Unlock()

	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("audit begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	// pg_advisory_xact_lock keyed by hash of api_key_id — releases on commit.
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext($1))`, ev.APIKeyID.String()); err != nil {
		return nil, fmt.Errorf("audit lock: %w", err)
	}

	prevHash := make([]byte, 32)
	row := tx.QueryRow(ctx, `
		SELECT entry_hash FROM audit_log
		WHERE api_key_id = $1
		ORDER BY seq DESC LIMIT 1
	`, ev.APIKeyID)
	var prev []byte
	if err := row.Scan(&prev); err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return nil, fmt.Errorf("audit prev lookup: %w", err)
	}
	if len(prev) == 32 {
		prevHash = prev
	}

	// Truncate to microseconds — Postgres timestamptz only stores microseconds,
	// so we must hash the truncated value to keep the chain reproducible after
	// a round-trip through the DB.
	now := time.Now().UTC().Truncate(time.Microsecond)
	record := struct {
		APIKeyID     string          `json:"api_key_id"`
		TS           string          `json:"ts"`
		EventType    string          `json:"event_type"`
		ResourceType string          `json:"resource_type"`
		ResourceID   string          `json:"resource_id"`
		Actor        string          `json:"actor"`
		Payload      json.RawMessage `json:"payload"`
		CUConsumed   *int            `json:"cu_consumed,omitempty"`
	}{
		APIKeyID:     ev.APIKeyID.String(),
		TS:           now.Format(time.RFC3339Nano),
		EventType:    ev.EventType,
		ResourceType: ev.ResourceType,
		ResourceID:   ev.ResourceID,
		Actor:        ev.Actor,
		Payload:      payloadJSON,
		CUConsumed:   ev.CUConsumed,
	}
	recordJSON, err := json.Marshal(record)
	if err != nil {
		return nil, fmt.Errorf("audit marshal: %w", err)
	}
	h := sha256.New()
	h.Write(prevHash)
	h.Write(recordJSON)
	entryHash := h.Sum(nil)

	// P1.4: the row is persisted with signature NULL — the SignerWorker
	// drains the queue out-of-band and updates signature later. Chain
	// integrity is preserved because the chain is defined by prev_hash +
	// entry_hash; the signature is an external proof attached after the
	// fact. Hot path no longer blocks on Vault.
	var seq int64
	err = tx.QueryRow(ctx, `
		INSERT INTO audit_log
		    (api_key_id, ts, event_type, resource_type, resource_id, actor,
		     payload, cu_consumed, prev_hash, entry_hash, signature, pending_signed_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, NULL, NOW())
		RETURNING seq
	`, ev.APIKeyID, now, ev.EventType, ev.ResourceType, ev.ResourceID, ev.Actor,
		string(payloadJSON), ev.CUConsumed, prevHash, entryHash).Scan(&seq)
	if err != nil {
		return nil, fmt.Errorf("audit insert: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		if r.obs != nil {
			r.obs.IncAuditFailure("append")
		}
		return nil, fmt.Errorf("audit commit: %w", err)
	}

	return &Entry{
		Seq:          seq,
		APIKeyID:     ev.APIKeyID,
		TS:           now,
		EventType:    ev.EventType,
		ResourceType: ev.ResourceType,
		ResourceID:   ev.ResourceID,
		Actor:        ev.Actor,
		Payload:      payloadJSON,
		CUConsumed:   ev.CUConsumed,
		PrevHash:     prevHash,
		EntryHash:    entryHash,
		// Signature is filled by SignerWorker out-of-band. Callers that
		// need the signature now (e.g. /audit/verify built-in test) must
		// poll the row.
		Signature: nil,
	}, nil
}

// canonicalJSON marshals a payload with deterministic key ordering. Go's
// `encoding/json` already sorts map keys; we re-marshal through json.Marshal
// to guarantee stable bytes. The round-trip decoder uses UseNumber() so a
// large integer in the payload survives as json.Number instead of being
// coerced to float64 (which would lose precision above 2^53 and change the
// canonical bytes — and therefore the audit hash).
func canonicalJSON(v any) (json.RawMessage, error) {
	buf, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	dec := json.NewDecoder(bytes.NewReader(buf))
	dec.UseNumber()
	var probe any
	if err := dec.Decode(&probe); err != nil {
		return nil, err
	}
	out, err := json.Marshal(probe)
	if err != nil {
		return nil, err
	}
	return json.RawMessage(out), nil
}
