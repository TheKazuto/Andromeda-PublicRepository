package audit

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Reader exposes paginated read access to the audit log.
type Reader struct {
	pool *pgxpool.Pool
	pub  string // base64
}

func NewReader(pool *pgxpool.Pool, publicKeyBase64 string) *Reader {
	return &Reader{pool: pool, pub: publicKeyBase64}
}

type APIKeyResolver func(r *http.Request) (uuid.UUID, error)

// MountRoutes registers `/v1/audit/log/...` on the provided router. The
// caller passes in a resolver that maps the request to the authenticated
// api_key_id (so audit reads are tenant-scoped).
func (rd *Reader) MountRoutes(r chi.Router, resolveAPIKey APIKeyResolver) {
	r.Get("/v1/audit/log", rd.list(resolveAPIKey))
	r.Get("/v1/audit/log/export", rd.export(resolveAPIKey))
	r.Get("/v1/audit/log/verify", rd.verify(resolveAPIKey))
	r.Get("/v1/audit/log/{seq}/proof", rd.proof(resolveAPIKey))
}

type entryView struct {
	Seq          int64           `json:"seq"`
	TS           time.Time       `json:"ts"`
	EventType    string          `json:"event_type"`
	ResourceType string          `json:"resource_type"`
	ResourceID   string          `json:"resource_id"`
	Actor        string          `json:"actor"`
	Payload      json.RawMessage `json:"payload"`
	CUConsumed   *int            `json:"cu_consumed,omitempty"`
	PrevHashHex  string          `json:"prev_hash_hex"`
	EntryHashHex string          `json:"entry_hash_hex"`
	SignatureHex string          `json:"signature_hex"`
}

func (rd *Reader) list(resolve APIKeyResolver) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		apiKeyID, err := resolve(r)
		if err != nil {
			writeErr(w, http.StatusUnauthorized, "unauthorised", err.Error())
			return
		}
		limit := parseInt(r.URL.Query().Get("limit"), 50)
		if limit > 500 {
			limit = 500
		}
		afterSeq := parseInt(r.URL.Query().Get("after_seq"), 0)
		eventType := r.URL.Query().Get("event_type")

		var rows pgx.Rows
		if eventType == "" {
			rows, err = rd.pool.Query(r.Context(), `
				SELECT seq, ts, event_type, resource_type, resource_id, actor,
				       payload, cu_consumed, prev_hash, entry_hash, signature
				FROM audit_log
				WHERE api_key_id = $1 AND seq > $2
				ORDER BY seq ASC
				LIMIT $3
			`, apiKeyID, afterSeq, limit)
		} else {
			rows, err = rd.pool.Query(r.Context(), `
				SELECT seq, ts, event_type, resource_type, resource_id, actor,
				       payload, cu_consumed, prev_hash, entry_hash, signature
				FROM audit_log
				WHERE api_key_id = $1 AND seq > $2 AND event_type = $4
				ORDER BY seq ASC
				LIMIT $3
			`, apiKeyID, afterSeq, limit, eventType)
		}
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "internal_error", "audit list failed")
			return
		}
		defer rows.Close()

		out := []entryView{}
		for rows.Next() {
			var e entryView
			var prev, hash, sig []byte
			var payloadStr string
			if err := rows.Scan(&e.Seq, &e.TS, &e.EventType, &e.ResourceType, &e.ResourceID,
				&e.Actor, &payloadStr, &e.CUConsumed, &prev, &hash, &sig); err != nil {
				writeErr(w, http.StatusInternalServerError, "internal_error", "audit scan failed")
				return
			}
			e.Payload = json.RawMessage(payloadStr)
			e.PrevHashHex = hexEncode(prev)
			e.EntryHashHex = hexEncode(hash)
			e.SignatureHex = hexEncode(sig)
			out = append(out, e)
		}
		writeJSON(w, http.StatusOK, map[string]any{"items": out, "audit_pubkey_b64": rd.pub})
	}
}

func (rd *Reader) export(resolve APIKeyResolver) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		apiKeyID, err := resolve(r)
		if err != nil {
			writeErr(w, http.StatusUnauthorized, "unauthorised", err.Error())
			return
		}
		w.Header().Set("Content-Type", "application/x-ndjson")
		w.Header().Set("X-Audit-Pubkey-B64", rd.pub)
		w.WriteHeader(http.StatusOK)

		ctx := r.Context()
		rows, err := rd.pool.Query(ctx, `
			SELECT seq, ts, event_type, resource_type, resource_id, actor,
			       payload, cu_consumed, prev_hash, entry_hash, signature
			FROM audit_log WHERE api_key_id = $1 ORDER BY seq ASC
		`, apiKeyID)
		if err != nil {
			return
		}
		defer rows.Close()
		enc := json.NewEncoder(w)
		for rows.Next() {
			var e entryView
			var prev, hash, sig []byte
			var payloadStr string
			if err := rows.Scan(&e.Seq, &e.TS, &e.EventType, &e.ResourceType, &e.ResourceID,
				&e.Actor, &payloadStr, &e.CUConsumed, &prev, &hash, &sig); err != nil {
				return
			}
			e.Payload = json.RawMessage(payloadStr)
			e.PrevHashHex = hexEncode(prev)
			e.EntryHashHex = hexEncode(hash)
			e.SignatureHex = hexEncode(sig)
			_ = enc.Encode(e)
			if f, ok := w.(http.Flusher); ok {
				f.Flush()
			}
		}
	}
}

func (rd *Reader) verify(resolve APIKeyResolver) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		apiKeyID, err := resolve(r)
		if err != nil {
			writeErr(w, http.StatusUnauthorized, "unauthorised", err.Error())
			return
		}
		head, err := rd.fetchHead(r.Context(), apiKeyID)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "internal_error", "audit head lookup failed")
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"audit_pubkey_b64":      rd.pub,
			"chain_head_seq":        head.seq,
			"chain_head_hash_hex":   hexEncode(head.entryHash),
			"chain_total_entries":   head.total,
			"signature_algorithm":   "ed25519",
			"hash_algorithm":        "sha256",
			"hash_record_format":    "json (rfc 8259) with sorted keys; entry_hash = SHA256(prev_hash || record_json)",
		})
	}
}

func (rd *Reader) proof(resolve APIKeyResolver) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		apiKeyID, err := resolve(r)
		if err != nil {
			writeErr(w, http.StatusUnauthorized, "unauthorised", err.Error())
			return
		}
		seqParam := chi.URLParam(r, "seq")
		seq, err := strconv.ParseInt(seqParam, 10, 64)
		if err != nil || seq < 1 {
			writeErr(w, http.StatusBadRequest, "invalid_seq", "seq must be a positive integer")
			return
		}
		var prev, hash, sig []byte
		var ts time.Time
		var eventType, resourceType, resourceID, actor string
		var payloadStr string
		var cu *int
		err = rd.pool.QueryRow(r.Context(), `
			SELECT ts, event_type, resource_type, resource_id, actor,
			       payload, cu_consumed, prev_hash, entry_hash, signature
			FROM audit_log WHERE seq = $1 AND api_key_id = $2
		`, seq, apiKeyID).Scan(&ts, &eventType, &resourceType, &resourceID, &actor,
			&payloadStr, &cu, &prev, &hash, &sig)
		payload := json.RawMessage(payloadStr)
		if errors.Is(err, pgx.ErrNoRows) {
			writeErr(w, http.StatusNotFound, "not_found", "entry not found")
			return
		}
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "internal_error", "audit proof lookup failed")
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"seq":              seq,
			"ts":               ts,
			"event_type":       eventType,
			"resource_type":    resourceType,
			"resource_id":      resourceID,
			"actor":            actor,
			"payload":          payload,
			"cu_consumed":      cu,
			"prev_hash_hex":    hexEncode(prev),
			"entry_hash_hex":   hexEncode(hash),
			"signature_hex":    hexEncode(sig),
			"audit_pubkey_b64": rd.pub,
		})
	}
}

type chainHead struct {
	seq       int64
	entryHash []byte
	total     int64
}

func (rd *Reader) fetchHead(ctx context.Context, apiKeyID uuid.UUID) (chainHead, error) {
	var head chainHead
	err := rd.pool.QueryRow(ctx, `
		SELECT COALESCE(MAX(seq), 0)::bigint, COUNT(*)::bigint
		FROM audit_log WHERE api_key_id = $1
	`, apiKeyID).Scan(&head.seq, &head.total)
	if err != nil {
		return head, err
	}
	if head.seq == 0 {
		return head, nil
	}
	err = rd.pool.QueryRow(ctx, `
		SELECT entry_hash FROM audit_log WHERE seq = $1
	`, head.seq).Scan(&head.entryHash)
	return head, err
}

func parseInt(s string, fallback int) int {
	if s == "" {
		return fallback
	}
	n, err := strconv.Atoi(s)
	if err != nil || n < 0 {
		return fallback
	}
	return n
}

func writeJSON(w http.ResponseWriter, code int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(body)
}

func writeErr(w http.ResponseWriter, code int, errCode, msg string) {
	writeJSON(w, code, map[string]any{"error": map[string]string{"code": errCode, "message": msg}})
}

func hexEncode(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	// keep minimal deps — use base64.std for binary fields elsewhere, but
	// audit proofs traditionally use hex
	return fmt.Sprintf("%x", b)
}

// AuditPublicKeyB64 returns the recorder's public key base64-encoded.
func AuditPublicKeyB64(rec *Recorder) string {
	if rec == nil {
		return ""
	}
	return rec.PublicKeyBase64()
}

// hint to suppress unused import lint when we route through base64
var _ = base64.StdEncoding
