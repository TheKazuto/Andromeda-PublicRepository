package oraclemonitor

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/shinkalabs/andromeda-gateway/internal/httpx"
)

// APIKeyResolver pulls the authenticated api_key_id from the request context.
type APIKeyResolver func(r *http.Request) (uuid.UUID, error)

// AuditAppender mirrors the audit.Recorder surface needed here (decoupled to
// avoid an import cycle).
type AuditAppender interface {
	Append(ctx context.Context, ev AuditEvent) error
}

// AuditEvent is the audit envelope this package emits.
type AuditEvent struct {
	APIKeyID     uuid.UUID
	EventType    string
	ResourceType string
	ResourceID   string
	Actor        string
	Payload      map[string]any
}

// RouteOptions wires the tenant-facing routes onto a chi sub-router.
type RouteOptions struct {
	Store     *Store
	ResolveID APIKeyResolver
	Cluster   string        // the gateway's active cluster (e.g. "devnet")
	Audit     AuditAppender // optional
	// Firer (optional) validates the embedded request_signature payload at arm
	// time with the authoritative schema, so a malformed payload is rejected on
	// create instead of only failing at fire time. When nil, arm-time payload
	// validation is skipped (fire-time validation still applies).
	Firer Firer
}

// MountRoutes registers the price-trigger endpoints. Must be called inside a
// chi.Group that already applied requireAPIKey + scope + subscription +
// idempotency + quota (mirrors the future-sign group).
//
//	POST   /v1/oracle/triggers       arm a price trigger
//	GET    /v1/oracle/triggers       list the caller's triggers
//	GET    /v1/oracle/triggers/{id}  get one
//	DELETE /v1/oracle/triggers/{id}  cancel an armed trigger
func MountRoutes(r chi.Router, opts RouteOptions) {
	if opts.Cluster == "" {
		opts.Cluster = "devnet"
	}
	r.Route("/v1/oracle/triggers", func(sub chi.Router) {
		sub.Post("/", handleCreate(opts))
		sub.Get("/", handleList(opts))
		sub.Get("/{id}", handleGet(opts))
		sub.Delete("/{id}", handleCancel(opts))
	})
}

func handleCreate(opts RouteOptions) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		apiKeyID, err := opts.ResolveID(r)
		if err != nil {
			httpx.WriteError(w, http.StatusUnauthorized, "unauthorised", err.Error())
			return
		}
		var req CreateRequest
		if !httpx.BindAndValidate(w, r, &req, 16<<10) {
			return
		}
		req.DWalletAddress = strings.TrimSpace(req.DWalletAddress)
		req.PythFeedIDHex = strings.ToLower(strings.TrimPrefix(strings.TrimSpace(req.PythFeedIDHex), "0x"))
		if req.Min1e8 < 0 {
			httpx.WriteError(w, http.StatusBadRequest, "invalid_band", "min1e8 must be >= 0 (canonical prices are non-negative)")
			return
		}
		if req.Min1e8 > req.Max1e8 {
			httpx.WriteError(w, http.StatusBadRequest, "invalid_band", "min1e8 must be <= max1e8")
			return
		}
		if req.ExpiresInSeconds <= 0 {
			req.ExpiresInSeconds = 86400
		}
		// Defence-in-depth: the embedded request_signature payload must target
		// the same dwallet the trigger declares, so a dev cannot arm a trigger
		// that audits as wallet A but signs against wallet B at fire time. Full
		// field validation runs in policy.FireRequestSignature at fire time.
		if probeErr := probeDWalletMatch(req.RequestSignaturePayload, req.DWalletAddress); probeErr != "" {
			httpx.WriteError(w, http.StatusBadRequest, "dwallet_mismatch", probeErr)
			return
		}
		// Validate the embedded request_signature payload now (authoritative
		// schema) so a malformed trigger is rejected at arm time, not silently
		// stored to fail later at fire time and waste gas on retries.
		if opts.Firer != nil {
			if err := opts.Firer.ValidateRequestSignaturePayload(req.RequestSignaturePayload); err != nil {
				httpx.WriteError(w, http.StatusBadRequest, "invalid_request_signature_payload", err.Error())
				return
			}
		}

		t, err := opts.Store.Create(r.Context(), apiKeyID, opts.Cluster, req)
		if err != nil {
			httpx.WriteError(w, http.StatusBadRequest, "create_failed", err.Error())
			return
		}
		recordAudit(r.Context(), opts, AuditEvent{
			APIKeyID:     apiKeyID,
			EventType:    "oracle_trigger.armed",
			ResourceType: "oracle_price_trigger",
			ResourceID:   t.ID.String(),
			Actor:        "api_key:" + apiKeyID.String(),
			Payload: map[string]any{
				"dwallet_address": t.DWalletAddress,
				"feed_id_hex":     t.PythFeedIDHex,
				"min_1e8":         t.Min1e8,
				"max_1e8":         t.Max1e8,
				"expires_at":      t.ExpiresAt.Format("2006-01-02T15:04:05Z"),
			},
		})
		httpx.WriteJSON(w, http.StatusCreated, t)
	}
}

func handleList(opts RouteOptions) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		apiKeyID, err := opts.ResolveID(r)
		if err != nil {
			httpx.WriteError(w, http.StatusUnauthorized, "unauthorised", err.Error())
			return
		}
		limit := 50
		if v := r.URL.Query().Get("limit"); v != "" {
			if n, err := strconv.Atoi(v); err == nil && n > 0 && n <= 200 {
				limit = n
			}
		}
		items, err := opts.Store.List(r.Context(), apiKeyID, limit)
		if err != nil {
			httpx.WriteError(w, http.StatusInternalServerError, "internal_error", "could not list triggers")
			return
		}
		httpx.WriteJSON(w, http.StatusOK, map[string]any{"items": items})
	}
}

func handleGet(opts RouteOptions) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		apiKeyID, err := opts.ResolveID(r)
		if err != nil {
			httpx.WriteError(w, http.StatusUnauthorized, "unauthorised", err.Error())
			return
		}
		id, err := uuid.Parse(chi.URLParam(r, "id"))
		if err != nil {
			httpx.WriteError(w, http.StatusBadRequest, "invalid_id", "id is not a UUID")
			return
		}
		t, err := opts.Store.Get(r.Context(), apiKeyID, id)
		if errors.Is(err, ErrNotFound) {
			httpx.WriteError(w, http.StatusNotFound, "not_found", "trigger not found")
			return
		}
		if err != nil {
			httpx.WriteError(w, http.StatusInternalServerError, "internal_error", "lookup failed")
			return
		}
		httpx.WriteJSON(w, http.StatusOK, t)
	}
}

func handleCancel(opts RouteOptions) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		apiKeyID, err := opts.ResolveID(r)
		if err != nil {
			httpx.WriteError(w, http.StatusUnauthorized, "unauthorised", err.Error())
			return
		}
		id, err := uuid.Parse(chi.URLParam(r, "id"))
		if err != nil {
			httpx.WriteError(w, http.StatusBadRequest, "invalid_id", "id is not a UUID")
			return
		}
		if err := opts.Store.Cancel(r.Context(), apiKeyID, id); err != nil {
			if errors.Is(err, ErrNotFound) {
				httpx.WriteError(w, http.StatusNotFound, "not_found", "trigger not armed or not yours")
				return
			}
			httpx.WriteError(w, http.StatusInternalServerError, "internal_error", "cancel failed")
			return
		}
		recordAudit(r.Context(), opts, AuditEvent{
			APIKeyID:     apiKeyID,
			EventType:    "oracle_trigger.cancelled",
			ResourceType: "oracle_price_trigger",
			ResourceID:   id.String(),
			Actor:        "api_key:" + apiKeyID.String(),
			Payload:      map[string]any{},
		})
		w.WriteHeader(http.StatusNoContent)
	}
}

// probeDWalletMatch permissively checks that the embedded request_signature
// payload's dwallet_address matches the declared one. Returns "" on match (or
// when the field is absent — the fire-time validation is authoritative).
func probeDWalletMatch(payload json.RawMessage, declared string) string {
	if len(payload) == 0 {
		return ""
	}
	var probe struct {
		DWalletAddress string `json:"dwallet_address"`
	}
	if err := json.Unmarshal(payload, &probe); err != nil {
		return "" // unfamiliar shape — let the fire-time validation reject it
	}
	if probe.DWalletAddress != "" && !strings.EqualFold(probe.DWalletAddress, declared) {
		return "requestSignaturePayload.dwallet_address does not match dwalletAddress"
	}
	return ""
}

func recordAudit(ctx context.Context, opts RouteOptions, ev AuditEvent) {
	if opts.Audit == nil {
		return
	}
	_ = opts.Audit.Append(ctx, ev)
}
