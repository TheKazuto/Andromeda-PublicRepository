package futuresign

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
	"github.com/shinkalabs/andromeda-gateway/internal/netsafety"
)

// APIKeyResolver pulls the authenticated api_key_id from the request context.
type APIKeyResolver func(r *http.Request) (uuid.UUID, error)

// AuditAppender mirrors the audit.Recorder interface needed here. Decoupled
// to avoid an import cycle.
type AuditAppender interface {
	Append(ctx context.Context, ev AuditEvent) error
}

// AuditEvent is the audit envelope this package emits. Callers translate to
// the canonical audit.Event in the api package wiring.
type AuditEvent struct {
	APIKeyID     uuid.UUID
	EventType    string
	ResourceType string
	ResourceID   string
	Actor        string
	Payload      map[string]any
}

// RouteOptions wires the routes onto a chi sub-router.
type RouteOptions struct {
	Store     *Store
	ResolveID APIKeyResolver
	Audit     AuditAppender        // optional
	URLGuard  *netsafety.Validator // optional; nil → use a default production validator
}

func (o RouteOptions) urlGuard() *netsafety.Validator {
	if o.URLGuard != nil {
		return o.URLGuard
	}
	return netsafety.New(netsafety.ModeProduction)
}

// MountRoutes registers the future-sign endpoints. Must be called inside a
// chi.Group that has already applied requireAPIKey.
func MountRoutes(r chi.Router, opts RouteOptions) {
	r.Route("/v1/future-sign/triggers", func(sub chi.Router) {
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
			writeError(w, http.StatusUnauthorized, "unauthorised", err.Error())
			return
		}
		var req CreateRequest
		if !httpx.BindAndValidate(w, r, &req, 64<<10) {
			return
		}
		req.PartialSigCapID = strings.TrimSpace(req.PartialSigCapID)
		req.DWalletAddress = strings.TrimSpace(req.DWalletAddress)
		req.WebhookURL = strings.TrimSpace(req.WebhookURL)
		if !req.TriggerType.IsKnown() {
			writeError(w, http.StatusBadRequest, "invalid_trigger_type",
				"trigger_type must be one of oracle_pyth, oracle_switchboard, solana_event, slot_time, external_webhook")
			return
		}
		if err := opts.urlGuard().ValidateRegister(r.Context(), req.WebhookURL); err != nil {
			writeError(w, http.StatusBadRequest, "invalid_webhook_url", "webhookUrl is not allowed by security policy")
			return
		}
		// Per-trigger-type condition validation. Catches malformed/empty
		// conditions at create time so the watcher never tries to poll them
		// later. Also re-runs the SSRF guard on external_webhook.callbackUrl
		// (mirrors the webhookUrl check above).
		if err := validateCondition(r.Context(), req.TriggerType, req.Condition, opts.urlGuard()); err != nil {
			writeError(w, http.StatusBadRequest, "invalid_condition", err.Error())
			return
		}
		// Defense-in-depth: ensure the dWalletAddress in the embedded
		// completePayload matches the trigger's declared dwalletAddress so a
		// dev cannot arm a trigger that audits as wallet A but signs against
		// wallet B at fire time. We do a permissive parse — if the payload
		// shape is unfamiliar we let the ika-backend reject it.
		if len(req.CompletePayload) > 0 {
			var probe struct {
				DWalletAddress string `json:"dwalletAddress"`
			}
			if err := json.Unmarshal(req.CompletePayload, &probe); err == nil &&
				probe.DWalletAddress != "" &&
				!strings.EqualFold(probe.DWalletAddress, req.DWalletAddress) {
				writeError(w, http.StatusBadRequest, "dwallet_mismatch",
					"completePayload.dwalletAddress does not match dwalletAddress")
				return
			}
		}
		if req.ExpiresInSeconds <= 0 {
			req.ExpiresInSeconds = 86400
		}
		if req.ExpiresInSeconds > 30*86400 {
			writeError(w, http.StatusBadRequest, "invalid_expires", "expiresInSeconds <= 30 days")
			return
		}
		t, err := opts.Store.Create(r.Context(), apiKeyID, req)
		if err != nil {
			writeError(w, http.StatusBadRequest, "create_failed", err.Error())
			return
		}
		recordAudit(r.Context(), opts, AuditEvent{
			APIKeyID:     apiKeyID,
			EventType:    "future_sign.armed",
			ResourceType: "future_sign_trigger",
			ResourceID:   t.ID.String(),
			Actor:        "api_key:" + apiKeyID.String(),
			Payload: map[string]any{
				"trigger_type":    string(t.TriggerType),
				"dwallet_address": t.DWalletAddress,
				"expires_at":      t.ExpiresAt.Format("2006-01-02T15:04:05Z"),
			},
		})
		writeJSON(w, http.StatusCreated, t)
	}
}

func handleList(opts RouteOptions) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		apiKeyID, err := opts.ResolveID(r)
		if err != nil {
			writeError(w, http.StatusUnauthorized, "unauthorised", err.Error())
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
			writeError(w, http.StatusInternalServerError, "internal_error", "could not list triggers")
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"items": items})
	}
}

func handleGet(opts RouteOptions) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		apiKeyID, err := opts.ResolveID(r)
		if err != nil {
			writeError(w, http.StatusUnauthorized, "unauthorised", err.Error())
			return
		}
		id, err := uuid.Parse(chi.URLParam(r, "id"))
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid_id", "id is not a UUID")
			return
		}
		t, err := opts.Store.Get(r.Context(), apiKeyID, id)
		if errors.Is(err, ErrNotFound) {
			writeError(w, http.StatusNotFound, "not_found", "trigger not found")
			return
		}
		if err != nil {
			writeError(w, http.StatusInternalServerError, "internal_error", "lookup failed")
			return
		}
		writeJSON(w, http.StatusOK, t)
	}
}

func handleCancel(opts RouteOptions) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		apiKeyID, err := opts.ResolveID(r)
		if err != nil {
			writeError(w, http.StatusUnauthorized, "unauthorised", err.Error())
			return
		}
		id, err := uuid.Parse(chi.URLParam(r, "id"))
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid_id", "id is not a UUID")
			return
		}
		if err := opts.Store.Cancel(r.Context(), apiKeyID, id); err != nil {
			if errors.Is(err, ErrNotFound) {
				writeError(w, http.StatusNotFound, "not_found", "trigger not armed or not yours")
				return
			}
			writeError(w, http.StatusInternalServerError, "internal_error", "cancel failed")
			return
		}
		recordAudit(r.Context(), opts, AuditEvent{
			APIKeyID:     apiKeyID,
			EventType:    "future_sign.cancelled",
			ResourceType: "future_sign_trigger",
			ResourceID:   id.String(),
			Actor:        "api_key:" + apiKeyID.String(),
			Payload:      map[string]any{},
		})
		w.WriteHeader(http.StatusNoContent)
	}
}

func recordAudit(ctx context.Context, opts RouteOptions, ev AuditEvent) {
	if opts.Audit == nil {
		return
	}
	_ = opts.Audit.Append(ctx, ev)
}

func writeJSON(w http.ResponseWriter, code int, body any) {
	httpx.WriteJSON(w, code, body)
}

func writeError(w http.ResponseWriter, code int, errCode, msg string) {
	httpx.WriteError(w, code, errCode, msg)
}
