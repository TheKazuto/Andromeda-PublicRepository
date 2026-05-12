package webhooks

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/shinkalabs/andromeda-gateway/internal/httpx"
	"github.com/shinkalabs/andromeda-gateway/internal/netsafety"
)

type APIKeyResolver func(r *http.Request) (uuid.UUID, error)

// AuditAppender is the subset of the audit.Recorder that webhooks needs.
// Decoupled to avoid an import cycle.
type AuditAppender interface {
	Append(ctx context.Context, ev AuditEvent) error
}

type AuditEvent struct {
	APIKeyID     uuid.UUID
	EventType    string
	ResourceType string
	ResourceID   string
	Actor        string
	Payload      map[string]any
}

type RouteOptions struct {
	Store     *Store
	ResolveID APIKeyResolver
	Audit     AuditAppender        // optional; nil → no-op
	URLGuard  *netsafety.Validator // optional; nil → use a default production validator
}

// urlGuard returns the validator to use, defaulting to a production
// validator. Tests inject a development-mode one via RouteOptions.
func (o RouteOptions) urlGuard() *netsafety.Validator {
	if o.URLGuard != nil {
		return o.URLGuard
	}
	return netsafety.New(netsafety.ModeProduction)
}

func recordAudit(ctx context.Context, opts RouteOptions, ev AuditEvent) {
	if opts.Audit == nil {
		return
	}
	_ = opts.Audit.Append(ctx, ev)
}

func MountRoutes(r chi.Router, opts RouteOptions) {
	r.Route("/v1/webhooks", func(sub chi.Router) {
		sub.Post("/endpoints", handleCreateEndpoint(opts))
		sub.Get("/endpoints", handleListEndpoints(opts))
		sub.Patch("/endpoints/{id}", handleUpdateEndpoint(opts))
		sub.Delete("/endpoints/{id}", handleDeleteEndpoint(opts))
		sub.Post("/endpoints/{id}/test", handleTestEndpoint(opts))
		sub.Get("/deliveries", handleListDeliveries(opts))
		sub.Post("/deliveries/{id}/retry", handleRetryDelivery(opts))
	})
}

type createEndpointReq struct {
	URL    string   `json:"url"`
	Events []string `json:"events"`
}

type endpointWithSecretResp struct {
	Endpoint
	Secret string `json:"secret"`
}

func handleCreateEndpoint(opts RouteOptions) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		apiKeyID, err := opts.ResolveID(r)
		if err != nil {
			writeError(w, http.StatusUnauthorized, "unauthorised", err.Error())
			return
		}
		var req createEndpointReq
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, "invalid_body", "invalid JSON body")
			return
		}
		req.URL = strings.TrimSpace(req.URL)
		if req.URL == "" {
			writeError(w, http.StatusBadRequest, "missing_url", "url is required")
			return
		}
		if err := opts.urlGuard().ValidateRegister(r.Context(), req.URL); err != nil {
			writeError(w, http.StatusBadRequest, "invalid_url", "url is not allowed by security policy")
			return
		}
		secret := genSecret(32)
		ep, err := opts.Store.CreateEndpoint(r.Context(), apiKeyID, req.URL, secret, req.Events)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "internal_error", "could not create endpoint")
			return
		}
		recordAudit(r.Context(), opts, AuditEvent{
			APIKeyID: apiKeyID, EventType: "webhook.endpoint.created",
			ResourceType: "webhook", ResourceID: ep.ID.String(),
			Actor:   "api_key:" + apiKeyID.String(),
			Payload: map[string]any{"url": ep.URL, "events": ep.Events},
		})
		writeJSON(w, http.StatusCreated, endpointWithSecretResp{Endpoint: *ep, Secret: secret})
	}
}

func handleListEndpoints(opts RouteOptions) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		apiKeyID, err := opts.ResolveID(r)
		if err != nil {
			writeError(w, http.StatusUnauthorized, "unauthorised", err.Error())
			return
		}
		eps, err := opts.Store.ListEndpoints(r.Context(), apiKeyID)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "internal_error", "could not list endpoints")
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"items": eps})
	}
}

type updateEndpointReq struct {
	URL    *string   `json:"url,omitempty"`
	Events *[]string `json:"events,omitempty"`
	Active *bool     `json:"active,omitempty"`
}

func handleUpdateEndpoint(opts RouteOptions) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		apiKeyID, err := opts.ResolveID(r)
		if err != nil {
			writeError(w, http.StatusUnauthorized, "unauthorised", err.Error())
			return
		}
		id, err := uuid.Parse(chi.URLParam(r, "id"))
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid_id", "endpoint id is not a UUID")
			return
		}
		var req updateEndpointReq
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, "invalid_body", "invalid JSON body")
			return
		}
		if req.URL != nil {
			trimmed := strings.TrimSpace(*req.URL)
			req.URL = &trimmed
			if err := opts.urlGuard().ValidateRegister(r.Context(), trimmed); err != nil {
				writeError(w, http.StatusBadRequest, "invalid_url", "url is not allowed by security policy")
				return
			}
		}
		ep, err := opts.Store.UpdateEndpoint(r.Context(), apiKeyID, id, EndpointPatch{
			URL: req.URL, Events: req.Events, Active: req.Active,
		})
		if errors.Is(err, ErrEndpointNotFound) {
			writeError(w, http.StatusNotFound, "not_found", "endpoint not found")
			return
		}
		if err != nil {
			writeError(w, http.StatusInternalServerError, "internal_error", "could not update endpoint")
			return
		}
		recordAudit(r.Context(), opts, AuditEvent{
			APIKeyID: apiKeyID, EventType: "webhook.endpoint.updated",
			ResourceType: "webhook", ResourceID: ep.ID.String(),
			Actor:   "api_key:" + apiKeyID.String(),
			Payload: map[string]any{"url": ep.URL, "active": ep.Active, "events": ep.Events},
		})
		writeJSON(w, http.StatusOK, ep)
	}
}

func handleDeleteEndpoint(opts RouteOptions) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		apiKeyID, err := opts.ResolveID(r)
		if err != nil {
			writeError(w, http.StatusUnauthorized, "unauthorised", err.Error())
			return
		}
		id, err := uuid.Parse(chi.URLParam(r, "id"))
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid_id", "endpoint id is not a UUID")
			return
		}
		if err := opts.Store.DeleteEndpoint(r.Context(), apiKeyID, id); err != nil {
			if errors.Is(err, ErrEndpointNotFound) {
				writeError(w, http.StatusNotFound, "not_found", "endpoint not found")
				return
			}
			writeError(w, http.StatusInternalServerError, "internal_error", "could not delete endpoint")
			return
		}
		recordAudit(r.Context(), opts, AuditEvent{
			APIKeyID: apiKeyID, EventType: "webhook.endpoint.deleted",
			ResourceType: "webhook", ResourceID: id.String(),
			Actor:   "api_key:" + apiKeyID.String(),
			Payload: map[string]any{},
		})
		w.WriteHeader(http.StatusNoContent)
	}
}

func handleTestEndpoint(opts RouteOptions) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		apiKeyID, err := opts.ResolveID(r)
		if err != nil {
			writeError(w, http.StatusUnauthorized, "unauthorised", err.Error())
			return
		}
		id, err := uuid.Parse(chi.URLParam(r, "id"))
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid_id", "endpoint id is not a UUID")
			return
		}
		eps, err := opts.Store.ListEndpoints(r.Context(), apiKeyID)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "internal_error", "could not load endpoint")
			return
		}
		var ep *Endpoint
		for _, e := range eps {
			if e.ID == id {
				ep = e
				break
			}
		}
		if ep == nil {
			writeError(w, http.StatusNotFound, "not_found", "endpoint not found")
			return
		}
		payload := json.RawMessage(`{"event_id":"test","kind":"webhook.test","data":{"hello":"world"}}`)
		if err := opts.Store.EnqueueDelivery(r.Context(), id, "webhook.test", uuid.New(), payload); err != nil {
			writeError(w, http.StatusInternalServerError, "internal_error", "could not enqueue test delivery")
			return
		}
		writeJSON(w, http.StatusAccepted, map[string]any{"queued": true})
	}
}

func handleListDeliveries(opts RouteOptions) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		apiKeyID, err := opts.ResolveID(r)
		if err != nil {
			writeError(w, http.StatusUnauthorized, "unauthorised", err.Error())
			return
		}
		var endpointFilter *uuid.UUID
		if v := r.URL.Query().Get("endpoint_id"); v != "" {
			parsed, err := uuid.Parse(v)
			if err != nil {
				writeError(w, http.StatusBadRequest, "invalid_endpoint_id", "endpoint_id is not a UUID")
				return
			}
			endpointFilter = &parsed
		}
		status := r.URL.Query().Get("status")
		out, err := opts.Store.ListDeliveries(r.Context(), apiKeyID, endpointFilter, status, 50)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "internal_error", "could not list deliveries")
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"items": out})
	}
}

func handleRetryDelivery(opts RouteOptions) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		apiKeyID, err := opts.ResolveID(r)
		if err != nil {
			writeError(w, http.StatusUnauthorized, "unauthorised", err.Error())
			return
		}
		id, err := uuid.Parse(chi.URLParam(r, "id"))
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid_id", "delivery id is not a UUID")
			return
		}
		if err := opts.Store.RetryDeadLetter(r.Context(), apiKeyID, id); err != nil {
			if errors.Is(err, ErrEndpointNotFound) {
				writeError(w, http.StatusNotFound, "not_found", "delivery not in dead_letter or not yours")
				return
			}
			writeError(w, http.StatusInternalServerError, "internal_error", "retry failed")
			return
		}
		writeJSON(w, http.StatusAccepted, map[string]any{"requeued": true})
	}
}

func genSecret(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return "whsec_" + hex.EncodeToString(b)
}

func writeJSON(w http.ResponseWriter, code int, body any) {
	httpx.WriteJSON(w, code, body)
}

func writeError(w http.ResponseWriter, code int, errCode, msg string) {
	httpx.WriteError(w, code, errCode, msg)
}
