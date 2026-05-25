package intents

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/go-playground/validator/v10"
)

var validate = validator.New()

// RouteOptions wires the HTTP handlers. The resolver funcs + Charge + RefundOnError
// come from the api package (which owns auth + billing plumbing). Charge applies
// the per-route token quota (intents are priced per endpoint, not flat);
// RefundOnError refunds that charge when the handler returns a 5xx technical
// failure (these are Local routes, so they don't get the proxy's auto-refund).
type RouteOptions struct {
	Orchestrator    *Orchestrator
	ResolveUserID   func(*http.Request) string
	ResolveAPIKeyID func(*http.Request) string
	Charge          func(routeKey string) func(http.Handler) http.Handler
	RefundOnError   func(http.Handler) http.Handler
}

// MountWriteRoutes registers the write-class intent routes (prepare, submit).
// The enclosing server group applies write scope + tx rate-limit + idempotency;
// per-route quota is applied here so each endpoint is billed at its catalogue cost.
func MountWriteRoutes(r chi.Router, opts RouteOptions) {
	h := &handlers{opts: opts}
	charge := chargeOrNoop(opts.Charge)
	refund := refundOrNoop(opts.RefundOnError)
	r.With(charge("intent.swap.prepare"), refund).Post("/v1/intents/swap/prepare", h.prepare)
	r.With(charge("intent.swap.submit"), refund).Post("/v1/intents/swap/submit", h.submit)
}

// MountReadRoutes registers the read-class intent routes (simulate, status).
// The enclosing server group applies read scope + read rate-limit (no
// idempotency — these are read-only previews/queries).
func MountReadRoutes(r chi.Router, opts RouteOptions) {
	h := &handlers{opts: opts}
	charge := chargeOrNoop(opts.Charge)
	refund := refundOrNoop(opts.RefundOnError)
	r.With(charge("intent.simulate"), refund).Post("/v1/intents/simulate", h.simulate)
	r.With(charge("intent.status"), refund).Get("/v1/intents/status/{intentId}", h.status)
}

func chargeOrNoop(charge func(string) func(http.Handler) http.Handler) func(string) func(http.Handler) http.Handler {
	if charge != nil {
		return charge
	}
	return func(string) func(http.Handler) http.Handler {
		return func(next http.Handler) http.Handler { return next }
	}
}

func refundOrNoop(refund func(http.Handler) http.Handler) func(http.Handler) http.Handler {
	if refund != nil {
		return refund
	}
	return func(next http.Handler) http.Handler { return next }
}

type handlers struct{ opts RouteOptions }

func (h *handlers) prepare(w http.ResponseWriter, r *http.Request) {
	userID := h.opts.ResolveUserID(r)
	if userID == "" {
		writeError(w, http.StatusUnauthorized, "unauthorized", "missing tenant identity")
		return
	}
	var req prepareRequest
	if !bind(w, r, &req) {
		return
	}
	resp, err := h.opts.Orchestrator.Prepare(r.Context(), userID, h.opts.ResolveAPIKeyID(r), req)
	if err != nil {
		writeUserError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

func (h *handlers) simulate(w http.ResponseWriter, r *http.Request) {
	userID := h.opts.ResolveUserID(r)
	if userID == "" {
		writeError(w, http.StatusUnauthorized, "unauthorized", "missing tenant identity")
		return
	}
	var req prepareRequest
	if !bind(w, r, &req) {
		return
	}
	resp, err := h.opts.Orchestrator.Simulate(r.Context(), userID, req)
	if err != nil {
		writeUserError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

func (h *handlers) submit(w http.ResponseWriter, r *http.Request) {
	userID := h.opts.ResolveUserID(r)
	if userID == "" {
		writeError(w, http.StatusUnauthorized, "unauthorized", "missing tenant identity")
		return
	}
	var req submitRequest
	if !bind(w, r, &req) {
		return
	}
	resp, err := h.opts.Orchestrator.Submit(r.Context(), userID, req)
	if err != nil {
		writeUserError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

func (h *handlers) status(w http.ResponseWriter, r *http.Request) {
	userID := h.opts.ResolveUserID(r)
	if userID == "" {
		writeError(w, http.StatusUnauthorized, "unauthorized", "missing tenant identity")
		return
	}
	id := chi.URLParam(r, "intentId")
	resp, err := h.opts.Orchestrator.Status(r.Context(), userID, id)
	if err != nil {
		writeUserError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

func bind(w http.ResponseWriter, r *http.Request, dst any) bool {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 32<<10))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_body", "invalid request body")
		return false
	}
	if err := validate.Struct(dst); err != nil {
		writeError(w, http.StatusBadRequest, "validation_failed", "invalid request parameters")
		return false
	}
	return true
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, code, msg string) {
	writeJSON(w, status, map[string]string{"error": msg, "code": code})
}

func writeUserError(w http.ResponseWriter, err error) {
	var ue *userError
	if errors.As(err, &ue) {
		writeError(w, ue.status, ue.code, ue.msg)
		return
	}
	writeError(w, http.StatusInternalServerError, "internal_error", "internal error")
}
