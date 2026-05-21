package oraclerelay

import (
	"errors"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/shinkalabs/andromeda-gateway/internal/httpx"
)

// RouteOptions wires the admin HTTP surface. These endpoints manage GLOBAL
// oracle feeds (shared by every tenant's KIND_ORACLE rules), so the parent
// router group in `internal/api/server.go` gates them with the gateway operator
// token (X-Admin-Token), not a per-tenant API-key scope. Handlers assume an
// authenticated operator caller.
type RouteOptions struct {
	Service *Service
}

// MountRoutes registers `/v1/oracle/*` under r.
//
//	GET    /v1/oracle/feeds              list feeds + last refresh + age
//	POST   /v1/oracle/feeds              register a feed (derives + inits FeedCache)
//	POST   /v1/oracle/feeds/{id}/refresh force a refresh now
//	POST   /v1/oracle/feeds/{id}/pause   pause (worker + on-chain force-stale)
//	POST   /v1/oracle/feeds/{id}/resume  resume
//	DELETE /v1/oracle/feeds/{id}         remove from the registry (PDA kept)
func MountRoutes(r chi.Router, opts RouteOptions) {
	h := &handler{svc: opts.Service}
	r.Get("/v1/oracle/catalog", h.catalog)
	r.Get("/v1/oracle/feeds", h.list)
	r.Post("/v1/oracle/feeds", h.register)
	r.Post("/v1/oracle/feeds/{id}/refresh", h.refresh)
	r.Post("/v1/oracle/feeds/{id}/pause", h.pause)
	r.Post("/v1/oracle/feeds/{id}/resume", h.resume)
	r.Delete("/v1/oracle/feeds/{id}", h.delete)
}

type handler struct {
	svc *Service
}

// ─── DTOs ────────────────────────────────────────────────────────

type feedJSON struct {
	ID              string  `json:"id"`
	Label           string  `json:"label"`
	Cluster         string  `json:"cluster"`
	PythFeedIDHex   string  `json:"pyth_feed_id_hex"`
	FeedCachePDA    string  `json:"feed_cache_pda"`
	PythAccount     string  `json:"pyth_account"`
	PythAccountKind string  `json:"pyth_account_kind"`
	RefreshInterval int     `json:"refresh_interval_seconds"`
	Paused          bool    `json:"paused"`
	LastPublishTime *string `json:"last_publish_time,omitempty"`
	LastTxSignature *string `json:"last_tx_signature,omitempty"`
	LastError       *string `json:"last_error,omitempty"`
	AgeSeconds      *int64  `json:"age_seconds,omitempty"`
}

func toFeedJSON(f Feed) feedJSON {
	out := feedJSON{
		ID:              f.ID,
		Label:           f.Label,
		Cluster:         f.Cluster,
		PythFeedIDHex:   f.PythFeedIDHex,
		FeedCachePDA:    f.FeedCachePDA,
		PythAccount:     f.PythAccount,
		PythAccountKind: f.PythAccountKind,
		RefreshInterval: f.RefreshInterval,
		Paused:          f.Paused,
		LastTxSignature: f.LastTxSignature,
		LastError:       f.LastError,
	}
	if f.LastPublishTime != nil {
		s := f.LastPublishTime.UTC().Format(time.RFC3339)
		out.LastPublishTime = &s
		age := int64(time.Since(*f.LastPublishTime).Seconds())
		out.AgeSeconds = &age
	}
	return out
}

type registerRequest struct {
	Label           string `json:"label" validate:"required,max=64"`
	PythFeedIDHex   string `json:"pyth_feed_id_hex" validate:"required,hex_len=32"`
	PythAccount     string `json:"pyth_account" validate:"required,solana_pubkey"`
	PythAccountKind string `json:"pyth_account_kind,omitempty" validate:"omitempty,oneof=price_feed price_update_v2"`
	RefreshInterval int    `json:"refresh_interval_seconds,omitempty" validate:"omitempty,min=1,max=3600"`
}

type listResponse struct {
	Feeds []feedJSON `json:"feeds"`
}

// ─── handlers ────────────────────────────────────────────────────

func (h *handler) catalog(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query().Get("query")
	assetType := r.URL.Query().Get("asset_type")
	entries, err := h.svc.Catalog(r.Context(), q, assetType)
	if err != nil {
		httpx.WriteError(w, http.StatusBadGateway, "catalog_failed", "could not fetch the Pyth feed catalog")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"feeds": entries})
}

func (h *handler) list(w http.ResponseWriter, r *http.Request) {
	feeds, err := h.svc.ListFeeds(r.Context())
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "list_failed", "could not list oracle feeds")
		return
	}
	out := make([]feedJSON, 0, len(feeds))
	for _, f := range feeds {
		out = append(out, toFeedJSON(f))
	}
	httpx.WriteJSON(w, http.StatusOK, listResponse{Feeds: out})
}

func (h *handler) register(w http.ResponseWriter, r *http.Request) {
	var req registerRequest
	if !httpx.BindAndValidate(w, r, &req, 4<<10) {
		return
	}
	feed, err := h.svc.RegisterFeed(r.Context(), FeedSeed{
		Label:           req.Label,
		PythFeedIDHex:   req.PythFeedIDHex,
		PythAccount:     req.PythAccount,
		PythAccountKind: req.PythAccountKind,
		RefreshInterval: req.RefreshInterval,
	})
	if err != nil {
		httpx.WriteError(w, http.StatusBadGateway, "register_failed", err.Error())
		return
	}
	httpx.WriteJSON(w, http.StatusOK, toFeedJSON(*feed))
}

func (h *handler) refresh(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	o, err := h.svc.ForceRefresh(r.Context(), id)
	if err != nil {
		writeFeedErr(w, err)
		return
	}
	resp := map[string]any{"result": o.Result}
	if o.TxSignature != "" {
		resp["tx_signature"] = o.TxSignature
	}
	if o.Err != "" {
		resp["error"] = o.Err
	}
	httpx.WriteJSON(w, http.StatusOK, resp)
}

func (h *handler) pause(w http.ResponseWriter, r *http.Request) {
	if err := h.svc.PauseFeed(r.Context(), chi.URLParam(r, "id")); err != nil {
		writeFeedErr(w, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"paused": true})
}

func (h *handler) resume(w http.ResponseWriter, r *http.Request) {
	if err := h.svc.ResumeFeed(r.Context(), chi.URLParam(r, "id")); err != nil {
		writeFeedErr(w, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"paused": false})
}

func (h *handler) delete(w http.ResponseWriter, r *http.Request) {
	if err := h.svc.DeleteFeed(r.Context(), chi.URLParam(r, "id")); err != nil {
		writeFeedErr(w, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"deleted": true})
}

func writeFeedErr(w http.ResponseWriter, err error) {
	if errors.Is(err, ErrNotFound) {
		httpx.WriteError(w, http.StatusNotFound, "not_found", "oracle feed not found")
		return
	}
	httpx.WriteError(w, http.StatusBadGateway, "oracle_op_failed", err.Error())
}
