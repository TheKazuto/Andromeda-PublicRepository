package mcp

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"time"
)

// Handler is the HTTP handler for /mcp.
type Handler struct {
	logger  *slog.Logger
	tools   *ToolRegistry
	charger ToolCharger
}

// NewHandler constructs a Handler. Pass nil charger to disable per-tool
// quota deduction — useful for tests and dev environments where the
// REST middleware already covered the call (legacy mode).
func NewHandler(logger *slog.Logger, tools *ToolRegistry, charger ToolCharger) *Handler {
	return &Handler{logger: logger, tools: tools, charger: charger}
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		// MCP Streamable HTTP transport: GET opens an SSE stream the
		// server can use for notifications (tool list changes, etc).
		// Andromeda has no server-initiated events today, so the stream
		// is mostly a keepalive — clients that issue GET get a stable
		// connection and a heartbeat every 15s, satisfying spec compat.
		h.serveSSE(w, r)
		return
	}
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, nil, rpcInvalidRequest, "POST or GET required")
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		writeError(w, http.StatusBadRequest, nil, rpcParseError, "could not read body")
		return
	}

	var req rpcRequest
	if err := json.Unmarshal(body, &req); err != nil {
		writeError(w, http.StatusBadRequest, nil, rpcParseError, "invalid JSON-RPC")
		return
	}
	if req.JSONRPC != "2.0" {
		writeError(w, http.StatusBadRequest, req.ID, rpcInvalidRequest, "jsonrpc must be '2.0'")
		return
	}

	switch req.Method {
	case "initialize":
		writeResult(w, req.ID, initializeResult{
			ProtocolVersion: ProtocolVersion,
			Capabilities: map[string]any{
				"tools": map[string]any{"listChanged": false},
			},
			ServerInfo: map[string]any{
				"name":      "andromeda-gateway",
				"version":   "0.1.0",
				"toolCount": h.tools.Count(),
			},
			Instructions: serverInstructions,
		})

	case "notifications/initialized":
		// Notification — no response.
		w.WriteHeader(http.StatusNoContent)

	case "tools/list":
		writeResult(w, req.ID, toolsListResult{Tools: h.tools.List()})

	case "tools/call":
		var p callToolParams
		if err := json.Unmarshal(req.Params, &p); err != nil {
			writeError(w, http.StatusBadRequest, req.ID, rpcInvalidParams, "invalid params")
			return
		}
		handler, ok := h.tools.Handler(p.Name)
		if !ok {
			writeError(w, http.StatusNotFound, req.ID, rpcMethodNotFound, "tool not found: "+p.Name)
			return
		}

		// Charge the tool's specific quota cost BEFORE invoking. The
		// charger uses pricer.Cost(toolKey) which mirrors the REST
		// price catalogue — so MCP `ika.sign.submit` costs the same
		// as the REST equivalent.
		var refund Refundable
		if h.charger != nil {
			r2, cerr := h.charger.Charge(r.Context(), r, p.Name)
			if cerr != nil {
				var ce *chargerError
				if errors.As(cerr, &ce) {
					writeError(w, http.StatusPaymentRequired, req.ID, ce.code, ce.Error())
				} else {
					writeError(w, http.StatusInternalServerError, req.ID, rpcInternalError, cerr.Error())
				}
				return
			}
			refund = r2
		}

		// Stash the inbound request's auth-bearing headers + remote addr
		// on the context so Local-route tools (PolicyEngine) can build a
		// faithful sibling *http.Request and serve it on the loopback mux.
		toolCtx := WithLoopbackInbound(r.Context(), &LoopbackInbound{
			Headers:    r.Header.Clone(),
			RemoteAddr: r.RemoteAddr,
		})

		res, err := handler(toolCtx, p.Arguments)
		// Refund only on a technical/upstream-5xx failure — never on a
		// 4xx (caller's fault). Mirrors the REST proxy's refund-on-5xx
		// policy. handler errors are always treated as technical.
		if refund != nil && (err != nil || res.RefundableError) {
			refund.Refund(r.Context())
		}
		if err != nil {
			// Log the full upstream error server-side; return a stable,
			// sanitised code to the MCP client. The handler error may
			// contain raw upstream bodies, internal hostnames, or Vault
			// status codes — never echo those across the trust boundary.
			h.logger.Error("mcp tool error", "tool", p.Name, "err", err)
			writeError(w, http.StatusInternalServerError, req.ID,
				rpcInternalError, "tool_execution_failed")
			return
		}
		writeResult(w, req.ID, res)

	case "ping":
		writeResult(w, req.ID, map[string]any{})

	default:
		writeError(w, http.StatusNotFound, req.ID, rpcMethodNotFound, "method not implemented: "+req.Method)
	}
}

func writeResult(w http.ResponseWriter, id json.RawMessage, result any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(rpcResponse{
		JSONRPC: "2.0",
		ID:      id,
		Result:  result,
	})
}

func writeError(w http.ResponseWriter, status int, id json.RawMessage, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(rpcResponse{
		JSONRPC: "2.0",
		ID:      id,
		Error:   &rpcError{Code: code, Message: msg},
	})
}

// sseKeepalive is the cadence of the comment-only ping events. 15s is
// the conventional default — clients that idle longer than this often
// have intermediate proxies (Cloudflare, ELB) that close the socket.
const sseKeepalive = 15 * time.Second

// serveSSE handles GET /mcp by opening a text/event-stream response and
// flushing keepalives until the client disconnects. The connection is
// available for future server-initiated notifications (tools/list_changed,
// progress events, etc) — those plug into a fan-out channel here once
// implemented.
func (h *Handler) serveSSE(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache, no-transform")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no") // disable nginx buffering when relevant
	w.WriteHeader(http.StatusOK)

	// Initial comment frame so clients know the stream is live without
	// having to wait for the first keepalive.
	if _, err := fmt.Fprint(w, ": andromeda mcp stream ready\n\n"); err != nil {
		return
	}
	flusher.Flush()

	t := time.NewTicker(sseKeepalive)
	defer t.Stop()
	ctx := r.Context()

	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if _, err := fmt.Fprint(w, ": keepalive\n\n"); err != nil {
				return
			}
			flusher.Flush()
		}
	}
}
