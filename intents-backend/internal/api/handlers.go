package api

import (
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/shinkalabs/andromeda-intents/internal/httpx"
	"github.com/shinkalabs/andromeda-intents/internal/lifi"
	"github.com/shinkalabs/andromeda-intents/internal/metrics"
	"github.com/shinkalabs/andromeda-intents/internal/swap"
)

// Handlers groups the intents-backend HTTP handlers and their dependencies.
type Handlers struct {
	lifi       *lifi.Client
	swap       *swap.Service
	metrics    *metrics.Metrics
	logger     *slog.Logger
	quoteCache *quoteCache
}

// NewHandlers wires the handler dependencies. quoteCacheTTL > 0 enables the
// short-lived preview cache on /quote (per-replica, display-only); <= 0 disables
// it (every quote hits LI.FI).
func NewHandlers(l *lifi.Client, s *swap.Service, m *metrics.Metrics, logger *slog.Logger, quoteCacheTTL time.Duration) *Handlers {
	var qc *quoteCache
	if quoteCacheTTL > 0 {
		qc = newQuoteCache(quoteCacheTTL, quoteCacheMaxEntries)
	}
	return &Handlers{lifi: l, swap: s, metrics: m, logger: logger, quoteCache: qc}
}

const maxBody = 64 << 10

// quote is the dry preview: price, unified fee, native gas estimate, validity.
func (h *Handlers) quote(w http.ResponseWriter, r *http.Request) {
	var req quoteRequest
	if err := httpx.DecodeJSON(r, &req, maxBody); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid_body", "invalid request body")
		return
	}
	if err := validate.Struct(&req); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "validation_failed", "invalid quote parameters")
		return
	}

	// Short-lived preview cache: absorbs repeated identical quotes (keystrokes,
	// agent re-checks, popular pairs) so they don't all hit LI.FI. Display-only —
	// the transactionRequest is never cached; prepare always re-quotes fresh.
	key := quoteCacheKey(req)
	if view, ok := h.quoteCache.get(key); ok {
		h.recordQuoteCache("hit")
		httpx.WriteJSON(w, http.StatusOK, view)
		return
	}

	step, err := h.lifi.Quote(r.Context(), toQuoteParams(req))
	if err != nil {
		h.writeLifiError(w, "quote", err)
		return
	}
	view := normalizeQuote(step)
	h.quoteCache.put(key, view)
	h.recordQuoteCache("miss")
	httpx.WriteJSON(w, http.StatusOK, view)
}

// recordQuoteCache increments the quote-cache result counter (nil-safe).
func (h *Handlers) recordQuoteCache(result string) {
	if h.metrics != nil {
		h.metrics.QuoteCacheTotal.WithLabelValues(result).Inc()
	}
}

// prepareSwap builds the unsigned swap tx and the message-to-sign for the
// gateway. It does NOT touch keys, policy or signing — that is the gateway's job.
func (h *Handlers) prepareSwap(w http.ResponseWriter, r *http.Request) {
	var req prepareRequest
	if err := httpx.DecodeJSON(r, &req, maxBody); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid_body", "invalid request body")
		return
	}
	if err := validate.Struct(&req); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "validation_failed", "invalid prepare parameters")
		return
	}
	if !h.swap.IsKindRegistered(req.ChainKind) {
		httpx.WriteError(w, http.StatusBadRequest, "unsupported_chain_kind", "chainKind is not supported")
		return
	}

	out, err := h.swap.Prepare(r.Context(), swap.PrepareInput{
		Params:    toQuoteParams(req.quoteRequest),
		ChainKind: req.ChainKind,
	})
	if err != nil {
		h.writeSwapError(w, "prepare", req.ChainKind, err)
		return
	}
	if h.metrics != nil {
		h.metrics.SwapPrepareTotal.WithLabelValues(req.ChainKind, "ok").Inc()
	}
	httpx.WriteJSON(w, http.StatusOK, out)
}

// finalizeSwap inserts the dWallet signature into the prepared tx and broadcasts.
func (h *Handlers) finalizeSwap(w http.ResponseWriter, r *http.Request) {
	var req finalizeRequest
	if err := httpx.DecodeJSON(r, &req, maxBody); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid_body", "invalid request body")
		return
	}
	if err := validate.Struct(&req); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "validation_failed", "invalid finalize parameters")
		return
	}
	if !h.swap.IsKindRegistered(req.ChainKind) {
		httpx.WriteError(w, http.StatusBadRequest, "unsupported_chain_kind", "chainKind is not supported")
		return
	}

	out, err := h.swap.Finalize(r.Context(), swap.FinalizeInput{
		ChainKind:       req.ChainKind,
		UnsignedTxB64:   req.UnsignedTxB64,
		SignatureB64:    req.SignatureB64,
		SignerPubkeyHex: req.SignerPubkeyHex,
		ChainID:         req.ChainID,
	})
	if err != nil {
		h.writeSwapError(w, "finalize", req.ChainKind, err)
		return
	}
	if h.metrics != nil {
		result := "ok"
		if out.BroadcastUnknown {
			result = "broadcast_unknown"
		}
		h.metrics.SwapFinalizeTotal.WithLabelValues(req.ChainKind, result).Inc()
	}
	httpx.WriteJSON(w, http.StatusOK, out)
}

// chains proxies LI.FI /chains (cacheable upstream of broadcast RPCs).
func (h *Handlers) chains(w http.ResponseWriter, r *http.Request) {
	body, err := h.lifi.Chains(r.Context(), r.URL.Query().Get("chainTypes"))
	if err != nil {
		h.writeLifiError(w, "chains", err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
}

// tokens proxies LI.FI /tokens.
func (h *Handlers) tokens(w http.ResponseWriter, r *http.Request) {
	body, err := h.lifi.Tokens(r.Context(), r.URL.Query().Get("chains"))
	if err != nil {
		h.writeLifiError(w, "tokens", err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
}

// deriveMessage re-derives the signing material from a persisted unsignedTx
// (no re-quote), so the gateway can re-validate the snapshot before signing.
func (h *Handlers) deriveMessage(w http.ResponseWriter, r *http.Request) {
	var req deriveRequest
	if err := httpx.DecodeJSON(r, &req, maxBody); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid_body", "invalid request body")
		return
	}
	if err := validate.Struct(&req); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "validation_failed", "invalid derive parameters")
		return
	}
	if !h.swap.IsKindRegistered(req.ChainKind) {
		httpx.WriteError(w, http.StatusBadRequest, "unsupported_chain_kind", "chainKind is not supported")
		return
	}
	out, err := h.swap.DeriveMessage(req.ChainKind, req.UnsignedTxB64)
	if err != nil {
		h.writeSwapError(w, "derive", req.ChainKind, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, out)
}

// nativeBalance returns the dWallet's native-token balance (base units) on a
// chain — the gateway pre-checks it can pay the swap gas.
func (h *Handlers) nativeBalance(w http.ResponseWriter, r *http.Request) {
	chainKind := r.URL.Query().Get("chainKind")
	chainID, err := strconv.Atoi(r.URL.Query().Get("chainId"))
	address := r.URL.Query().Get("address")
	if chainKind == "" || err != nil || chainID <= 0 || address == "" {
		httpx.WriteError(w, http.StatusBadRequest, "invalid_params", "chainKind, a positive chainId and address are required")
		return
	}
	if !h.swap.IsKindRegistered(chainKind) {
		httpx.WriteError(w, http.StatusBadRequest, "unsupported_chain_kind", "chainKind is not supported")
		return
	}
	bal, err := h.swap.NativeBalance(r.Context(), chainKind, chainID, address)
	if err != nil {
		httpx.WriteError(w, http.StatusBadGateway, "rpc_error", "could not read native balance")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]string{"balance": bal})
}

// evmReceipt reports whether an EVM tx (e.g. an ERC20 approve) is mined and
// succeeded — the gateway gates the swap on it.
func (h *Handlers) evmReceipt(w http.ResponseWriter, r *http.Request) {
	txHash := r.URL.Query().Get("txHash")
	chainID, err := strconv.Atoi(r.URL.Query().Get("chainId"))
	if txHash == "" || err != nil || chainID <= 0 {
		httpx.WriteError(w, http.StatusBadRequest, "invalid_params", "txHash and a positive chainId are required")
		return
	}
	found, success, err := h.swap.EVMReceipt(r.Context(), chainID, txHash)
	if err != nil {
		httpx.WriteError(w, http.StatusBadGateway, "rpc_error", "could not read receipt")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]bool{"found": found, "success": success})
}

// txStatus normalizes LI.FI /status for a broadcast tx hash.
func (h *Handlers) txStatus(w http.ResponseWriter, r *http.Request) {
	txHash := r.URL.Query().Get("txHash")
	if txHash == "" {
		httpx.WriteError(w, http.StatusBadRequest, "missing_tx_hash", "txHash is required")
		return
	}
	st, err := h.lifi.Status(r.Context(), txHash, r.URL.Query().Get("fromChain"), r.URL.Query().Get("toChain"))
	if err != nil {
		h.writeLifiError(w, "status", err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, st)
}

func toQuoteParams(req quoteRequest) lifi.QuoteParams {
	return lifi.QuoteParams{
		FromChain:   req.FromChain,
		ToChain:     req.ToChain,
		FromToken:   req.FromToken,
		ToToken:     req.ToToken,
		FromAmount:  req.FromAmount,
		FromAddress: req.FromAddress,
		ToAddress:   req.ToAddress,
		SlippageBps: req.SlippageBps,
	}
}

// writeLifiError maps LI.FI client errors to sanitized HTTP responses. The raw
// upstream body is never forwarded.
func (h *Handlers) writeLifiError(w http.ResponseWriter, endpoint string, err error) {
	if errors.Is(err, lifi.ErrBackpressure) {
		w.Header().Set("Retry-After", "5")
		httpx.WriteJSON(w, http.StatusTooManyRequests, map[string]any{
			"error": "aggregator rate limit reached, retry shortly", "code": "backpressure", "retryAfterSeconds": 5,
		})
		return
	}
	var up *lifi.ErrUpstream
	if errors.As(err, &up) {
		status := http.StatusBadGateway
		code := "aggregator_error"
		if up.StatusCode >= 400 && up.StatusCode < 500 {
			status = http.StatusUnprocessableEntity
			code = "no_route"
		}
		httpx.WriteError(w, status, code, "aggregator could not fulfill the request")
		return
	}
	h.logger.Error("lifi call failed", "endpoint", endpoint, "err", err)
	httpx.WriteError(w, http.StatusBadGateway, "aggregator_unavailable", "aggregator unavailable")
}

// writeSwapError maps swap-layer errors. Validation/invariant failures are 422;
// LI.FI errors reuse writeLifiError; everything else is a sanitized 502.
func (h *Handlers) writeSwapError(w http.ResponseWriter, op, chainKind string, err error) {
	if h.metrics != nil {
		// Count the error against the metric for the operation that failed —
		// a finalize failure must not inflate the prepare error counter.
		switch op {
		case "prepare":
			h.metrics.SwapPrepareTotal.WithLabelValues(chainKind, "error").Inc()
		case "finalize":
			h.metrics.SwapFinalizeTotal.WithLabelValues(chainKind, "error").Inc()
		}
	}
	var inv *swap.InvariantError
	if errors.As(err, &inv) {
		httpx.WriteError(w, http.StatusUnprocessableEntity, "invariant_failed", inv.Error())
		return
	}
	if errors.Is(err, lifi.ErrBackpressure) || asUpstream(err) {
		h.writeLifiError(w, op, err)
		return
	}
	h.logger.Error("swap op failed", "op", op, "chain_kind", chainKind, "err", err)
	httpx.WriteError(w, http.StatusBadGateway, "swap_failed", "swap operation failed")
}

func asUpstream(err error) bool {
	var up *lifi.ErrUpstream
	return errors.As(err, &up)
}
