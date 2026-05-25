package api

import "github.com/go-chi/chi/v5"

// Mount registers every internal route on the given router (already behind the
// X-Internal-Key guard). Paths are short; the gateway maps the public
// /v1/intents/* surface onto them via UpstreamPath.
func (h *Handlers) Mount(r chi.Router) {
	r.Post("/quote", h.quote)
	r.Post("/prepare", h.prepareSwap)
	r.Post("/derive-message", h.deriveMessage)
	r.Post("/finalize", h.finalizeSwap)
	r.Get("/tx-status", h.txStatus)
	r.Get("/evm/receipt", h.evmReceipt)
	r.Get("/native-balance", h.nativeBalance)
	r.Get("/chains", h.chains)
	r.Get("/tokens", h.tokens)
}
