// Package util mounts small, dependency-free helper routes that the gateway
// serves in-process. Currently: a display-only amount formatter.
//
// These are conveniences for devs building UIs on top of Andromeda — they hold
// no state, touch no engine, and their output is NEVER a signed message. The
// amount formatter shares its canonical core (internal/humanfmt) with the
// on-chain human messages, so what a dev renders matches what a user signs.
package util

import (
	"math/big"
	"net/http"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/shinkalabs/andromeda-gateway/internal/httpx"
	"github.com/shinkalabs/andromeda-gateway/internal/humanfmt"
)

// MountRoutes registers the utility endpoints. Must be called inside a
// chi.Group that already applied requireAPIKey + scope + subscription +
// rate limit + quota.
//
//	GET /v1/util/format-amount?raw=&decimals=&symbol=&group=
func MountRoutes(r chi.Router) {
	r.Get("/v1/util/format-amount", handleFormatAmount)
}

// formatAmountResponse is the display-only envelope. `formatted` is for human
// display only and must never be treated as signed bytes.
type formatAmountResponse struct {
	Formatted string `json:"formatted"`
	Raw       string `json:"raw"`
	Decimals  int    `json:"decimals"`
	// Note reminds callers this is presentational, not the signed message.
	Note string `json:"note"`
}

func handleFormatAmount(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()

	rawStr := strings.TrimSpace(q.Get("raw"))
	if rawStr == "" {
		httpx.WriteError(w, http.StatusBadRequest, "missing_raw", "query param 'raw' (integer base units) is required")
		return
	}
	raw, ok := new(big.Int).SetString(rawStr, 10)
	if !ok || raw.Sign() < 0 {
		httpx.WriteError(w, http.StatusBadRequest, "invalid_raw", "'raw' must be a non-negative base-10 integer")
		return
	}

	decimals, err := strconv.Atoi(strings.TrimSpace(q.Get("decimals")))
	if err != nil || decimals < 0 || decimals > humanfmt.MaxDecimals {
		httpx.WriteError(w, http.StatusBadRequest, "invalid_decimals",
			"'decimals' must be an integer in [0, "+strconv.Itoa(humanfmt.MaxDecimals)+"]")
		return
	}

	opts := humanfmt.Options{
		Symbol: strings.TrimSpace(q.Get("symbol")),
		Group:  q.Get("group") == "true" || q.Get("group") == "1",
	}

	formatted, err := humanfmt.FormatAmount(raw, decimals, opts)
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "format_failed", err.Error())
		return
	}

	httpx.WriteJSON(w, http.StatusOK, formatAmountResponse{
		Formatted: formatted,
		Raw:       raw.String(),
		Decimals:  decimals,
		Note:      "display-only; not a signed message",
	})
}
