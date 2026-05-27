package chains

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/shinkalabs/andromeda-intents/internal/metrics"
)

// SuiBroadcaster is a minimal JSON-RPC client for Sui mainnet: execute a
// signed TransactionBlock and read native (SUI) balance. It fails over across
// the RPC URLs the caller resolved (override → LI.FI /chains cache). No keys.
type SuiBroadcaster struct {
	http    *http.Client
	metrics *metrics.Metrics
	logger  *slog.Logger
}

func NewSuiBroadcaster(m *metrics.Metrics, logger *slog.Logger) *SuiBroadcaster {
	return &SuiBroadcaster{
		http:    &http.Client{Timeout: 30 * time.Second},
		metrics: m,
		logger:  logger,
	}
}

// Execute sends a signed Sui TransactionBlock. txBytesB64 is the base64-encoded
// BCS TransactionData; sigsB64 is the array of Sui-flagged signatures (1-byte
// scheme flag || 64-byte sig || 32-byte pubkey, all base64'd).
//
// Returns (digest, unknown, err): a hard JSON-RPC rejection (bad tx, gas, …)
// is deterministic; a transport-ambiguous failure (timeout / 5xx) sets
// unknown so the caller reconciles by digest, never blind-retries.
func (b *SuiBroadcaster) Execute(ctx context.Context, urls []string, txBytesB64 string, sigsB64 []string, chainID int) (string, bool, error) {
	idLabel := strconv.Itoa(chainID)
	var lastErr error
	ambiguous := false

	params := []any{
		txBytesB64,
		sigsB64,
		map[string]any{"showEffects": true},
		"WaitForLocalExecution",
	}

	for i, url := range urls {
		if i > 0 && b.metrics != nil {
			b.metrics.RPCFailover.WithLabelValues("sui", idLabel).Inc()
		}
		start := time.Now()
		result, rpcErr, err := suiCall(ctx, b.http, url, "sui_executeTransactionBlock", params)
		if b.metrics != nil {
			b.metrics.BroadcastDuration.WithLabelValues("sui").Observe(time.Since(start).Seconds())
		}
		if err != nil {
			lastErr = err
			ambiguous = true
			continue
		}
		if rpcErr != nil {
			low := strings.ToLower(*rpcErr)
			// "already executed" / "transaction already in mempool" mean a previous
			// broadcast attempt already landed the tx, but this call did not
			// return its digest — the gateway must reconcile via the LI.FI /status
			// route, never blind-retry. Mark ambiguous and keep trying other URLs
			// (a different fullnode may surface the executed result).
			if strings.Contains(low, "already executed") || strings.Contains(low, "already in mempool") {
				ambiguous = true
				lastErr = fmt.Errorf("sui rpc reported tx already known: %s", *rpcErr)
				continue
			}
			// Genuine deterministic rejection (insufficient gas, sender mismatch,
			// stale gas object, …) — same outcome on every node.
			return "", false, fmt.Errorf("sui rpc rejected: %s", *rpcErr)
		}
		var resp struct {
			Digest string `json:"digest"`
		}
		if err := json.Unmarshal(result, &resp); err != nil || resp.Digest == "" {
			lastErr = fmt.Errorf("sui rpc returned no digest")
			continue
		}
		return resp.Digest, false, nil
	}
	if ambiguous && b.metrics != nil {
		b.metrics.BroadcastUnknown.WithLabelValues("sui", idLabel).Inc()
	}
	return "", ambiguous, lastErr
}

// Balance returns the dWallet's SUI balance in MIST (1 SUI = 1e9 MIST) as a
// decimal string. Uses suix_getBalance with the native coin type.
func (b *SuiBroadcaster) Balance(ctx context.Context, urls []string, address string) (string, error) {
	params := []any{address, "0x2::sui::SUI"}
	var lastErr error
	for _, url := range urls {
		result, rpcErr, err := suiCall(ctx, b.http, url, "suix_getBalance", params)
		if err != nil {
			lastErr = err
			continue
		}
		if rpcErr != nil {
			return "", fmt.Errorf("suix_getBalance rejected: %s", *rpcErr)
		}
		var bal struct {
			TotalBalance string `json:"totalBalance"`
		}
		if err := json.Unmarshal(result, &bal); err != nil {
			return "", fmt.Errorf("decode sui balance: %w", err)
		}
		if bal.TotalBalance == "" {
			return "0", nil
		}
		return bal.TotalBalance, nil
	}
	return "", lastErr
}

// suiCall is the per-URL JSON-RPC dispatcher (Sui is JSON-RPC 2.0 like EVM).
// Kept separate from the EVM helper because Sui's error/result shapes differ
// slightly and we want clean type boundaries.
func suiCall(ctx context.Context, client *http.Client, url, method string, params []any) (json.RawMessage, *string, error) {
	body, err := json.Marshal(map[string]any{
		"jsonrpc": "2.0", "id": 1, "method": method, "params": params,
	})
	if err != nil {
		return nil, nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return nil, nil, err
	}
	if resp.StatusCode >= 500 {
		return nil, nil, fmt.Errorf("sui rpc http %d", resp.StatusCode)
	}
	var parsed struct {
		Result json.RawMessage `json:"result"`
		Error  *struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return nil, nil, fmt.Errorf("decode sui rpc: %w", err)
	}
	if parsed.Error != nil {
		msg := parsed.Error.Message
		return nil, &msg, nil
	}
	return parsed.Result, nil, nil
}
