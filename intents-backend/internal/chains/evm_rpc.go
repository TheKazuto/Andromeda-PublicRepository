package chains

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/shinkalabs/andromeda-intents/internal/metrics"
)

// EVMBroadcaster is a minimal JSON-RPC client for EVM chains: send a signed raw
// tx, read state (eth_call), and fetch the pending nonce. It fails over across
// the RPC URLs the caller resolved (override, else LI.FI /chains). No keys.
type EVMBroadcaster struct {
	http    *http.Client
	metrics *metrics.Metrics
	logger  *slog.Logger
}

func NewEVMBroadcaster(m *metrics.Metrics, logger *slog.Logger) *EVMBroadcaster {
	return &EVMBroadcaster{
		http:    &http.Client{Timeout: 20 * time.Second},
		metrics: m,
		logger:  logger,
	}
}

type rpcRequest struct {
	JSONRPC string `json:"jsonrpc"`
	ID      int    `json:"id"`
	Method  string `json:"method"`
	Params  []any  `json:"params"`
}

type rpcResponse struct {
	Result json.RawMessage `json:"result"`
	Error  *struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

// call does a single JSON-RPC call against one URL. rpcErr is set when the node
// returned a JSON-RPC error (deterministic); transport errors come back as err.
func (b *EVMBroadcaster) call(ctx context.Context, url, method string, params []any) (json.RawMessage, *string, error) {
	body, err := json.Marshal(rpcRequest{JSONRPC: "2.0", ID: 1, Method: method, Params: params})
	if err != nil {
		return nil, nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := b.http.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return nil, nil, err
	}
	if resp.StatusCode >= 500 {
		return nil, nil, fmt.Errorf("rpc http %d", resp.StatusCode)
	}
	var parsed rpcResponse
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return nil, nil, fmt.Errorf("decode rpc response: %w", err)
	}
	if parsed.Error != nil {
		msg := parsed.Error.Message
		return nil, &msg, nil
	}
	return parsed.Result, nil, nil
}

// SendRawTransaction broadcasts a signed tx, trying each URL. Returns
// (txHash, unknown, err). A node-level rejection is deterministic (no retry);
// "already known"/"nonce too low" means the tx is already in flight (returns the
// hash, not unknown). Transport failure on every URL → unknown.
func (b *EVMBroadcaster) SendRawTransaction(ctx context.Context, urls []string, rawTx []byte, knownHash string, chainID int) (string, bool, error) {
	raw0x := "0x" + hex.EncodeToString(rawTx)
	idLabel := strconv.Itoa(chainID)
	var lastErr error
	ambiguous := false
	for i, url := range urls {
		if i > 0 && b.metrics != nil {
			b.metrics.RPCFailover.WithLabelValues("evm", idLabel).Inc()
		}
		start := time.Now()
		result, rpcErr, err := b.call(ctx, url, "eth_sendRawTransaction", []any{raw0x})
		if b.metrics != nil {
			b.metrics.BroadcastDuration.WithLabelValues("evm").Observe(time.Since(start).Seconds())
		}
		if err != nil {
			lastErr = err
			ambiguous = true // transport — the node may or may not have received it
			continue
		}
		if rpcErr != nil {
			low := strings.ToLower(*rpcErr)
			if strings.Contains(low, "already known") || strings.Contains(low, "nonce too low") || strings.Contains(low, "already imported") {
				// The tx (this nonce) is already in flight — same outcome on every
				// node. Return the deterministic hash; not unknown.
				return knownHash, false, nil
			}
			return "", false, fmt.Errorf("rpc rejected: %s", *rpcErr)
		}
		var hash string
		if err := json.Unmarshal(result, &hash); err == nil && hash != "" {
			return hash, false, nil
		}
		return knownHash, false, nil
	}
	if ambiguous && b.metrics != nil {
		b.metrics.BroadcastUnknown.WithLabelValues("evm", idLabel).Inc()
	}
	return "", ambiguous, lastErr
}

// EthCall performs a read-only eth_call at "latest". Returns the raw result bytes.
func (b *EVMBroadcaster) EthCall(ctx context.Context, urls []string, to string, data []byte) ([]byte, error) {
	param := map[string]string{"to": to, "data": "0x" + hex.EncodeToString(data)}
	var lastErr error
	for _, url := range urls {
		result, rpcErr, err := b.call(ctx, url, "eth_call", []any{param, "latest"})
		if err != nil {
			lastErr = err
			continue
		}
		if rpcErr != nil {
			return nil, fmt.Errorf("eth_call rejected: %s", *rpcErr)
		}
		var hexStr string
		if err := json.Unmarshal(result, &hexStr); err != nil {
			return nil, err
		}
		clean := strings.TrimPrefix(hexStr, "0x")
		if len(clean)%2 == 1 { // odd nibble count (e.g. "0x0") — left-pad
			clean = "0" + clean
		}
		return hex.DecodeString(clean)
	}
	return nil, lastErr
}

// Balance returns the native balance (wei) of an address, trying each RPC.
func (b *EVMBroadcaster) Balance(ctx context.Context, urls []string, address string) (*big.Int, error) {
	var lastErr error
	for _, url := range urls {
		result, rpcErr, err := b.call(ctx, url, "eth_getBalance", []any{address, "latest"})
		if err != nil {
			lastErr = err
			continue
		}
		if rpcErr != nil {
			return nil, fmt.Errorf("eth_getBalance rejected: %s", *rpcErr)
		}
		var hexStr string
		if err := json.Unmarshal(result, &hexStr); err != nil {
			return nil, err
		}
		n, ok := new(big.Int).SetString(strings.TrimPrefix(hexStr, "0x"), 16)
		if !ok {
			return nil, fmt.Errorf("invalid balance hex %q", hexStr)
		}
		return n, nil
	}
	return nil, lastErr
}

// TransactionReceipt returns (found, success). found=false means the tx is not
// mined yet (receipt null). Used to gate the swap on the approve confirming.
func (b *EVMBroadcaster) TransactionReceipt(ctx context.Context, urls []string, txHash string) (bool, bool, error) {
	var lastErr error
	for _, url := range urls {
		result, rpcErr, err := b.call(ctx, url, "eth_getTransactionReceipt", []any{txHash})
		if err != nil {
			lastErr = err
			continue
		}
		if rpcErr != nil {
			return false, false, fmt.Errorf("eth_getTransactionReceipt rejected: %s", *rpcErr)
		}
		if len(result) == 0 || string(result) == "null" {
			return false, false, nil // not mined yet
		}
		var r struct {
			Status string `json:"status"`
		}
		if err := json.Unmarshal(result, &r); err != nil {
			return true, false, fmt.Errorf("decode receipt: %w", err)
		}
		return true, r.Status == "0x1", nil
	}
	return false, false, lastErr
}

// PendingNonce returns eth_getTransactionCount(addr, "pending").
func (b *EVMBroadcaster) PendingNonce(ctx context.Context, urls []string, addr string) (uint64, error) {
	var lastErr error
	for _, url := range urls {
		result, rpcErr, err := b.call(ctx, url, "eth_getTransactionCount", []any{addr, "pending"})
		if err != nil {
			lastErr = err
			continue
		}
		if rpcErr != nil {
			return 0, fmt.Errorf("eth_getTransactionCount rejected: %s", *rpcErr)
		}
		var hexStr string
		if err := json.Unmarshal(result, &hexStr); err != nil {
			return 0, err
		}
		n, ok := new(big.Int).SetString(strings.TrimPrefix(hexStr, "0x"), 16)
		if !ok {
			return 0, fmt.Errorf("invalid nonce hex %q", hexStr)
		}
		return n.Uint64(), nil
	}
	return 0, lastErr
}
