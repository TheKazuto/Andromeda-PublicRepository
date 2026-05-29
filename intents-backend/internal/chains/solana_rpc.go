// Package chains holds the per-chain broadcast clients. MVP: Solana.
package chains

import (
	"context"
	"log/slog"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gagliardetto/solana-go"
	"github.com/gagliardetto/solana-go/rpc"

	"github.com/shinkalabs/andromeda-intents/internal/metrics"
)

// solanaCallTimeout bounds a single RPC call so a hung node cannot pin a
// goroutine for the whole request window; failover then moves to the next URL.
const solanaCallTimeout = 20 * time.Second

// SolanaBroadcaster sends a signed VersionedTransaction, failing over across the
// RPC URLs the caller resolved (operator override, else the public list from
// LI.FI /chains). It never holds keys — it only relays bytes.
type SolanaBroadcaster struct {
	metrics *metrics.Metrics
	logger  *slog.Logger

	mu      sync.Mutex
	clients map[string]*rpc.Client
}

func NewSolanaBroadcaster(m *metrics.Metrics, logger *slog.Logger) *SolanaBroadcaster {
	return &SolanaBroadcaster{metrics: m, logger: logger, clients: make(map[string]*rpc.Client)}
}

// client returns a pooled rpc.Client for url, building it once. rpc.Client wraps
// a connection-pooling HTTP transport, so reusing it across calls avoids a fresh
// TCP/TLS handshake on every broadcast and balance read.
func (b *SolanaBroadcaster) client(url string) *rpc.Client {
	b.mu.Lock()
	defer b.mu.Unlock()
	if c, ok := b.clients[url]; ok {
		return c
	}
	c := rpc.New(url)
	b.clients[url] = c
	return c
}

// Broadcast tries each RPC URL in order. Returns (signature, unknown, err):
//   - success: (txid, false, nil)
//   - deterministic rejection (bad tx, will fail everywhere): ("", false, err)
//   - transport-ambiguous (the tx may have landed): ("", true, err) — the
//     caller must reconcile by signature, never blind-retry.
func (b *SolanaBroadcaster) Broadcast(ctx context.Context, urls []string, tx *solana.Transaction, chainID int) (string, bool, error) {
	opts := rpc.TransactionOpts{PreflightCommitment: rpc.CommitmentConfirmed}
	var lastErr error
	ambiguous := false
	idLabel := strconv.Itoa(chainID)

	for i, url := range urls {
		if i > 0 && b.metrics != nil {
			b.metrics.RPCFailover.WithLabelValues("solana", idLabel).Inc()
		}
		client := b.client(url)
		callCtx, cancel := context.WithTimeout(ctx, solanaCallTimeout)
		start := time.Now()
		sig, err := client.SendTransactionWithOpts(callCtx, tx, opts)
		cancel()
		if b.metrics != nil {
			b.metrics.BroadcastDuration.WithLabelValues("solana").Observe(time.Since(start).Seconds())
		}
		if err == nil {
			return sig.String(), false, nil
		}
		lastErr = err
		if isDeterministicRejection(err) {
			// Same outcome on every endpoint — stop and surface it safely.
			return "", false, err
		}
		// Transport-level: the node may or may not have accepted the bytes.
		ambiguous = true
	}

	if ambiguous && b.metrics != nil {
		b.metrics.BroadcastUnknown.WithLabelValues("solana", idLabel).Inc()
	}
	return "", ambiguous, lastErr
}

// Balance returns the SOL balance (lamports) of an address, trying each RPC.
func (b *SolanaBroadcaster) Balance(ctx context.Context, urls []string, address string) (uint64, error) {
	pk, err := solana.PublicKeyFromBase58(address)
	if err != nil {
		return 0, err
	}
	var lastErr error
	for _, url := range urls {
		client := b.client(url)
		callCtx, cancel := context.WithTimeout(ctx, solanaCallTimeout)
		out, err := client.GetBalance(callCtx, pk, rpc.CommitmentConfirmed)
		cancel()
		if err != nil {
			lastErr = err
			continue
		}
		return out.Value, nil
	}
	return 0, lastErr
}

// isDeterministicRejection reports whether the RPC rejected the tx for a reason
// that will repeat on every endpoint (so failover/retry is pointless and safe to
// surface). Conservative: anything not matched here is treated as transport-
// ambiguous, which forces reconciliation rather than a blind retry.
func isDeterministicRejection(err error) bool {
	msg := strings.ToLower(err.Error())
	markers := []string{
		"simulation failed",
		"invalid transaction",
		"custom program error",
		"error processing instruction",
		"insufficient funds",
		"blockhash not found",
		"already processed",
		"signature verification failure",
	}
	for _, m := range markers {
		if strings.Contains(msg, m) {
			return true
		}
	}
	return false
}
