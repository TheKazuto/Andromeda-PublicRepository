// Package chains holds the per-chain broadcast clients. MVP: Solana.
package chains

import (
	"context"
	"log/slog"
	"strconv"
	"strings"
	"time"

	"github.com/gagliardetto/solana-go"
	"github.com/gagliardetto/solana-go/rpc"

	"github.com/shinkalabs/andromeda-intents/internal/metrics"
)

// SolanaBroadcaster sends a signed VersionedTransaction, failing over across the
// RPC URLs the caller resolved (operator override, else the public list from
// LI.FI /chains). It never holds keys — it only relays bytes.
type SolanaBroadcaster struct {
	metrics *metrics.Metrics
	logger  *slog.Logger
}

func NewSolanaBroadcaster(m *metrics.Metrics, logger *slog.Logger) *SolanaBroadcaster {
	return &SolanaBroadcaster{metrics: m, logger: logger}
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
		client := rpc.New(url)
		start := time.Now()
		sig, err := client.SendTransactionWithOpts(ctx, tx, opts)
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
		client := rpc.New(url)
		out, err := client.GetBalance(ctx, pk, rpc.CommitmentConfirmed)
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
