// Package swap turns a LI.FI route into an unsigned chain transaction and,
// after the gateway returns the dWallet signature, inserts it and broadcasts.
// It never touches keys, policy or the gateway's billing — it is the pure
// "build tx / insert sig / send" layer. Covers Solana + EVM, same-chain and
// cross-chain (bridge).
package swap

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strconv"

	"github.com/shinkalabs/andromeda-intents/internal/chains"
	"github.com/shinkalabs/andromeda-intents/internal/lifi"
	"github.com/shinkalabs/andromeda-intents/internal/metrics"
)

// NativeBalance returns the dWallet's native-token balance on a chain, in base
// units (lamports / wei) as a decimal string. Used by the gateway to pre-check
// that the dWallet can pay the swap gas before broadcasting.
func (s *Service) NativeBalance(ctx context.Context, chainKind string, chainID int, address string) (string, error) {
	switch chainKind {
	case "solana":
		urls := s.resolveSolanaRPCs(chainID)
		if len(urls) == 0 {
			return "", fmt.Errorf("no Solana RPC available for chain %d", chainID)
		}
		lamports, err := s.solana.Balance(ctx, urls, address)
		if err != nil {
			return "", err
		}
		return strconv.FormatUint(lamports, 10), nil
	case "evm":
		urls := s.resolveEVMRPCs(chainID)
		if len(urls) == 0 {
			return "", fmt.Errorf("no EVM RPC available for chain %d", chainID)
		}
		wei, err := s.evm.Balance(ctx, urls, address)
		if err != nil {
			return "", err
		}
		return wei.String(), nil
	default:
		return "", fmt.Errorf("unsupported chainKind %q", chainKind)
	}
}

// solanaCAIP2 is the CAIP-2 id the gateway forwards to ika-backend
// prepare-message. Only the namespace ("solana") matters there — Solana applies
// no signing envelope and the approval digest is keccak256 regardless — so the
// mainnet genesis reference is a stable, correct value across clusters.
const solanaCAIP2 = "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp"

// solanaSignScheme is EddsaSha512 (Ed25519). Matches ika-backend chains.ts.
const solanaSignScheme = 5

// InvariantError marks a safety check that failed on the LI.FI tx (wrong fee
// payer, unexpected signer, cross-chain route, …). The handler maps it to 422
// so the caller fixes inputs rather than retrying blindly.
type InvariantError struct{ Msg string }

func (e *InvariantError) Error() string { return e.Msg }

func invariant(format string, args ...any) error {
	return &InvariantError{Msg: fmt.Sprintf(format, args...)}
}

// Service is the swap builder/broadcaster.
type Service struct {
	lifi              *lifi.Client
	solana            *chains.SolanaBroadcaster
	evm               *chains.EVMBroadcaster
	solanaRPCOverride string
	evmOverrides      map[int]string // chainId → RPC URL override
	metrics           *metrics.Metrics
	logger            *slog.Logger
}

// Options wires the swap dependencies. The RPC overrides take priority over the
// public RPCs LI.FI publishes in /chains.
type Options struct {
	Lifi              *lifi.Client
	Solana            *chains.SolanaBroadcaster
	EVM               *chains.EVMBroadcaster
	SolanaRPCOverride string
	EVMOverrides      map[int]string
	Metrics           *metrics.Metrics
	Logger            *slog.Logger
}

func NewService(o Options) *Service {
	return &Service{
		lifi: o.Lifi, solana: o.Solana, evm: o.EVM,
		solanaRPCOverride: o.SolanaRPCOverride, evmOverrides: o.EVMOverrides,
		metrics: o.Metrics, logger: o.Logger,
	}
}

// resolveSolanaRPCs returns the broadcast endpoints for a Solana chain id:
// the operator override first, then the cached public RPCs from LI.FI /chains.
func (s *Service) resolveSolanaRPCs(chainID int) []string {
	if s.solanaRPCOverride != "" {
		return []string{s.solanaRPCOverride}
	}
	return s.lifi.RPC().RPCsFor(chainID)
}

// resolveEVMRPCs returns the endpoints for an EVM chainId: the per-chain operator
// override first, then the cached public RPCs from LI.FI /chains.
func (s *Service) resolveEVMRPCs(chainID int) []string {
	if url, ok := s.evmOverrides[chainID]; ok && url != "" {
		return []string{url}
	}
	return s.lifi.RPC().RPCsFor(chainID)
}

// PrepareInput is the swap-prepare request.
type PrepareInput struct {
	Params    lifi.QuoteParams
	ChainKind string // "solana" (MVP)
}

// PrepareResult is everything the gateway needs to persist the intent, derive
// the sign material via ika prepare-message, authorize via PolicyEngine, and
// later finalize. No key material, no digest (the gateway derives those).
type PrepareResult struct {
	ChainKind          string `json:"chainKind"`
	ChainID            int    `json:"chainId"`            // numeric LI.FI id (broadcast RPC key)
	SignChainID        string `json:"signChainId"`        // CAIP-2 for prepare-message
	SignScheme         int    `json:"signScheme"`         // 5 for Solana
	ChainNativeAddress string `json:"chainNativeAddress"` // dWallet address on the chain (== fee payer)

	// UnsignedTxB64 is the full LI.FI transaction snapshot, re-serialized
	// canonically. The gateway persists it and returns it verbatim at finalize.
	UnsignedTxB64 string `json:"unsignedTxB64"`
	// MessageToSignHex is the exact bytes the gateway feeds to ika
	// prepare-message as payloadHex (the Solana message). preprocessedHex comes
	// back equal to this; digestHex = keccak256(this).
	MessageToSignHex string `json:"messageToSignHex"`
	// UnsignedTxHash is sha256(UnsignedTxB64 bytes) for snapshot integrity.
	UnsignedTxHash string `json:"unsignedTxHash"`

	AmountOut           string          `json:"amountOut"`
	AmountOutMin        string          `json:"amountOutMin"`
	TransactionFeeUSD   string          `json:"transactionFeeUsd"`
	NativeFeeEstimate   string          `json:"nativeFeeEstimate"`
	NativeFeeUSD        string          `json:"nativeFeeUsd,omitempty"`
	RequiresAtaCreation bool            `json:"requiresAtaCreation"`
	Tool                string          `json:"tool"`
	RouteSnapshot       json.RawMessage `json:"routeSnapshot"`
	Notice              string          `json:"notice"`

	// EVMNonce is the nonce assigned to the swap tx (EVM only). The gateway
	// persists it and enforces a single in-flight EVM swap per (dwallet, chain)
	// so the pending-nonce assignment never collides.
	EVMNonce uint64 `json:"evmNonce,omitempty"`
	// Approval, when set (EVM only), is an ERC20 approve tx that must be signed
	// and broadcast (and confirmed) BEFORE the swap. It uses the nonce just below
	// the swap's. The gateway derives its digest via prepare-message and runs the
	// same authorize→sign→broadcast cycle the swap uses.
	Approval *EVMApproval `json:"approval,omitempty"`
}

// FinalizeInput inserts the signature and broadcasts.
type FinalizeInput struct {
	ChainKind       string
	UnsignedTxB64   string
	SignatureB64    string
	SignerPubkeyHex string
	ChainID         int
}

// FinalizeResult reports the broadcast outcome. BroadcastUnknown is set when the
// RPC errored after the tx may already have been accepted — the gateway must
// reconcile (never blind-retry).
type FinalizeResult struct {
	TxHash           string `json:"txHash,omitempty"`
	BroadcastUnknown bool   `json:"broadcastUnknown"`
}
