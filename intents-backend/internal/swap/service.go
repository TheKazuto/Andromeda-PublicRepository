// Package swap turns a LI.FI route into an unsigned chain transaction and,
// after the gateway returns the dWallet signature, inserts it and broadcasts.
// It never touches keys, policy or the gateway's billing — it is the pure
// "build tx / insert sig / send" layer.
//
// Family support is plugged in via ChainAdapter (see adapter.go). The Service
// keeps a per-instance registry of adapters and delegates Prepare/Derive/
// Finalize/NativeBalance to the adapter for the requested chainKind. Adding a
// new family is one file (adapter_<family>.go) registered in NewService.
package swap

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"

	"github.com/shinkalabs/andromeda-intents/internal/chains"
	"github.com/shinkalabs/andromeda-intents/internal/lifi"
	"github.com/shinkalabs/andromeda-intents/internal/metrics"
)

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
	lifi     *lifi.Client
	metrics  *metrics.Metrics
	logger   *slog.Logger
	adapters *registry

	// evm is kept as a direct field because EVMReceipt is exposed as an
	// EVM-specific HTTP endpoint (/evm/receipt) — Solana has no analog and
	// the operation does not fit the ChainAdapter contract.
	evmAdapter *evmAdapter
}

// Options wires the swap dependencies. The RPC overrides take priority over the
// public RPCs LI.FI publishes in /chains.
type Options struct {
	Lifi              *lifi.Client
	Solana            *chains.SolanaBroadcaster
	EVM               *chains.EVMBroadcaster
	Sui               *chains.SuiBroadcaster
	SolanaRPCOverride string
	EVMOverrides      map[int]string
	SuiRPCOverride    string
	Metrics           *metrics.Metrics
	Logger            *slog.Logger
}

func NewService(o Options) *Service {
	r := newRegistry()
	sol := newSolanaAdapter(o.Solana, o.Lifi, o.SolanaRPCOverride)
	evm := newEVMAdapter(o.EVM, o.Lifi, o.EVMOverrides)
	r.register(sol)
	r.register(evm)
	if o.Sui != nil {
		r.register(newSuiAdapter(o.Sui, o.Lifi, o.SuiRPCOverride))
	}
	return &Service{
		lifi:       o.Lifi,
		metrics:    o.Metrics,
		logger:     o.Logger,
		adapters:   r,
		evmAdapter: evm,
	}
}

// RegisteredKinds returns the chainKinds the Service can serve. Used by the
// DTO validator and by /v1/intents/capabilities so the public surface always
// matches the actual code.
func (s *Service) RegisteredKinds() []string {
	return s.adapters.keys()
}

// IsKindRegistered reports whether a chainKind has a registered adapter.
// Constant-time check used by the API handler to reject unsupported kinds
// before any RPC or business logic runs.
func (s *Service) IsKindRegistered(kind string) bool {
	_, ok := s.adapters.get(kind)
	return ok
}

// PrepareInput is the swap-prepare request.
type PrepareInput struct {
	Params    lifi.QuoteParams
	ChainKind string // any registered adapter key
}

// PrepareResult is everything the gateway needs to persist the intent, derive
// the sign material via ika prepare-message, authorize via PolicyEngine, and
// later finalize. No key material, no digest (the gateway derives those).
type PrepareResult struct {
	ChainKind          string `json:"chainKind"`
	ChainID            int    `json:"chainId"`            // numeric LI.FI id (broadcast RPC key)
	SignChainID        string `json:"signChainId"`        // CAIP-2 for prepare-message
	SignScheme         int    `json:"signScheme"`         // 5 Solana, 0 EVM, ...
	ChainNativeAddress string `json:"chainNativeAddress"` // dWallet address on the chain (== fee payer)

	// UnsignedTxB64 is the full LI.FI transaction snapshot, re-serialized
	// canonically. The gateway persists it and returns it verbatim at finalize.
	UnsignedTxB64 string `json:"unsignedTxB64"`
	// MessageToSignHex is the exact bytes the gateway feeds to ika
	// prepare-message as payloadHex. For families without an envelope (EVM,
	// Solana) ika's preprocessedHex comes back EQUAL to this. For families
	// with an envelope (Sui: blake2b(intent || txBytes); Bitcoin: BIP143
	// sighash; …) ika applies the envelope itself — preprocessedHex differs,
	// and the drift check is performed on MessageDigestHex instead.
	MessageToSignHex string `json:"messageToSignHex"`
	// MessageDigestHex is the keccak256 the gateway cross-checks against ika's
	// returned digestHex. Populated by EVERY adapter — the canonical value the
	// MessageApproval PDA is keyed by (see ika-backend chain/digest.ts).
	// This is the single drift-check anchor: a mismatch here means the
	// intents-backend and ika-backend disagree on what is being signed.
	MessageDigestHex string `json:"messageDigestHex"`
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

// DeriveResult is the re-derived signing material for an already-prepared tx.
type DeriveResult struct {
	MessageToSignHex string `json:"messageToSignHex"`
	DigestHex        string `json:"digestHex"`
	UnsignedTxHash   string `json:"unsignedTxHash"`
}

// Prepare fetches the LI.FI route and builds the unsigned tx + the bytes
// the gateway must authorize/sign. Read-only against keys and policy. Same-chain
// (fromChain == toChain) and cross-chain (bridge) both flow here: LI.FI returns
// a SOURCE-chain tx in either case; we sign + broadcast it on the source chain
// and the bridge delivers to the destination.
func (s *Service) Prepare(ctx context.Context, in PrepareInput) (*PrepareResult, error) {
	adapter, err := s.pickAdapter(in.ChainKind)
	if err != nil {
		return nil, err
	}
	step, err := s.lifi.Quote(ctx, in.Params)
	if err != nil {
		return nil, err
	}
	return adapter.Prepare(ctx, step, in.Params)
}

// DeriveMessage recomputes the message-to-sign + digest + snapshot hash from a
// persisted unsignedTx, WITHOUT re-quoting LI.FI. It reproduces exactly what
// prepare produced, so the gateway can re-validate the persisted snapshot
// byte-for-byte before authorizing/signing (defense against snapshot tampering).
func (s *Service) DeriveMessage(chainKind, unsignedTxB64 string) (*DeriveResult, error) {
	adapter, err := s.pickAdapter(chainKind)
	if err != nil {
		return nil, err
	}
	return adapter.DeriveMessage(unsignedTxB64)
}

// Finalize inserts the dWallet signature into the prepared tx and broadcasts it.
func (s *Service) Finalize(ctx context.Context, in FinalizeInput) (*FinalizeResult, error) {
	adapter, err := s.pickAdapter(in.ChainKind)
	if err != nil {
		return nil, err
	}
	urls := adapter.ResolveRPCs(in.ChainID)
	if len(urls) == 0 {
		return nil, fmt.Errorf("no RPC available for chain %d (kind=%s) — set an override or wait for the /chains cache to load", in.ChainID, in.ChainKind)
	}
	return adapter.Finalize(ctx, in, urls)
}

// NativeBalance returns the dWallet's native-token balance on a chain, in base
// units (lamports / wei / sun / …) as a decimal string.
func (s *Service) NativeBalance(ctx context.Context, chainKind string, chainID int, address string) (string, error) {
	adapter, err := s.pickAdapter(chainKind)
	if err != nil {
		return "", err
	}
	urls := adapter.ResolveRPCs(chainID)
	if len(urls) == 0 {
		return "", fmt.Errorf("no RPC available for chain %d (kind=%s)", chainID, chainKind)
	}
	return adapter.NativeBalance(ctx, urls, address)
}

// EVMReceipt reports whether an EVM tx is mined (found) and succeeded. Used by
// the gateway to gate the swap on the ERC20 approve confirming. EVM-only — see
// the EVMReceiptReader interface comment.
func (s *Service) EVMReceipt(ctx context.Context, chainID int, txHash string) (bool, bool, error) {
	return s.evmAdapter.Receipt(ctx, chainID, txHash)
}
