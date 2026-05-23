// Package gasponsor exposes the Andromeda gas sponsor keypair and the
// signAndSend helper that makes the gateway wallet-agnostic.
//
// The gateway pays Solana fees for every challenge-based admin / recovery
// flow it controls — users never need a Solana wallet or SOL. The keypair
// is loaded from `ANDROMEDA_GAS_SPONSOR_KEYPAIR` (JSON byte array, 64 bytes,
// `solana-keygen` format).
package gasponsor

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/gagliardetto/solana-go"
	"github.com/gagliardetto/solana-go/rpc"
	"github.com/gagliardetto/solana-go/rpc/jsonrpc"
)

// SendObserver is the optional metrics hook for SignAndSend. Implemented in the
// metrics package; keeps gasponsor free of a prometheus dependency.
type SendObserver interface {
	// RecordSendUnknown counts a send that errored after the bytes may have
	// reached the chain (TxPhaseSubmittedUnknown) — needs reconciliation.
	RecordSendUnknown()
}

// Signer wraps the gas-sponsor keypair plus a Solana RPC client.
type Signer struct {
	priv      solana.PrivateKey
	publicKey solana.PublicKey
	rpc       *rpc.Client
	observer  SendObserver
}

// TxPhase classifies how far a sponsored send got before failing, so callers
// know whether the inputs are safe to roll back / reuse.
type TxPhase string

const (
	// TxPhasePreflight — the failure happened before the tx could land on-chain
	// (blockhash/build/sign failed, or the RPC rejected it at preflight without
	// broadcasting). Safe to roll back and reuse the inputs.
	TxPhasePreflight TxPhase = "preflight"
	// TxPhaseSubmittedUnknown — the send errored after the bytes may already
	// have been broadcast (transport error, deadline). The tx might have
	// landed: do NOT reuse single-use inputs (e.g. a presign); reconcile by
	// signature instead.
	TxPhaseSubmittedUnknown TxPhase = "submitted_unknown"
)

// TxSendError carries the phase of a failed SignAndSend plus the locally-signed
// transaction signature (best-effort) so a reconcile job can look it up.
type TxSendError struct {
	Phase     TxPhase
	Signature solana.Signature // locally computed at sign time; zero if we failed before signing
	Err       error
}

func (e *TxSendError) Error() string {
	return fmt.Sprintf("gasponsor send (%s): %v", e.Phase, e.Err)
}
func (e *TxSendError) Unwrap() error { return e.Err }

// SafeToRetry reports whether the inputs can be rolled back / reused. Only the
// preflight phase guarantees the transaction never landed.
func (e *TxSendError) SafeToRetry() bool { return e.Phase == TxPhasePreflight }

// classifySendError maps a SendTransactionWithOpts error to a phase. A
// structured JSON-RPC error normally means the node rejected the request before
// broadcasting (preflight simulation failed, bad params, stale blockhash) —
// safe to roll back. The exception is an "already processed" / duplicate error:
// that means the tx DID land, so it is submitted_unknown (do not reuse
// single-use inputs). Non-RPC errors (transport timeout, reset, deadline) may
// also have landed — be conservative.
func classifySendError(err error) TxPhase {
	var rpcErr *jsonrpc.RPCError
	if errors.As(err, &rpcErr) {
		msg := strings.ToLower(rpcErr.Message)
		if strings.Contains(msg, "already processed") ||
			strings.Contains(msg, "already been processed") ||
			strings.Contains(msg, "already in block") {
			return TxPhaseSubmittedUnknown
		}
		return TxPhasePreflight
	}
	return TxPhaseSubmittedUnknown
}

// New parses a JSON byte-array keypair (64 bytes: 32 secret + 32 public)
// and returns a Signer ready to sign transactions.
func New(keypairJSON string, rpcClient *rpc.Client) (*Signer, error) {
	if keypairJSON == "" {
		return nil, errors.New("ANDROMEDA_GAS_SPONSOR_KEYPAIR is empty")
	}
	if rpcClient == nil {
		return nil, errors.New("rpc client is required")
	}
	var raw []int
	if err := json.Unmarshal([]byte(keypairJSON), &raw); err != nil {
		return nil, fmt.Errorf("ANDROMEDA_GAS_SPONSOR_KEYPAIR: %w", err)
	}
	if len(raw) != 64 {
		return nil, fmt.Errorf("ANDROMEDA_GAS_SPONSOR_KEYPAIR must be 64 bytes (got %d)", len(raw))
	}
	bytes := make([]byte, 64)
	for i, v := range raw {
		if v < 0 || v > 255 {
			return nil, fmt.Errorf("ANDROMEDA_GAS_SPONSOR_KEYPAIR: byte %d out of range", i)
		}
		bytes[i] = byte(v)
	}
	priv := solana.PrivateKey(bytes)
	return &Signer{
		priv:      priv,
		publicKey: priv.PublicKey(),
		rpc:       rpcClient,
	}, nil
}

// WithObserver attaches the optional metrics hook. Returns the signer for
// chaining. Safe to skip — a nil observer just means no metric.
func (s *Signer) WithObserver(o SendObserver) *Signer {
	s.observer = o
	return s
}

// PublicKey returns the gas sponsor's public key (used as fee payer in
// every gateway-built tx).
func (s *Signer) PublicKey() solana.PublicKey {
	return s.publicKey
}

// MinHealthyBalanceLamports is the soft floor the gas sponsor must keep to
// stay healthy. 0.05 SOL covers ~10000 vote-priced txs on devnet. When the
// balance drops below this, Healthy() returns false so /readyz can surface
// the depletion before tenants hit "insufficient lamports" mid-flow.
const MinHealthyBalanceLamports = 50_000_000 // 0.05 SOL

// Balance returns the current lamport balance for the sponsor pubkey.
func (s *Signer) Balance(ctx context.Context) (uint64, error) {
	res, err := s.rpc.GetBalance(ctx, s.publicKey, rpc.CommitmentConfirmed)
	if err != nil {
		return 0, fmt.Errorf("gasponsor balance: %w", err)
	}
	return res.Value, nil
}

// Healthy reports whether the gas sponsor has enough lamports to keep
// serving (`balance >= MinHealthyBalanceLamports`). Callers use this from
// the readiness probe and metrics scraper. Network failure is treated as
// "unknown" (returns false, error) — the caller decides whether to alert.
func (s *Signer) Healthy(ctx context.Context) (bool, uint64, error) {
	bal, err := s.Balance(ctx)
	if err != nil {
		return false, 0, err
	}
	return bal >= MinHealthyBalanceLamports, bal, nil
}

// PartialSignTx fills only the gas sponsor's signature slot in `tx` and
// leaves every other signer slot zeroed. The dev's client adds remaining
// signatures (e.g. session-keys session_signer) before submitting via
// /v1/private-tx/submit. Used by the batching endpoint where the gateway
// pays gas but does not send the tx itself.
func (s *Signer) PartialSignTx(tx *solana.Transaction) error {
	if tx == nil {
		return errors.New("gasponsor.PartialSignTx: nil tx")
	}
	if _, err := tx.PartialSign(func(key solana.PublicKey) *solana.PrivateKey {
		if key.Equals(s.publicKey) {
			return &s.priv
		}
		return nil
	}); err != nil {
		return fmt.Errorf("partial-sign tx: %w", err)
	}
	return nil
}

// SignAndSend builds a v0 Solana transaction with the gas sponsor as fee
// payer, signs it, sends it via RPC, and returns `(txSignature, error)`.
//
// On failure the error is a *TxSendError carrying the phase (preflight vs
// submitted_unknown): callers that depend on rolling back / reusing single-use
// inputs must only do so when err.SafeToRetry() (i.e. preflight). In the
// submitted_unknown phase the tx may have landed — the error also carries the
// locally-signed signature for reconciliation.
func (s *Signer) SignAndSend(ctx context.Context, ixs []solana.Instruction) (solana.Signature, error) {
	if len(ixs) == 0 {
		return solana.Signature{}, &TxSendError{Phase: TxPhasePreflight, Err: errors.New("gasponsor.SignAndSend: empty instruction list")}
	}
	bh, err := s.rpc.GetLatestBlockhash(ctx, rpc.CommitmentConfirmed)
	if err != nil {
		return solana.Signature{}, &TxSendError{Phase: TxPhasePreflight, Err: fmt.Errorf("get latest blockhash: %w", err)}
	}
	tx, err := solana.NewTransaction(ixs, bh.Value.Blockhash, solana.TransactionPayer(s.publicKey))
	if err != nil {
		return solana.Signature{}, &TxSendError{Phase: TxPhasePreflight, Err: fmt.Errorf("build tx: %w", err)}
	}
	if _, err := tx.Sign(func(key solana.PublicKey) *solana.PrivateKey {
		if key.Equals(s.publicKey) {
			return &s.priv
		}
		return nil
	}); err != nil {
		return solana.Signature{}, &TxSendError{Phase: TxPhasePreflight, Err: fmt.Errorf("sign tx: %w", err)}
	}
	// The first signature slot is the fee payer's — deterministic from the
	// signed bytes, so we have it even when the send call errors.
	var localSig solana.Signature
	if len(tx.Signatures) > 0 {
		localSig = tx.Signatures[0]
	}
	sig, err := s.rpc.SendTransactionWithOpts(ctx, tx, rpc.TransactionOpts{
		SkipPreflight:       false,
		PreflightCommitment: rpc.CommitmentConfirmed,
	})
	if err != nil {
		phase := classifySendError(err)
		if phase == TxPhaseSubmittedUnknown {
			slog.Warn("gas sponsor tx submitted but status unknown — reconcile by signature",
				"signature", localSig.String(), "err", err)
			if s.observer != nil {
				s.observer.RecordSendUnknown()
			}
		}
		return solana.Signature{}, &TxSendError{Phase: phase, Signature: localSig, Err: fmt.Errorf("send tx: %w", err)}
	}
	return sig, nil
}

// ErrConfirmationTimeout signals that WaitForConfirmation gave up before the
// transaction reached the requested commitment. The tx may still confirm
// later — callers decide whether to treat it as a hard failure.
var ErrConfirmationTimeout = errors.New("transaction confirmation timed out")

// WaitForConfirmation polls GetSignatureStatuses until `sig` reaches
// `commitment` (confirmed or finalized) or `timeout` elapses. Callers use
// this between SignAndSend and any persistence step that should only happen
// after the transaction is durable (e.g. policy_subscriptions). Returns
// ErrConfirmationTimeout if the deadline trips.
//
// commitment must be rpc.CommitmentConfirmed or rpc.CommitmentFinalized.
// Other values are coerced to CommitmentConfirmed.
func (s *Signer) WaitForConfirmation(ctx context.Context, sig solana.Signature, commitment rpc.CommitmentType, timeout time.Duration) error {
	if commitment != rpc.CommitmentConfirmed && commitment != rpc.CommitmentFinalized {
		commitment = rpc.CommitmentConfirmed
	}
	deadline := time.Now().Add(timeout)
	tick := time.NewTicker(400 * time.Millisecond)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-tick.C:
		}
		res, err := s.rpc.GetSignatureStatuses(ctx, true, sig)
		if err == nil && res != nil && len(res.Value) > 0 && res.Value[0] != nil {
			st := res.Value[0]
			if st.Err != nil {
				return fmt.Errorf("transaction failed on-chain: %v", st.Err)
			}
			switch commitment {
			case rpc.CommitmentFinalized:
				if st.ConfirmationStatus == rpc.ConfirmationStatusFinalized {
					return nil
				}
			default:
				if st.ConfirmationStatus == rpc.ConfirmationStatusConfirmed ||
					st.ConfirmationStatus == rpc.ConfirmationStatusFinalized {
					return nil
				}
			}
		}
		if time.Now().After(deadline) {
			return ErrConfirmationTimeout
		}
	}
}

// ConfirmSlot polls GetSignatureStatuses until `sig` reaches confirmed (or
// finalized) commitment and returns the slot it landed in — the slot a caller
// needs for an Ika `ApprovalProof::Solana { transaction_signature, slot }`.
// Best-effort companion to SignAndSend; returns ErrConfirmationTimeout on
// deadline (callers treat the slot as unknown and let the client fetch it).
func (s *Signer) ConfirmSlot(ctx context.Context, sig solana.Signature, timeout time.Duration) (uint64, error) {
	deadline := time.Now().Add(timeout)
	tick := time.NewTicker(400 * time.Millisecond)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return 0, ctx.Err()
		case <-tick.C:
		}
		res, err := s.rpc.GetSignatureStatuses(ctx, true, sig)
		if err == nil && res != nil && len(res.Value) > 0 && res.Value[0] != nil {
			st := res.Value[0]
			if st.Err != nil {
				return 0, fmt.Errorf("transaction failed on-chain: %v", st.Err)
			}
			if st.ConfirmationStatus == rpc.ConfirmationStatusConfirmed ||
				st.ConfirmationStatus == rpc.ConfirmationStatusFinalized {
				return st.Slot, nil
			}
		}
		if time.Now().After(deadline) {
			return 0, ErrConfirmationTimeout
		}
	}
}
