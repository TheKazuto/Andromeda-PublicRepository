package swap

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"

	"github.com/gagliardetto/solana-go"

	"github.com/shinkalabs/andromeda-intents/internal/chains"
	"github.com/shinkalabs/andromeda-intents/internal/lifi"
)

// solanaCAIP2 is the CAIP-2 id the gateway forwards to ika-backend
// prepare-message. Only the namespace ("solana") matters there — Solana applies
// no signing envelope and the approval digest is keccak256 regardless — so the
// mainnet genesis reference is a stable, correct value across clusters.
const solanaCAIP2 = "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp"

// solanaSignScheme is EddsaSha512 (Ed25519). Matches ika-backend chains.ts.
const solanaSignScheme = 5

// solanaAdapter is the ChainAdapter for Solana same-chain swaps (Jupiter
// routes via LI.FI). Same-chain only on Solana: the source dWallet is the
// fee payer and the only required signer.
type solanaAdapter struct {
	broadcaster *chains.SolanaBroadcaster
	lifi        *lifi.Client // RPC cache (LI.FI /chains)
	rpcOverride string       // env override (SOLANA_RPC_URL)
}

func newSolanaAdapter(b *chains.SolanaBroadcaster, l *lifi.Client, override string) *solanaAdapter {
	return &solanaAdapter{broadcaster: b, lifi: l, rpcOverride: override}
}

func (a *solanaAdapter) Key() string     { return "solana" }
func (a *solanaAdapter) SignScheme() int { return solanaSignScheme }

func (a *solanaAdapter) ResolveRPCs(chainID int) []string {
	if a.rpcOverride != "" {
		return []string{a.rpcOverride}
	}
	if a.lifi == nil {
		return nil
	}
	return a.lifi.RPC().RPCsFor(chainID)
}

// txRequestSolana is the LI.FI transactionRequest shape for Solana: `data` is a
// base64-serialized VersionedTransaction with the dWallet as fee payer + signer.
type txRequestSolana struct {
	Data string `json:"data"`
}

// Prepare validates the LI.FI Solana tx and extracts the message to sign.
// It enforces the safety invariants (fee payer == dWallet, no foreign required
// signer) before anything is persisted or signed.
func (a *solanaAdapter) Prepare(_ context.Context, step *lifi.Step, p lifi.QuoteParams) (*PrepareResult, error) {
	if len(step.TransactionRequest) == 0 {
		return nil, invariant("LI.FI returned no transactionRequest for the route")
	}
	var tr txRequestSolana
	if err := json.Unmarshal(step.TransactionRequest, &tr); err != nil || tr.Data == "" {
		return nil, invariant("LI.FI Solana transactionRequest has no data field")
	}
	raw, err := base64.StdEncoding.DecodeString(tr.Data)
	if err != nil {
		return nil, invariant("LI.FI Solana tx is not valid base64")
	}
	tx, err := solana.TransactionFromBytes(raw)
	if err != nil {
		return nil, invariant("LI.FI Solana tx failed to deserialize: %v", err)
	}

	keys := tx.Message.AccountKeys
	if len(keys) == 0 {
		return nil, invariant("Solana tx has no account keys")
	}
	numSigners := int(tx.Message.Header.NumRequiredSignatures)
	if numSigners < 1 {
		return nil, invariant("Solana tx requires no signers")
	}
	if numSigners > len(keys) {
		return nil, invariant("Solana tx header is inconsistent with account keys")
	}

	feePayer := keys[0]
	if feePayer.String() != p.FromAddress {
		return nil, invariant("Solana fee payer (%s) is not the dWallet (%s)", feePayer.String(), p.FromAddress)
	}
	// Same-chain MVP: the dWallet must be the ONLY required signer. A foreign
	// required signer means the route needs a third party we cannot satisfy
	// custody-free — reject rather than sign something we can't complete.
	for i := 0; i < numSigners; i++ {
		if keys[i].String() != p.FromAddress {
			return nil, invariant("Solana tx has an unexpected required signer at index %d", i)
		}
	}

	msgBytes, err := tx.Message.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("serialize solana message: %w", err)
	}

	sum := sha256.Sum256(raw)
	est := step.Estimate
	return &PrepareResult{
		ChainKind:           "solana",
		ChainID:             step.Action.FromChainID,
		SignChainID:         solanaCAIP2,
		SignScheme:          solanaSignScheme,
		ChainNativeAddress:  feePayer.String(),
		UnsignedTxB64:       tr.Data,
		MessageToSignHex:    hex.EncodeToString(msgBytes),
		MessageDigestHex:    hex.EncodeToString(keccak256(msgBytes)),
		UnsignedTxHash:      hex.EncodeToString(sum[:]),
		AmountOut:           est.ToAmount,
		AmountOutMin:        est.ToAmountMin,
		TransactionFeeUSD:   est.TransactionFeeUSD(),
		NativeFeeEstimate:   est.NativeFeeEstimate(),
		NativeFeeUSD:        est.NativeFeeUSD(),
		RequiresAtaCreation: est.RequiresAtaCreation(),
		Tool:                step.Tool,
		RouteSnapshot:       routeSnapshot(step),
		Notice:              "pre-alpha on Solana devnet — not for real value",
	}, nil
}

// DeriveMessage recomputes the message-to-sign + digest + snapshot hash from a
// persisted Solana unsignedTx, WITHOUT re-quoting LI.FI.
func (a *solanaAdapter) DeriveMessage(unsignedTxB64 string) (*DeriveResult, error) {
	raw, err := base64.StdEncoding.DecodeString(unsignedTxB64)
	if err != nil {
		return nil, invariant("unsignedTx is not valid base64")
	}
	tx, err := solana.TransactionFromBytes(raw)
	if err != nil {
		return nil, invariant("unsignedTx failed to deserialize: %v", err)
	}
	msg, err := tx.Message.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("serialize solana message: %w", err)
	}
	sum := sha256.Sum256(raw)
	return &DeriveResult{
		MessageToSignHex: hex.EncodeToString(msg),
		DigestHex:        hex.EncodeToString(keccak256(msg)),
		UnsignedTxHash:   hex.EncodeToString(sum[:]),
	}, nil
}

// Finalize inserts the Ed25519 signature at the fee-payer slot and
// broadcasts. The signed message must be byte-identical to MessageToSignHex from
// prepare, which holds because we re-deserialize the same persisted snapshot.
func (a *solanaAdapter) Finalize(ctx context.Context, in FinalizeInput, urls []string) (*FinalizeResult, error) {
	raw, err := base64.StdEncoding.DecodeString(in.UnsignedTxB64)
	if err != nil {
		return nil, invariant("unsignedTx is not valid base64")
	}
	tx, err := solana.TransactionFromBytes(raw)
	if err != nil {
		return nil, invariant("unsignedTx failed to deserialize: %v", err)
	}

	signerBytes, err := hex.DecodeString(in.SignerPubkeyHex)
	if err != nil || len(signerBytes) != 32 {
		return nil, invariant("signerPubkeyHex must be 32-byte hex")
	}
	var signer solana.PublicKey
	copy(signer[:], signerBytes)

	numSigners := int(tx.Message.Header.NumRequiredSignatures)
	idx := -1
	for i := 0; i < numSigners && i < len(tx.Message.AccountKeys); i++ {
		if tx.Message.AccountKeys[i].Equals(signer) {
			idx = i
			break
		}
	}
	if idx < 0 {
		return nil, invariant("signer pubkey is not a required signer of the tx")
	}

	sigBytes, err := base64.StdEncoding.DecodeString(in.SignatureB64)
	if err != nil || len(sigBytes) != 64 {
		return nil, invariant("signature must be base64-encoded 64 bytes")
	}
	var sig solana.Signature
	copy(sig[:], sigBytes)

	// Ensure the signatures slice has one slot per required signer.
	if len(tx.Signatures) < numSigners {
		grown := make([]solana.Signature, numSigners)
		copy(grown, tx.Signatures)
		tx.Signatures = grown
	}
	tx.Signatures[idx] = sig

	// For Solana the txid IS the fee payer's signature (account index 0, which
	// we just set). Computing it up front means even an ambiguous broadcast
	// returns a hash the gateway can reconcile against — never a blind retry.
	expectedTxID := tx.Signatures[0].String()

	hash, unknown, err := a.broadcaster.Broadcast(ctx, urls, tx, in.ChainID)
	if err != nil {
		if unknown {
			return &FinalizeResult{TxHash: expectedTxID, BroadcastUnknown: true}, nil
		}
		return nil, fmt.Errorf("broadcast failed: %w", err)
	}
	if hash == "" {
		hash = expectedTxID
	}
	return &FinalizeResult{TxHash: hash}, nil
}

// NativeBalance returns the SOL balance (lamports) of the dWallet as a decimal
// string.
func (a *solanaAdapter) NativeBalance(ctx context.Context, urls []string, address string) (string, error) {
	lamports, err := a.broadcaster.Balance(ctx, urls, address)
	if err != nil {
		return "", err
	}
	return strconv.FormatUint(lamports, 10), nil
}

// routeSnapshot keeps a compact, audit-friendly copy of the LI.FI route. Shared
// helper (used by every adapter's Prepare).
func routeSnapshot(step *lifi.Step) json.RawMessage {
	snap := map[string]any{
		"tool":        step.Tool,
		"type":        step.Type,
		"fromChainId": step.Action.FromChainID,
		"toChainId":   step.Action.ToChainID,
		"fromToken":   step.Action.FromToken.Address,
		"toToken":     step.Action.ToToken.Address,
		"fromAmount":  step.Estimate.FromAmount,
		"toAmount":    step.Estimate.ToAmount,
		"toAmountMin": step.Estimate.ToAmountMin,
		"slippage":    step.Action.Slippage,
	}
	b, err := json.Marshal(snap)
	if err != nil {
		return json.RawMessage(`{}`)
	}
	return json.RawMessage(b)
}
