package swap

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/gagliardetto/solana-go"

	"github.com/shinkalabs/andromeda-intents/internal/lifi"
)

// txRequestSolana is the LI.FI transactionRequest shape for Solana: `data` is a
// base64-serialized VersionedTransaction with the dWallet as fee payer + signer.
type txRequestSolana struct {
	Data string `json:"data"`
}

// solanaPrepare validates the LI.FI Solana tx and extracts the message to sign.
// It enforces the safety invariants (fee payer == dWallet, no foreign required
// signer) before anything is persisted or signed.
func (s *Service) solanaPrepare(step *lifi.Step, p lifi.PrepareInputParams) (*PrepareResult, error) {
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

// solanaFinalize inserts the Ed25519 signature at the fee-payer slot and
// broadcasts. The signed message must be byte-identical to MessageToSignHex from
// prepare, which holds because we re-deserialize the same persisted snapshot.
func (s *Service) solanaFinalize(ctx context.Context, in FinalizeInput, urls []string) (*FinalizeResult, error) {
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

	hash, unknown, err := s.solana.Broadcast(ctx, urls, tx, in.ChainID)
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

// routeSnapshot keeps a compact, audit-friendly copy of the LI.FI route.
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
