package policies

import (
	"context"
	"encoding/base64"
	"fmt"

	"github.com/gagliardetto/solana-go"
	"github.com/gagliardetto/solana-go/rpc"
)

// BuildUnsignedTx wraps the provided instruction(s) into a legacy Solana
// transaction with a recent blockhash, an empty signature slot for the
// payer, and returns the FULL serialized transaction as base64. The client
// signs locally and submits via the gateway's /v1/private-tx/submit
// (custody-free).
//
// The unsigned transaction format is what every other endpoint in this
// package returns (see batch.go), so SDKs and Postman recipes can use a
// single deserialiser for all `unsigned_tx_base64` payloads. Earlier
// versions returned the serialized MESSAGE only — that drift was fixed in
// 2026-05 and there is no compatibility shim (pre-alpha, B2D, single field
// name across all endpoints).
func BuildUnsignedTx(ctx context.Context, rpcClient *rpc.Client, payer solana.PublicKey, ixs []solana.Instruction) (string, error) {
	resp, err := rpcClient.GetLatestBlockhash(ctx, rpc.CommitmentConfirmed)
	if err != nil {
		return "", fmt.Errorf("get latest blockhash: %w", err)
	}
	tx, err := solana.NewTransaction(ixs, resp.Value.Blockhash, solana.TransactionPayer(payer))
	if err != nil {
		return "", fmt.Errorf("build tx: %w", err)
	}
	raw, err := tx.MarshalBinary()
	if err != nil {
		return "", fmt.Errorf("marshal tx: %w", err)
	}
	return base64.StdEncoding.EncodeToString(raw), nil
}
