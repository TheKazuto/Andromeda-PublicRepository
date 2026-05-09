package policies

import (
	"context"
	"encoding/base64"
	"fmt"

	"github.com/gagliardetto/solana-go"
	"github.com/gagliardetto/solana-go/rpc"
)

// BuildUnsignedTx wraps the provided instruction(s) into a v0 Solana
// transaction with a recent blockhash and returns the serialized message
// as base64. The client signs locally and submits via the gateway's
// /v1/private-tx/submit (custody-free).
func BuildUnsignedTx(ctx context.Context, rpcClient *rpc.Client, payer solana.PublicKey, ixs []solana.Instruction) (string, error) {
	resp, err := rpcClient.GetLatestBlockhash(ctx, rpc.CommitmentConfirmed)
	if err != nil {
		return "", fmt.Errorf("get latest blockhash: %w", err)
	}
	tx, err := solana.NewTransaction(ixs, resp.Value.Blockhash, solana.TransactionPayer(payer))
	if err != nil {
		return "", fmt.Errorf("build tx: %w", err)
	}
	msgBytes, err := tx.Message.MarshalBinary()
	if err != nil {
		return "", fmt.Errorf("marshal message: %w", err)
	}
	return base64.StdEncoding.EncodeToString(msgBytes), nil
}
