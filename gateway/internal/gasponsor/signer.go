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
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/gagliardetto/solana-go"
	"github.com/gagliardetto/solana-go/rpc"
)

// Signer wraps the gas-sponsor keypair plus a Solana RPC client.
type Signer struct {
	priv      solana.PrivateKey
	publicKey solana.PublicKey
	rpc       *rpc.Client
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

// PublicKey returns the gas sponsor's public key (used as fee payer in
// every gateway-built tx).
func (s *Signer) PublicKey() solana.PublicKey {
	return s.publicKey
}

// SignAndSend builds a v0 Solana transaction with the gas sponsor as fee
// payer, signs it, sends it via RPC, and returns `(txSignature, error)`.
func (s *Signer) SignAndSend(ctx context.Context, ixs []solana.Instruction) (solana.Signature, error) {
	if len(ixs) == 0 {
		return solana.Signature{}, errors.New("gasponsor.SignAndSend: empty instruction list")
	}
	bh, err := s.rpc.GetLatestBlockhash(ctx, rpc.CommitmentConfirmed)
	if err != nil {
		return solana.Signature{}, fmt.Errorf("get latest blockhash: %w", err)
	}
	tx, err := solana.NewTransaction(ixs, bh.Value.Blockhash, solana.TransactionPayer(s.publicKey))
	if err != nil {
		return solana.Signature{}, fmt.Errorf("build tx: %w", err)
	}
	if _, err := tx.Sign(func(key solana.PublicKey) *solana.PrivateKey {
		if key.Equals(s.publicKey) {
			return &s.priv
		}
		return nil
	}); err != nil {
		return solana.Signature{}, fmt.Errorf("sign tx: %w", err)
	}
	sig, err := s.rpc.SendTransactionWithOpts(ctx, tx, rpc.TransactionOpts{
		SkipPreflight:       false,
		PreflightCommitment: rpc.CommitmentConfirmed,
	})
	if err != nil {
		return solana.Signature{}, fmt.Errorf("send tx: %w", err)
	}
	return sig, nil
}

// SignAndSendWithExtraSigners is the variant used when the transaction needs
// additional signers besides the gas sponsor — e.g. session-keys'
// `request_signature_via_session` where the session keypair (NOT the user
// wallet, but a dev-app keypair) co-signs. `extra` keys are looked up by
// pubkey when assembling signatures; pass them ordered to be defensive.
func (s *Signer) SignAndSendWithExtraSigners(
	ctx context.Context,
	ixs []solana.Instruction,
	extra []solana.PrivateKey,
) (solana.Signature, error) {
	if len(ixs) == 0 {
		return solana.Signature{}, errors.New("gasponsor.SignAndSendWithExtraSigners: empty instruction list")
	}
	bh, err := s.rpc.GetLatestBlockhash(ctx, rpc.CommitmentConfirmed)
	if err != nil {
		return solana.Signature{}, fmt.Errorf("get latest blockhash: %w", err)
	}
	tx, err := solana.NewTransaction(ixs, bh.Value.Blockhash, solana.TransactionPayer(s.publicKey))
	if err != nil {
		return solana.Signature{}, fmt.Errorf("build tx: %w", err)
	}
	if _, err := tx.Sign(func(key solana.PublicKey) *solana.PrivateKey {
		if key.Equals(s.publicKey) {
			return &s.priv
		}
		for i := range extra {
			if extra[i].PublicKey().Equals(key) {
				return &extra[i]
			}
		}
		return nil
	}); err != nil {
		return solana.Signature{}, fmt.Errorf("sign tx: %w", err)
	}
	sig, err := s.rpc.SendTransactionWithOpts(ctx, tx, rpc.TransactionOpts{
		SkipPreflight:       false,
		PreflightCommitment: rpc.CommitmentConfirmed,
	})
	if err != nil {
		return solana.Signature{}, fmt.Errorf("send tx: %w", err)
	}
	return sig, nil
}

// DecodeBase64Signature is a small helper for tests.
func DecodeBase64Signature(s string) (solana.Signature, error) {
	raw, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return solana.Signature{}, err
	}
	if len(raw) != 64 {
		return solana.Signature{}, errors.New("signature must be 64 bytes")
	}
	var out solana.Signature
	copy(out[:], raw)
	return out, nil
}
