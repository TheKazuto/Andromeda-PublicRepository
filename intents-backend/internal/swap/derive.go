package swap

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/gagliardetto/solana-go"
)

// DeriveResult is the re-derived signing material for an already-prepared tx.
type DeriveResult struct {
	MessageToSignHex string `json:"messageToSignHex"`
	DigestHex        string `json:"digestHex"`
	UnsignedTxHash   string `json:"unsignedTxHash"`
}

// DeriveMessage recomputes the message-to-sign + digest + snapshot hash from a
// persisted unsignedTx, WITHOUT re-quoting LI.FI. It reproduces exactly what
// prepare produced, so the gateway can re-validate the persisted snapshot
// byte-for-byte before authorizing/signing (defense against snapshot tampering).
func (s *Service) DeriveMessage(chainKind, unsignedTxB64 string) (*DeriveResult, error) {
	switch chainKind {
	case "solana":
		return deriveSolana(unsignedTxB64)
	case "evm":
		return deriveEVM(unsignedTxB64)
	default:
		return nil, invariant("unsupported chainKind %q", chainKind)
	}
}

func deriveSolana(unsignedTxB64 string) (*DeriveResult, error) {
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

func deriveEVM(unsignedTxB64 string) (*DeriveResult, error) {
	raw, err := base64.StdEncoding.DecodeString(unsignedTxB64)
	if err != nil {
		return nil, invariant("unsignedTx is not valid base64")
	}
	var snap evmTx
	if err := json.Unmarshal(raw, &snap); err != nil {
		return nil, invariant("unsignedTx snapshot is unreadable")
	}
	toBytes, err := hexAddr(snap.To)
	if err != nil {
		return nil, invariant("snapshot `to` is invalid")
	}
	value, _ := parseBig(snap.Value)
	maxFee, _ := parseBig(snap.MaxFee)
	maxPriority, _ := parseBig(snap.MaxPriorityFee)
	data, _ := hexBytes(snap.Data)
	unsigned := encodeEIP1559(snap.ChainID, snap.Nonce, maxPriority, maxFee, snap.Gas, toBytes, value, data, nil)
	sum := sha256.Sum256(raw)
	return &DeriveResult{
		MessageToSignHex: hex.EncodeToString(unsigned),
		DigestHex:        hex.EncodeToString(keccak256(unsigned)),
		UnsignedTxHash:   hex.EncodeToString(sum[:]),
	}, nil
}
