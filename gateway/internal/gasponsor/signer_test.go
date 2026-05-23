package gasponsor

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/gagliardetto/solana-go/rpc/jsonrpc"
)

func TestClassifySendError(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want TxPhase
	}{
		{
			name: "structured RPC error → preflight (rejected, not broadcast)",
			err:  &jsonrpc.RPCError{Code: -32002, Message: "Transaction simulation failed"},
			want: TxPhasePreflight,
		},
		{
			name: "wrapped RPC error → preflight",
			err:  fmt.Errorf("send tx: %w", &jsonrpc.RPCError{Code: -32602, Message: "invalid params"}),
			want: TxPhasePreflight,
		},
		{
			name: "already-processed RPC error → submitted_unknown (tx landed)",
			err:  &jsonrpc.RPCError{Code: -32002, Message: "Transaction simulation failed: This transaction has already been processed"},
			want: TxPhaseSubmittedUnknown,
		},
		{
			name: "transport error → submitted_unknown (may have landed)",
			err:  errors.New("Post \"https://rpc\": context deadline exceeded"),
			want: TxPhaseSubmittedUnknown,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := classifySendError(tt.err); got != tt.want {
				t.Fatalf("classifySendError = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestTxSendError_SafeToRetry(t *testing.T) {
	if !(&TxSendError{Phase: TxPhasePreflight}).SafeToRetry() {
		t.Fatal("preflight must be SafeToRetry")
	}
	if (&TxSendError{Phase: TxPhaseSubmittedUnknown}).SafeToRetry() {
		t.Fatal("submitted_unknown must NOT be SafeToRetry")
	}
}

func TestTxSendError_UnwrapAndError(t *testing.T) {
	inner := errors.New("boom")
	te := &TxSendError{Phase: TxPhasePreflight, Err: inner}
	if !errors.Is(te, inner) {
		t.Fatal("TxSendError must unwrap to its inner error")
	}
	var asTe *TxSendError
	if !errors.As(error(te), &asTe) {
		t.Fatal("errors.As must recover *TxSendError")
	}
}

func TestSignAndSend_EmptyInstructionsIsPreflight(t *testing.T) {
	s := &Signer{}
	_, err := s.SignAndSend(context.Background(), nil)
	var te *TxSendError
	if !errors.As(err, &te) {
		t.Fatalf("want *TxSendError, got %T", err)
	}
	if te.Phase != TxPhasePreflight {
		t.Fatalf("empty ixs phase = %q, want preflight", te.Phase)
	}
}
