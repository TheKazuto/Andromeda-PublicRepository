package swap

import (
	"context"
	"fmt"
)

// Finalize inserts the dWallet signature into the prepared tx and broadcasts it.
func (s *Service) Finalize(ctx context.Context, in FinalizeInput) (*FinalizeResult, error) {
	switch in.ChainKind {
	case "solana":
		urls := s.resolveSolanaRPCs(in.ChainID)
		if len(urls) == 0 {
			return nil, fmt.Errorf("no Solana RPC available for chain %d — set SOLANA_RPC_URL or wait for the /chains cache to load", in.ChainID)
		}
		return s.solanaFinalize(ctx, in, urls)
	case "evm":
		urls := s.resolveEVMRPCs(in.ChainID)
		if len(urls) == 0 {
			return nil, fmt.Errorf("no EVM RPC available for chain %d — set EVM_RPC_URLS_JSON or wait for the /chains cache to load", in.ChainID)
		}
		return s.evmFinalize(ctx, in, urls)
	default:
		return nil, invariant("unsupported chainKind %q (supported: solana, evm)", in.ChainKind)
	}
}
