package swap

import "context"

// Prepare fetches the LI.FI route and builds the unsigned chain tx + the bytes
// the gateway must authorize/sign. Read-only against keys and policy.
func (s *Service) Prepare(ctx context.Context, in PrepareInput) (*PrepareResult, error) {
	step, err := s.lifi.Quote(ctx, in.Params)
	if err != nil {
		return nil, err
	}
	// Same-chain (fromChain == toChain) and cross-chain (bridge) both flow here:
	// LI.FI returns a SOURCE-chain tx in either case; we sign + broadcast it on
	// the source chain and the bridge delivers to the destination. The status
	// reconciliation (LI.FI /status with fromChain+toChain) tracks the bridge.
	switch in.ChainKind {
	case "solana":
		return s.solanaPrepare(step, in.Params)
	case "evm":
		return s.evmPrepare(ctx, step, in.Params)
	default:
		return nil, invariant("unsupported chainKind %q (supported: solana, evm)", in.ChainKind)
	}
}
