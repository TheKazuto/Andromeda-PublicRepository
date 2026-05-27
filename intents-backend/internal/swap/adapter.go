package swap

import (
	"context"
	"sort"
	"sync"

	"github.com/shinkalabs/andromeda-intents/internal/lifi"
)

// ChainAdapter is the per-family contract for turning a LI.FI route into a
// signed, broadcast transaction. Every family (EVM, Solana, TRON, Sui, Bitcoin)
// implements this interface; the Service dispatches through a registry, so
// adding a new family means writing one file and registering it — no switch
// growing in 5 places.
//
// The adapter never touches keys, policy or billing. It only:
//   - builds the unsigned tx + the canonical bytes-to-sign (Prepare),
//   - reconstructs those bytes from a persisted snapshot (DeriveMessage),
//   - inserts a signature and broadcasts (Finalize),
//   - reads native balance on the chain (NativeBalance).
type ChainAdapter interface {
	// Key is the canonical chainKind ("solana", "evm", "tron", "sui", "bitcoin").
	// Matches the value the gateway sends in the prepare/finalize request body.
	Key() string

	// SignScheme is the Ika signature scheme id (0 EcdsaKeccak256, 2
	// EcdsaDoubleSha256, 5 EddsaSha512, …). The gateway cross-checks this
	// against ika prepare-message to fail any scheme drift loudly.
	SignScheme() int

	// Prepare validates the LI.FI route and builds the unsigned tx + the bytes
	// the gateway will authorize/sign. Read-only against keys and policy.
	Prepare(ctx context.Context, step *lifi.Step, params lifi.QuoteParams) (*PrepareResult, error)

	// DeriveMessage recomputes the bytes-to-sign + digest + snapshot hash from
	// a persisted unsignedTx, WITHOUT re-quoting LI.FI. The gateway uses it to
	// re-validate the persisted snapshot byte-for-byte before signing.
	DeriveMessage(unsignedTxB64 string) (*DeriveResult, error)

	// Finalize inserts the dWallet signature and broadcasts. `urls` is the
	// RPC list already resolved by the Service (override first, then LI.FI
	// /chains cache).
	Finalize(ctx context.Context, in FinalizeInput, urls []string) (*FinalizeResult, error)

	// NativeBalance returns the native-token balance of `address` in base
	// units (lamports, wei, sun, …) as a decimal string. The gateway pre-checks
	// the dWallet can pay the swap gas before broadcasting.
	NativeBalance(ctx context.Context, urls []string, address string) (string, error)

	// ResolveRPCs returns the broadcast endpoints for a numeric LI.FI chainId.
	// Adapter-owned because the override env vars and the LI.FI cache key shape
	// differ slightly per family (Solana uses a single cluster URL, EVM keys by
	// chainId, TRON keys by chainId, …).
	ResolveRPCs(chainID int) []string
}

// registry holds the registered adapters. Populated by the Service constructor
// (per-Service registry, not global) so tests can build a Service with a subset
// of adapters and the production binary registers all of them at boot.
type registry struct {
	mu       sync.RWMutex
	adapters map[string]ChainAdapter
}

func newRegistry() *registry {
	return &registry{adapters: make(map[string]ChainAdapter)}
}

func (r *registry) register(a ChainAdapter) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.adapters[a.Key()] = a
}

func (r *registry) get(kind string) (ChainAdapter, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	a, ok := r.adapters[kind]
	return a, ok
}

func (r *registry) keys() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]string, 0, len(r.adapters))
	for k := range r.adapters {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// errUnsupportedKind is returned for a chainKind no adapter handles.
func errUnsupportedKind(kind string) error {
	return invariant("unsupported chainKind %q", kind)
}

// pickAdapter is the central dispatch helper. Wraps "not found" in
// InvariantError so handlers map it to 422 (caller-fixable), not 500.
func (s *Service) pickAdapter(kind string) (ChainAdapter, error) {
	a, ok := s.adapters.get(kind)
	if !ok {
		return nil, errUnsupportedKind(kind)
	}
	return a, nil
}

