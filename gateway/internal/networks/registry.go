// Package networks is the multi-network scaffolding (Update 5 / F4): a registry
// that maps a network name (resolved from the X-Network request header) to its
// own RPC, engine upstreams, program ids and gas-sponsor keypair.
//
// SCAFFOLDING ONLY — Andromeda is devnet-only today. The registry is built at
// boot and validated, but the request hot path still uses the single configured
// network. Wiring the per-request resolution into the proxy / gas sponsor is the
// remaining step, to be done when a second real network exists. Until then the
// registry always has exactly one network (the default) and Resolve() returns it
// for an absent header, so current consumers are unaffected.
//
// Mirrors mpckit's `shared/networks/registry.ts` in spirit (network → client
// context, header-selected), adapted to Andromeda's custody-free boundaries:
// the gas sponsor keypair and program ids are per-network.
package networks

import (
	"errors"
	"fmt"
	"sort"
	"strings"
)

// HeaderNetwork is the request header that selects the target network. Absent →
// the registry default. Unknown/disabled value → a resolve error (400-worthy).
const HeaderNetwork = "X-Network"

// Network is one network's full context. The engine upstreams stay private; the
// gateway is still the only public surface. GasSponsorKeypairJSON is per-network
// (a distinct fee payer per chain).
type Network struct {
	Name                  string
	SolanaRPCURL          string
	IkaUpstreamURL        string
	EncryptUpstreamURL    string
	IkaProgramID          string
	PolicyEngineProgramID string
	GasSponsorKeypairJSON string
}

// Registry is an immutable name → Network map with a designated default.
type Registry struct {
	defaultName string
	byName      map[string]Network
}

// NewRegistry builds a registry from the default network plus optional extras.
// It validates that every network has a non-empty name and that names are
// unique. The default network is always present and is what Resolve returns
// when the X-Network header is absent.
func NewRegistry(defaultNet Network, extras []Network) (*Registry, error) {
	def := normalizeName(defaultNet.Name)
	if def == "" {
		return nil, errors.New("networks: default network must have a name")
	}
	defaultNet.Name = def
	byName := map[string]Network{def: defaultNet}
	for _, n := range extras {
		name := normalizeName(n.Name)
		if name == "" {
			return nil, errors.New("networks: extra network must have a name")
		}
		if _, dup := byName[name]; dup {
			return nil, fmt.Errorf("networks: duplicate network name %q", name)
		}
		n.Name = name
		byName[name] = n
	}
	return &Registry{defaultName: def, byName: byName}, nil
}

// Resolve maps an X-Network header value to a network. Empty → the default; an
// unknown name is an error so a caller cannot silently hit the wrong chain.
func (r *Registry) Resolve(header string) (Network, error) {
	name := normalizeName(header)
	if name == "" {
		return r.byName[r.defaultName], nil
	}
	n, ok := r.byName[name]
	if !ok {
		return Network{}, fmt.Errorf("unknown network %q (available: %s)", name, strings.Join(r.Names(), ", "))
	}
	return n, nil
}

// Default returns the default network.
func (r *Registry) Default() Network { return r.byName[r.defaultName] }

// Names returns the configured network names, sorted, for diagnostics/errors.
func (r *Registry) Names() []string {
	out := make([]string, 0, len(r.byName))
	for name := range r.byName {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

func normalizeName(s string) string {
	return strings.ToLower(strings.TrimSpace(s))
}
