package networks

import "testing"

func devnet() Network {
	return Network{Name: "devnet", SolanaRPCURL: "https://devnet", IkaUpstreamURL: "http://ika"}
}

func TestNewRegistry_DefaultRequired(t *testing.T) {
	if _, err := NewRegistry(Network{}, nil); err == nil {
		t.Fatal("expected error for a default network without a name")
	}
}

func TestNewRegistry_DuplicateRejected(t *testing.T) {
	_, err := NewRegistry(devnet(), []Network{{Name: "Devnet"}})
	if err == nil {
		t.Fatal("expected duplicate-name error (case-insensitive)")
	}
}

func TestResolve_DefaultWhenHeaderAbsent(t *testing.T) {
	r, err := NewRegistry(devnet(), nil)
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}
	n, err := r.Resolve("")
	if err != nil {
		t.Fatalf("resolve empty: %v", err)
	}
	if n.Name != "devnet" {
		t.Fatalf("default network = %q, want devnet", n.Name)
	}
}

func TestResolve_KnownAndUnknown(t *testing.T) {
	r, err := NewRegistry(devnet(), []Network{{Name: "testnet", SolanaRPCURL: "https://testnet"}})
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}
	// Case-insensitive + trims.
	n, err := r.Resolve("  TESTNET ")
	if err != nil {
		t.Fatalf("resolve testnet: %v", err)
	}
	if n.SolanaRPCURL != "https://testnet" {
		t.Fatalf("testnet rpc = %q", n.SolanaRPCURL)
	}
	if _, err := r.Resolve("mainnet"); err == nil {
		t.Fatal("expected error for an unknown network")
	}
}

func TestNames(t *testing.T) {
	r, _ := NewRegistry(devnet(), []Network{{Name: "testnet"}})
	names := r.Names()
	if len(names) != 2 || names[0] != "devnet" || names[1] != "testnet" {
		t.Fatalf("names = %v, want [devnet testnet]", names)
	}
}
