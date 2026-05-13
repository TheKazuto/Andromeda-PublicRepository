package auth

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/gagliardetto/solana-go"
)

// TestFHEGatedDecisionCanonicalBytes_Fixture pins the gateway-side canonical
// digest computation to the cross-language fixture at
// fixtures/fhe-decision-vectors.json. The same fixture is consumed by
// encrypt-backend (TS) and contracts/fhe-gated (Rust). Any drift breaks every
// fhe-gated request_signature on devnet, so this test runs in CI alongside
// the TS and Rust suites.
func TestFHEGatedDecisionCanonicalBytes_Fixture(t *testing.T) {
	type vector struct {
		Name                string `json:"name"`
		PolicyHex           string `json:"policy_hex"`
		MessageDigestHex    string `json:"message_digest_hex"`
		DecisionCreatedSlot string `json:"decision_created_slot"`
		DecisionAuthorize   uint8  `json:"decision_authorize"`
		ExpectedDigestHex   string `json:"expected_digest_hex"`
	}
	type fixture struct {
		Version int      `json:"version"`
		Domain  string   `json:"domain"`
		Vectors []vector `json:"vectors"`
	}

	// Walk up from internal/auth to repo root to find fixtures/.
	path := findFixture(t, "fhe-decision-vectors.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	var f fixture
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatalf("parse fixture: %v", err)
	}
	if f.Domain != "andromeda::fhe-gated::decision::v1" {
		t.Fatalf("unexpected domain in fixture: %q", f.Domain)
	}
	if len(f.Vectors) == 0 {
		t.Fatal("fixture has no vectors")
	}

	for _, v := range f.Vectors {
		v := v
		t.Run(v.Name, func(t *testing.T) {
			policyBytes := mustHex(t, v.PolicyHex, 32)
			msgBytes := mustHex(t, v.MessageDigestHex, 32)
			slot, err := strconv.ParseUint(v.DecisionCreatedSlot, 10, 64)
			if err != nil {
				t.Fatalf("parse slot: %v", err)
			}

			var policy solana.PublicKey
			copy(policy[:], policyBytes)
			var msg [32]byte
			copy(msg[:], msgBytes)

			got := FHEGatedDecisionCanonicalBytes(policy, msg, slot, v.DecisionAuthorize)
			gotHex := hex.EncodeToString(got[:])
			if gotHex != v.ExpectedDigestHex {
				t.Fatalf("digest mismatch\n got:  %s\n want: %s", gotHex, v.ExpectedDigestHex)
			}
		})
	}
}

func findFixture(t *testing.T, name string) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	dir := wd
	for i := 0; i < 8; i++ {
		candidate := filepath.Join(dir, "fixtures", name)
		if _, err := os.Stat(candidate); err == nil {
			return candidate
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	t.Fatalf("could not locate fixtures/%s from %s", name, wd)
	return ""
}

func mustHex(t *testing.T, s string, expectedLen int) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("hex decode %q: %v", s, err)
	}
	if len(b) != expectedLen {
		t.Fatalf("hex %q decoded to %d bytes, want %d", s, len(b), expectedLen)
	}
	return b
}
