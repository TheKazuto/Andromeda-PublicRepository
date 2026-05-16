package policy

import (
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/gagliardetto/solana-go"
)

// fixturesDir locates `fixtures/policy_engine_v3/` from any directory under
// the repo (walks up the tree looking for `fixtures/policy_engine_v3/`).
func fixturesDir(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("os.Getwd: %v", err)
	}
	for {
		candidate := filepath.Join(dir, "fixtures", "policy_engine_v3")
		if info, err := os.Stat(candidate); err == nil && info.IsDir() {
			return candidate
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatalf("fixtures/policy_engine_v3/ not found above %s", dir)
		}
		dir = parent
	}
}

type fixtureFile struct {
	SpecRef string `json:"spec_ref"`
	Version string `json:"version"`
	Status  string `json:"status"`
	Input   map[string]any `json:"input"`
	Expected struct {
		PreimageHex   string `json:"preimage_hex"`
		PreimageBytes int    `json:"preimage_bytes"`
		ChallengeHex  string `json:"challenge_hex"`
	} `json:"expected"`
}

func loadFixture(t *testing.T, rel string) fixtureFile {
	t.Helper()
	path := filepath.Join(fixturesDir(t), rel)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	var f fixtureFile
	if err := json.Unmarshal(data, &f); err != nil {
		t.Fatalf("unmarshal %s: %v", path, err)
	}
	if f.Status != "frozen" {
		t.Skipf("fixture %s is %q (not frozen) — skipping cross-language assertion", rel, f.Status)
	}
	return f
}

func decodeHex32(t *testing.T, s string) [32]byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != 32 {
		t.Fatalf("expected 32-byte hex, got %q (%d bytes, err=%v)", s, len(b), err)
	}
	var out [32]byte
	copy(out[:], b)
	return out
}

func decodeHex34(t *testing.T, s string) [MemberSlotLen]byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != MemberSlotLen {
		t.Fatalf("expected 34-byte hex, got %q (%d bytes, err=%v)", s, len(b), err)
	}
	var out [MemberSlotLen]byte
	copy(out[:], b)
	return out
}

func mustPubkey(t *testing.T, s string) solana.PublicKey {
	t.Helper()
	pk, err := solana.PublicKeyFromBase58(s)
	if err != nil {
		t.Fatalf("base58 %q: %v", s, err)
	}
	return pk
}

func u64(v any) uint64 {
	switch x := v.(type) {
	case float64:
		return uint64(x)
	case int:
		return uint64(x)
	case int64:
		return uint64(x)
	case uint64:
		return x
	default:
		panic("u64: unexpected type")
	}
}

func u32(v any) uint32 {
	switch x := v.(type) {
	case float64:
		return uint32(x)
	case int:
		return uint32(x)
	case uint32:
		return x
	default:
		panic("u32: unexpected type")
	}
}

func u8(v any) uint8 {
	switch x := v.(type) {
	case float64:
		return uint8(x)
	case int:
		return uint8(x)
	default:
		panic("u8: unexpected type")
	}
}

// ─── Tests ──────────────────────────────────────────────────────────────────

func TestAdminChallenge_AddRuleAllowlist_MatchesFixture(t *testing.T) {
	f := loadFixture(t, "challenges/admin/add-rule-allowlist.json")
	in := f.Input

	engine := mustPubkey(t, in["engine_b58"].(string))
	dwallet := mustPubkey(t, in["dwallet_b58"].(string))
	ruleKind := u8(in["rule_kind"])
	ruleIndex := u8(in["rule_index"])
	ruleGen := u32(in["rule_generation"])
	expectedNonce := u64(in["expected_nonce"])
	appliesTo := u8(in["applies_to"])
	configHash := decodeHex32(t, in["config_hash_hex"].(string))
	ownerSlot := decodeHex34(t, in["owner_slot_hex"].(string))
	human := []byte(in["human_message_utf8"].(string))

	var genLE [4]byte
	binary.LittleEndian.PutUint32(genLE[:], ruleGen)

	got := &AdminChallengeInput{
		OpTag:          OpAddAllowlist,
		HumanMessage:   human,
		Engine:         engine,
		DWallet:        dwallet,
		RuleKind:       ruleKind,
		RuleIndex:      ruleIndex,
		RuleGeneration: ruleGen,
		ExpectedNonce:  expectedNonce,
		ConfigHash:     configHash,
		OwnerSlot:      ownerSlot,
		Extras:         [][]byte{{appliesTo}, genLE[:]},
	}
	pre, err := got.Preimage()
	if err != nil {
		t.Fatalf("preimage: %v", err)
	}
	if hex.EncodeToString(pre) != f.Expected.PreimageHex {
		t.Fatalf("preimage drift:\n  got:  %s\n  want: %s", hex.EncodeToString(pre), f.Expected.PreimageHex)
	}
	h, _ := got.Hash()
	if hex.EncodeToString(h[:]) != f.Expected.ChallengeHex {
		t.Fatalf("challenge drift:\n  got:  %s\n  want: %s", hex.EncodeToString(h[:]), f.Expected.ChallengeHex)
	}
}

func TestAdminChallenge_AllowlistAddDestination_MatchesFixture(t *testing.T) {
	f := loadFixture(t, "challenges/admin/allowlist-add-destination.json")
	in := f.Input

	engine := mustPubkey(t, in["engine_b58"].(string))
	dwallet := mustPubkey(t, in["dwallet_b58"].(string))
	ruleIndex := u8(in["rule_index"])
	ruleGen := u32(in["rule_generation"])
	expectedNonce := u64(in["expected_nonce"])
	configHash := decodeHex32(t, in["config_hash_hex"].(string))
	ownerSlot := decodeHex34(t, in["owner_slot_hex"].(string))
	destHex := in["destination_hex"].(string)
	destBytes, _ := hex.DecodeString(destHex)
	var dest [32]byte
	copy(dest[:], destBytes)
	human := HumanMessageAllowlistAddDestination(dest, engine, dwallet)

	// Sanity: human message reproduced by Go must equal the one stored.
	if string(human) != in["human_message_utf8"].(string) {
		t.Fatalf("human_message drift:\n  got:  %s\n  want: %s", string(human), in["human_message_utf8"].(string))
	}

	var genLE [4]byte
	binary.LittleEndian.PutUint32(genLE[:], ruleGen)

	got := &AdminChallengeInput{
		OpTag:          OpAllowlistAddDest,
		HumanMessage:   human,
		Engine:         engine,
		DWallet:        dwallet,
		RuleKind:       uint8(KindAllowlist),
		RuleIndex:      ruleIndex,
		RuleGeneration: ruleGen,
		ExpectedNonce:  expectedNonce,
		ConfigHash:     configHash,
		OwnerSlot:      ownerSlot,
		Extras:         [][]byte{dest[:], genLE[:]},
	}
	pre, err := got.Preimage()
	if err != nil {
		t.Fatalf("preimage: %v", err)
	}
	if hex.EncodeToString(pre) != f.Expected.PreimageHex {
		t.Fatalf("preimage drift:\n  got:  %s\n  want: %s", hex.EncodeToString(pre), f.Expected.PreimageHex)
	}
	h, _ := got.Hash()
	if hex.EncodeToString(h[:]) != f.Expected.ChallengeHex {
		t.Fatalf("challenge drift:\n  got:  %s\n  want: %s", hex.EncodeToString(h[:]), f.Expected.ChallengeHex)
	}
}

func TestRequestMetadataDigest_MatchesFixture(t *testing.T) {
	f := loadFixture(t, "challenges/runtime/request_metadata_digest.json")
	in := f.Input

	got := &RequestMetadataDigestInput{
		Engine:          mustPubkey(t, in["engine_b58"].(string)),
		DWallet:         mustPubkey(t, in["dwallet_b58"].(string)),
		MessageDigest:   decodeHex32(t, in["message_digest_hex"].(string)),
		Destination:     decodeHex32(t, in["destination_hex"].(string)),
		UserPubkey:      decodeHex32(t, in["user_pubkey_hex"].(string)),
		SignatureScheme: uint16(u64(in["signature_scheme"])),
		Path:            u8(in["path"]),
		RulesGeneration: u32(in["rules_generation"]),
	}
	pre := got.Preimage()
	if hex.EncodeToString(pre) != f.Expected.PreimageHex {
		t.Fatalf("preimage drift:\n  got:  %s\n  want: %s", hex.EncodeToString(pre), f.Expected.PreimageHex)
	}
	h := got.Hash()
	if hex.EncodeToString(h[:]) != f.Expected.ChallengeHex {
		t.Fatalf("challenge drift:\n  got:  %s\n  want: %s", hex.EncodeToString(h[:]), f.Expected.ChallengeHex)
	}
}
