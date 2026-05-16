package policy

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/gagliardetto/solana-go"
)

// Synthesises a canonical PolicyEngine PDA byte buffer matching the on-chain
// layout, then asserts that DecodePolicyEngine round-trips every field.
func TestDecodePolicyEngine_RoundTrip(t *testing.T) {
	var dwallet solana.PublicKey
	for i := range dwallet {
		dwallet[i] = byte(i + 1)
	}
	var initSlot, ownerSlot [MemberSlotLen]byte
	initSlot[0] = 0 // Ed25519
	for i := 1; i < MemberSlotLen; i++ {
		initSlot[i] = byte(0x10 + i)
	}
	ownerSlot[0] = 0
	for i := 1; i < MemberSlotLen; i++ {
		ownerSlot[i] = byte(0x20 + i)
	}

	// Build the byte buffer exactly as the on-chain handler would write it.
	buf := make([]byte, policyEngineMinBytes)
	buf[0] = 1 // disc
	buf[1] = 1 // version
	copy(buf[2:34], dwallet[:])
	copy(buf[34:68], initSlot[:])
	copy(buf[68:102], ownerSlot[:])
	binary.LittleEndian.PutUint64(buf[102:110], 7)  // next_admin_nonce
	binary.LittleEndian.PutUint64(buf[110:118], 0)  // next_primary_recover
	binary.LittleEndian.PutUint64(buf[118:126], 0)
	binary.LittleEndian.PutUint64(buf[126:134], 0)
	binary.LittleEndian.PutUint64(buf[134:142], 0)
	buf[142] = 0                                                                   // paused
	buf[143] = 1                                                                   // rules_count
	binary.LittleEndian.PutUint32(buf[144:148], 2)                                  // rules_generation
	// pad 148..154
	// RuleEntry[0] starts at 154.
	off := 154
	buf[off+0] = uint8(KindAllowlist)
	buf[off+1] = 254 // bump
	buf[off+2] = 1   // version
	buf[off+3] = 1   // enabled
	binary.LittleEndian.PutUint32(buf[off+4:off+8], 1) // generation
	var fakePDA solana.PublicKey
	for i := range fakePDA {
		fakePDA[i] = byte(0xA0 + i)
	}
	copy(buf[off+8:off+40], fakePDA[:])
	var configHash [32]byte
	for i := range configHash {
		configHash[i] = byte(0xC0 + i)
	}
	copy(buf[off+40:off+72], configHash[:])

	state, err := DecodePolicyEngine(buf)
	if err != nil {
		t.Fatalf("DecodePolicyEngine: %v", err)
	}
	if state.Version != 1 {
		t.Fatalf("version: got %d", state.Version)
	}
	if state.DWallet != dwallet {
		t.Fatal("dwallet round-trip mismatch")
	}
	if state.NextAdminNonce != 7 {
		t.Fatalf("next_admin_nonce: got %d", state.NextAdminNonce)
	}
	if state.RulesCount != 1 {
		t.Fatalf("rules_count: got %d", state.RulesCount)
	}
	if state.RulesGeneration != 2 {
		t.Fatalf("rules_generation: got %d", state.RulesGeneration)
	}
	e0 := state.Rules[0]
	if e0.Kind != KindAllowlist || !e0.Enabled || e0.Generation != 1 {
		t.Fatalf("rule[0] drift: %+v", e0)
	}
	if e0.RulePDA != fakePDA {
		t.Fatal("rule_pda drift")
	}
	if !bytes.Equal(e0.ConfigHash[:], configHash[:]) {
		t.Fatal("config_hash drift")
	}
	// Slots 1..15 must be empty.
	for i := 1; i < MaxRules; i++ {
		if state.Rules[i].Kind != KindEmpty {
			t.Fatalf("rule[%d] should be empty", i)
		}
	}
}

func TestDecodePolicyEngine_RejectsWrongDisc(t *testing.T) {
	buf := make([]byte, policyEngineMinBytes)
	buf[0] = 99
	if _, err := DecodePolicyEngine(buf); err == nil {
		t.Fatal("expected error on wrong discriminator")
	}
}

func TestDecodeAllowlistRule_RoundTrip(t *testing.T) {
	buf := make([]byte, allowlistRuleMinBytes)
	buf[0] = 2 // disc
	buf[1] = uint8(KindAllowlist)
	buf[2] = 0    // index
	buf[3] = 1    // enabled
	// pad0 at buf[4]
	binary.LittleEndian.PutUint32(buf[5:9], 3)  // generation
	binary.LittleEndian.PutUint32(buf[9:13], 1) // config_version
	// _pad1 at 13..17
	var engineAddr solana.PublicKey
	for i := range engineAddr {
		engineAddr[i] = byte(0x42)
	}
	copy(buf[17:49], engineAddr[:])
	binary.LittleEndian.PutUint64(buf[49:57], 5) // next_admin_nonce
	var configHash [32]byte
	for i := range configHash {
		configHash[i] = byte(0xCC)
	}
	copy(buf[57:89], configHash[:])
	// _pad_header_tail at 89..97
	buf[97] = AppliesNormal
	buf[98] = 2 // destinations_count
	// _pad_cfg0 at 99..105
	var d0, d1 [32]byte
	for i := range d0 {
		d0[i] = byte(0xD0)
		d1[i] = byte(0xD1)
	}
	copy(buf[105:137], d0[:])
	copy(buf[137:169], d1[:])

	state, err := DecodeAllowlistRule(buf)
	if err != nil {
		t.Fatalf("DecodeAllowlistRule: %v", err)
	}
	if state.Kind != KindAllowlist || !state.Enabled || state.Generation != 3 {
		t.Fatalf("header drift: %+v", state)
	}
	if state.Engine != engineAddr {
		t.Fatal("engine address drift")
	}
	if state.AppliesTo != AppliesNormal {
		t.Fatal("applies_to drift")
	}
	if state.DestinationsCount != 2 || len(state.Destinations) != 2 {
		t.Fatalf("dest count: %d (slice len %d)", state.DestinationsCount, len(state.Destinations))
	}
	if !bytes.Equal(state.Destinations[0][:], d0[:]) {
		t.Fatal("destination[0] drift")
	}
	if !bytes.Equal(state.Destinations[1][:], d1[:]) {
		t.Fatal("destination[1] drift")
	}
}
