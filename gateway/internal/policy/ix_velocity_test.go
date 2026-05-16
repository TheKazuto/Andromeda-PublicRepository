package policy

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func TestAddRuleVelocity_DataLayout(t *testing.T) {
	programID := mustPub(t, "ARfJadMTH8mvAWprE8oMoRGNamKVDX9GV3URvudYyXgL")
	engine := mustPub(t, "9MaRaGinB3P9EDkD5kLzsfM4PPuMDGXQPYzEz7pUtiU4")
	dwallet := mustPub(t, "4aNkFccW7p2nZDC72wMqFxoKvJMVJQ28Pm7WcpqS9d14")
	payer := mustPub(t, "11111111111111111111111111111112")

	var initHash [32]byte
	for i := range initHash {
		initHash[i] = byte(i + 0x80)
	}

	ix, err := AddRuleVelocity(AddRuleVelocityParams{
		ProgramID:         programID,
		Engine:            engine,
		DWallet:           dwallet,
		Payer:             payer,
		InitAuthorityHash: initHash,
		ExpectedNonce:     0,
		RuleIndex:         0,
		AppliesTo:         AppliesNormal,
		Windows: []VelocityWindow{
			{WindowSeconds: 60, Cap: 5},
		},
	})
	if err != nil {
		t.Fatalf("AddRuleVelocity: %v", err)
	}
	data, err := ix.Data()
	if err != nil {
		t.Fatalf("ix.Data: %v", err)
	}
	// 1 (disc) + 32 (init_hash) + 8 (nonce) + 1 (rule_index) + 1 (applies)
	// + 1 (windows_count) + 64 (windows_config 4×16) = 108
	if len(data) != 108 {
		t.Fatalf("data length: got %d, want 108", len(data))
	}
	if data[0] != DiscAddRuleVelocity {
		t.Fatalf("disc: got %d, want %d", data[0], DiscAddRuleVelocity)
	}
	if !bytes.Equal(data[1:33], initHash[:]) {
		t.Fatal("init_authority_hash byte drift")
	}
	if data[42] != AppliesNormal {
		t.Fatalf("applies_to drift: %d", data[42])
	}
	if data[43] != 1 {
		t.Fatalf("windows_count drift: %d", data[43])
	}
	// First window: window_seconds=60 at offset 44..52
	got := binary.LittleEndian.Uint64(data[44:52])
	if got != 60 {
		t.Fatalf("window_seconds: got %d, want 60", got)
	}
	// First window: cap=5 at offset 52..60
	got = binary.LittleEndian.Uint64(data[52:60])
	if got != 5 {
		t.Fatalf("cap: got %d, want 5", got)
	}
	// Remaining 3 windows must be zero-filled.
	for i := 60; i < 108; i++ {
		if data[i] != 0 {
			t.Fatalf("byte %d should be zero (got %d)", i, data[i])
		}
	}
	if len(ix.Accounts()) != 10 {
		t.Fatalf("expected 10 accounts, got %d", len(ix.Accounts()))
	}
}

func TestAddRuleVelocity_RejectsZeroCapOrSeconds(t *testing.T) {
	programID := mustPub(t, "ARfJadMTH8mvAWprE8oMoRGNamKVDX9GV3URvudYyXgL")
	engine := mustPub(t, "9MaRaGinB3P9EDkD5kLzsfM4PPuMDGXQPYzEz7pUtiU4")
	dwallet := mustPub(t, "4aNkFccW7p2nZDC72wMqFxoKvJMVJQ28Pm7WcpqS9d14")
	payer := mustPub(t, "11111111111111111111111111111112")

	_, err := AddRuleVelocity(AddRuleVelocityParams{
		ProgramID: programID,
		Engine:    engine,
		DWallet:   dwallet,
		Payer:     payer,
		AppliesTo: AppliesNormal,
		Windows:   []VelocityWindow{{WindowSeconds: 0, Cap: 5}},
	})
	if err == nil {
		t.Fatal("expected error for window_seconds=0")
	}
	_, err = AddRuleVelocity(AddRuleVelocityParams{
		ProgramID: programID,
		Engine:    engine,
		DWallet:   dwallet,
		Payer:     payer,
		AppliesTo: AppliesNormal,
		Windows:   []VelocityWindow{{WindowSeconds: 60, Cap: 0}},
	})
	if err == nil {
		t.Fatal("expected error for cap=0")
	}
	_, err = AddRuleVelocity(AddRuleVelocityParams{
		ProgramID: programID,
		Engine:    engine,
		DWallet:   dwallet,
		Payer:     payer,
		AppliesTo: AppliesNormal,
		Windows:   []VelocityWindow{}, // empty
	})
	if err == nil {
		t.Fatal("expected error for empty windows")
	}
}

func TestVelocityConfigHash_Stable(t *testing.T) {
	windowsFlat := make([]byte, MaxVelocityWindows*48)
	// Set window 0: window_seconds=60, cap=5
	binary.LittleEndian.PutUint64(windowsFlat[0:8], 60)
	binary.LittleEndian.PutUint64(windowsFlat[8:16], 5)
	h1, err := VelocityConfigHash(AppliesNormal, 1, windowsFlat)
	if err != nil {
		t.Fatalf("VelocityConfigHash: %v", err)
	}
	h2, _ := VelocityConfigHash(AppliesNormal, 1, windowsFlat)
	if h1 != h2 {
		t.Fatal("VelocityConfigHash should be deterministic")
	}
	// Different applies_to → different hash.
	h3, _ := VelocityConfigHash(AppliesAll, 1, windowsFlat)
	if h1 == h3 {
		t.Fatal("hash should differ for different applies_to")
	}
}
