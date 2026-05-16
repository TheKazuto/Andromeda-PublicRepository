package policy

import (
	"testing"
)

func TestAddRuleTimeLock_Layout(t *testing.T) {
	pid := mustPub(t, "ARfJadMTH8mvAWprE8oMoRGNamKVDX9GV3URvudYyXgL")
	engine := mustPub(t, "9MaRaGinB3P9EDkD5kLzsfM4PPuMDGXQPYzEz7pUtiU4")
	dwallet := mustPub(t, "4aNkFccW7p2nZDC72wMqFxoKvJMVJQ28Pm7WcpqS9d14")
	payer := mustPub(t, "11111111111111111111111111111112")

	ix, err := AddRuleTimeLock(AddRuleTimeLockParams{
		ProgramID: pid, Engine: engine, DWallet: dwallet, Payer: payer,
		RuleIndex: 0, AppliesTo: AppliesNormal,
		Mode: TimeLockModeAbsolute, UnlockTs: 1_800_000_000,
	})
	if err != nil {
		t.Fatalf("AddRuleTimeLock: %v", err)
	}
	data, _ := ix.Data()
	// 1 + 32 + 8 + 1 + 1 + 1 + 8 + 8 = 60
	if len(data) != 60 {
		t.Fatalf("data length: got %d, want 60", len(data))
	}
	if data[0] != DiscAddRuleTimeLock {
		t.Fatalf("disc: %d", data[0])
	}
	// Layout: disc(0) + init_hash(1..33) + nonce(33..41) + rule_index(41) +
	// applies_to(42) + mode(43) + unlock_ts(44..52) + delay_seconds(52..60)
	if data[43] != TimeLockModeAbsolute {
		t.Fatalf("mode at offset 43: got %d", data[43])
	}
}

func TestAddRuleTimeLock_RejectsInvalidMode(t *testing.T) {
	_, err := AddRuleTimeLock(AddRuleTimeLockParams{
		ProgramID: mustPub(t, "ARfJadMTH8mvAWprE8oMoRGNamKVDX9GV3URvudYyXgL"),
		Mode:      9, // invalid
		AppliesTo: AppliesNormal,
	})
	if err == nil {
		t.Fatal("expected error for invalid mode")
	}
}

func TestAddRuleOracle_Layout(t *testing.T) {
	pid := mustPub(t, "ARfJadMTH8mvAWprE8oMoRGNamKVDX9GV3URvudYyXgL")
	ix, err := AddRuleOracle(AddRuleOracleParams{
		ProgramID: pid,
		Engine:    mustPub(t, "9MaRaGinB3P9EDkD5kLzsfM4PPuMDGXQPYzEz7pUtiU4"),
		DWallet:   mustPub(t, "4aNkFccW7p2nZDC72wMqFxoKvJMVJQ28Pm7WcpqS9d14"),
		Payer:     mustPub(t, "11111111111111111111111111111112"),
		AppliesTo: AppliesNormal,
		FreshnessSecondsDiv16: 4,
		MinConfidenceBpsDiv4:  2,
	})
	if err != nil {
		t.Fatalf("AddRuleOracle: %v", err)
	}
	data, _ := ix.Data()
	// 1 + 32 + 8 + 1 + 1 + 1 + 1 = 45
	if len(data) != 45 {
		t.Fatalf("data length: got %d, want 45", len(data))
	}
	if data[0] != DiscAddRuleOracle {
		t.Fatal("disc drift")
	}
}

func TestAddRulePasskey_Layout(t *testing.T) {
	pid := mustPub(t, "ARfJadMTH8mvAWprE8oMoRGNamKVDX9GV3URvudYyXgL")
	ix, err := AddRulePasskey(AddRulePasskeyParams{
		ProgramID: pid,
		Engine:    mustPub(t, "9MaRaGinB3P9EDkD5kLzsfM4PPuMDGXQPYzEz7pUtiU4"),
		DWallet:   mustPub(t, "4aNkFccW7p2nZDC72wMqFxoKvJMVJQ28Pm7WcpqS9d14"),
		Payer:     mustPub(t, "11111111111111111111111111111112"),
		AppliesTo: AppliesNormal,
	})
	if err != nil {
		t.Fatalf("AddRulePasskey: %v", err)
	}
	data, _ := ix.Data()
	// 1 + 32 + 8 + 1 + 1 = 43
	if len(data) != 43 {
		t.Fatalf("data length: got %d, want 43", len(data))
	}
	if data[0] != DiscAddRulePasskey {
		t.Fatal("disc drift")
	}
}

func TestAddRuleFheGated_Layout(t *testing.T) {
	pid := mustPub(t, "ARfJadMTH8mvAWprE8oMoRGNamKVDX9GV3URvudYyXgL")
	ix, err := AddRuleFheGated(AddRuleFheGatedParams{
		ProgramID: pid,
		Engine:    mustPub(t, "9MaRaGinB3P9EDkD5kLzsfM4PPuMDGXQPYzEz7pUtiU4"),
		DWallet:   mustPub(t, "4aNkFccW7p2nZDC72wMqFxoKvJMVJQ28Pm7WcpqS9d14"),
		Payer:     mustPub(t, "11111111111111111111111111111112"),
		AppliesTo: AppliesNormal,
		FreshnessSecondsDiv16: 8,
	})
	if err != nil {
		t.Fatalf("AddRuleFheGated: %v", err)
	}
	data, _ := ix.Data()
	// 1 + 32 + 8 + 1 + 1 + 1 = 44
	if len(data) != 44 {
		t.Fatalf("data length: got %d, want 44", len(data))
	}
	if data[0] != DiscAddRuleFheGated {
		t.Fatal("disc drift")
	}
}
