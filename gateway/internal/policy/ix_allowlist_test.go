package policy

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/gagliardetto/solana-go"
)

func mustPub(t *testing.T, s string) solana.PublicKey {
	t.Helper()
	pk, err := solana.PublicKeyFromBase58(s)
	if err != nil {
		t.Fatalf("base58 %q: %v", s, err)
	}
	return pk
}

func TestAddRuleAllowlist_DataLayout(t *testing.T) {
	programID := mustPub(t, "ARfJadMTH8mvAWprE8oMoRGNamKVDX9GV3URvudYyXgL")
	engine := mustPub(t, "9MaRaGinB3P9EDkD5kLzsfM4PPuMDGXQPYzEz7pUtiU4")
	dwallet := mustPub(t, "4aNkFccW7p2nZDC72wMqFxoKvJMVJQ28Pm7WcpqS9d14")
	payer := mustPub(t, "11111111111111111111111111111112")

	var initHash [32]byte
	for i := range initHash {
		initHash[i] = byte(i)
	}

	ix, err := AddRuleAllowlist(AddRuleAllowlistParams{
		ProgramID:         programID,
		Engine:            engine,
		DWallet:           dwallet,
		Payer:             payer,
		InitAuthorityHash: initHash,
		ExpectedNonce:     0,
		RuleIndex:         0,
		AppliesTo:         AppliesNormal,
	})
	if err != nil {
		t.Fatalf("AddRuleAllowlist: %v", err)
	}

	data, err := ix.Data()
	if err != nil {
		t.Fatalf("ix.Data: %v", err)
	}
	expectedLen := 1 + 32 + 8 + 1 + 1
	if len(data) != expectedLen {
		t.Fatalf("data length: got %d, want %d", len(data), expectedLen)
	}
	if data[0] != DiscAddRuleAllowlist {
		t.Fatalf("disc: got %d, want %d", data[0], DiscAddRuleAllowlist)
	}
	if !bytes.Equal(data[1:33], initHash[:]) {
		t.Fatal("init_authority_hash byte drift")
	}
	if binary.LittleEndian.Uint64(data[33:41]) != 0 {
		t.Fatal("expected_nonce should be 0")
	}
	if data[41] != 0 {
		t.Fatal("rule_index should be 0")
	}
	if data[42] != AppliesNormal {
		t.Fatal("applies_to byte drift")
	}

	if len(ix.Accounts()) != 10 {
		t.Fatalf("expected 10 accounts, got %d", len(ix.Accounts()))
	}
	if !ix.Accounts()[3].IsSigner {
		t.Fatal("account[3] (payer) should be signer")
	}
}

func TestUpdateRuleAllowlistAddDestination_DataLayout(t *testing.T) {
	programID := mustPub(t, "ARfJadMTH8mvAWprE8oMoRGNamKVDX9GV3URvudYyXgL")
	engine := mustPub(t, "9MaRaGinB3P9EDkD5kLzsfM4PPuMDGXQPYzEz7pUtiU4")
	dwallet := mustPub(t, "4aNkFccW7p2nZDC72wMqFxoKvJMVJQ28Pm7WcpqS9d14")
	payer := mustPub(t, "11111111111111111111111111111112")

	var initHash [32]byte
	var dest [32]byte
	for i := range dest {
		dest[i] = byte(0xAA)
	}

	ix, err := UpdateRuleAllowlistAddDestination(UpdateRuleAllowlistAddDestinationParams{
		ProgramID:         programID,
		Engine:            engine,
		DWallet:           dwallet,
		Payer:             payer,
		InitAuthorityHash: initHash,
		ExpectedNonce:     1,
		RuleIndex:         0,
		Destination:       dest,
	})
	if err != nil {
		t.Fatalf("UpdateRuleAllowlistAddDestination: %v", err)
	}

	data, err := ix.Data()
	if err != nil {
		t.Fatalf("ix.Data: %v", err)
	}
	expectedLen := 1 + 32 + 8 + 1 + 32
	if len(data) != expectedLen {
		t.Fatalf("data length: got %d, want %d", len(data), expectedLen)
	}
	if data[0] != DiscUpdateRuleAllowlistAddDestination {
		t.Fatalf("disc: got %d, want %d", data[0], DiscUpdateRuleAllowlistAddDestination)
	}
	if !bytes.Equal(data[42:74], dest[:]) {
		t.Fatal("destination byte drift")
	}

	if len(ix.Accounts()) != 9 {
		t.Fatalf("expected 9 accounts, got %d", len(ix.Accounts()))
	}
}

func TestEnginePDA_Deterministic(t *testing.T) {
	programID := mustPub(t, "ARfJadMTH8mvAWprE8oMoRGNamKVDX9GV3URvudYyXgL")
	dwallet := mustPub(t, "4aNkFccW7p2nZDC72wMqFxoKvJMVJQ28Pm7WcpqS9d14")
	var slot [MemberSlotLen]byte
	for i := range slot {
		slot[i] = byte(i)
	}
	hash := InitAuthorityHashFromSlot(slot)

	pda1, bump1, err := EnginePDA(programID, dwallet, hash)
	if err != nil {
		t.Fatalf("EnginePDA: %v", err)
	}
	pda2, bump2, err := EnginePDA(programID, dwallet, hash)
	if err != nil {
		t.Fatalf("EnginePDA(2): %v", err)
	}
	if pda1 != pda2 || bump1 != bump2 {
		t.Fatal("EnginePDA should be deterministic")
	}
}
