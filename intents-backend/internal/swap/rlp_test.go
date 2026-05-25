package swap

import (
	"encoding/hex"
	"math/big"
	"testing"
)

// Canonical RLP vectors from the Ethereum docs.
func TestRLPString(t *testing.T) {
	tests := []struct {
		in   []byte
		want string
	}{
		{[]byte{}, "80"},
		{[]byte("dog"), "83646f67"},
		{[]byte{0x00}, "00"},
		{[]byte{0x0f}, "0f"},
		{[]byte{0x80}, "8180"},
	}
	for _, tc := range tests {
		if got := hex.EncodeToString(rlpString(tc.in)); got != tc.want {
			t.Errorf("rlpString(%x) = %s, want %s", tc.in, got, tc.want)
		}
	}
}

func TestRLPUint(t *testing.T) {
	tests := []struct {
		in   int64
		want string
	}{
		{0, "80"},
		{15, "0f"},
		{1024, "820400"},
	}
	for _, tc := range tests {
		if got := hex.EncodeToString(rlpUint(big.NewInt(tc.in))); got != tc.want {
			t.Errorf("rlpUint(%d) = %s, want %s", tc.in, got, tc.want)
		}
	}
}

func TestRLPList(t *testing.T) {
	got := hex.EncodeToString(rlpList(rlpString([]byte("cat")), rlpString([]byte("dog"))))
	if got != "c88363617483646f67" {
		t.Errorf("rlpList(cat,dog) = %s, want c88363617483646f67", got)
	}
	if hex.EncodeToString(rlpList()) != "c0" {
		t.Error("empty rlpList should be c0")
	}
}
