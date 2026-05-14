package audit

import (
	"encoding/base64"
	"testing"

	"github.com/shinkalabs/andromeda-gateway/internal/auth"
)

func TestBuildClearSigningPayload(t *testing.T) {
	var hash [32]byte
	for i := range hash {
		hash[i] = byte(i)
	}
	cs := auth.ClearSigning{
		Version:   "policy-clear-v1",
		Operation: "allowlist.add_destination",
		Fields: map[string]any{
			"dwallet":         "4xyz",
			"policy":          "9abc",
			"expected_nonce":  "7",
			"destination_hex": "deadbeef",
		},
	}
	got, err := BuildClearSigningPayload(hash, "Allow destination deadbeef on allowlist policy ...", cs)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if got.ClearSigningVersion != "policy-clear-v1" {
		t.Errorf("version: %q", got.ClearSigningVersion)
	}
	if got.Operation != "allowlist.add_destination" {
		t.Errorf("operation: %q", got.Operation)
	}
	if want := base64.StdEncoding.EncodeToString(hash[:]); got.ChallengeHashBase64 != want {
		t.Errorf("hash mismatch: got %q want %q", got.ChallengeHashBase64, want)
	}
	if got.HumanMessage == "" || got.FieldsHashBase64 == "" {
		t.Error("empty human/fields hash")
	}
}

func TestBuildClearSigningPayload_RejectsOverlongMessage(t *testing.T) {
	var hash [32]byte
	huge := make([]byte, auth.MaxHumanMessageBytes+1)
	for i := range huge {
		huge[i] = 'a'
	}
	_, err := BuildClearSigningPayload(hash, string(huge), auth.ClearSigning{
		Version:   "policy-clear-v1",
		Operation: "x",
		Fields:    map[string]any{},
	})
	if err == nil {
		t.Fatal("expected error for overlong humanMessage")
	}
}

func TestHashFieldsJCS_DeterministicAcrossInsertOrder(t *testing.T) {
	a := map[string]any{"b": 2, "a": 1, "c": 3}
	b := map[string]any{"c": 3, "a": 1, "b": 2}
	ha, err := hashFieldsJCS(a)
	if err != nil {
		t.Fatal(err)
	}
	hb, err := hashFieldsJCS(b)
	if err != nil {
		t.Fatal(err)
	}
	if ha != hb {
		t.Errorf("hashFieldsJCS not deterministic: %x vs %x", ha, hb)
	}
}

func TestSanitizePayload_AcceptsClearSigningKeysForGovernanceEvents(t *testing.T) {
	in := map[string]any{
		"policy_id":             "p1",
		"dwallet_address":       "dw1",
		"clear_signing_version": "policy-clear-v1",
		"operation":             "allowlist.pause",
		"challenge_hash_base64": "aGVsbG8=",
		"human_message":         "Pause allowlist policy ... for dWallet ...",
		"fields_hash_base64":    "AAAA",
		"unknown_key":           "should be dropped",
	}
	out := sanitizePayload(EventPolicyPaused, in)
	if _, ok := out["clear_signing_version"]; !ok {
		t.Error("clear_signing_version dropped — should be allowed for EventPolicyPaused")
	}
	if _, ok := out["unknown_key"]; ok {
		t.Error("unknown_key should be dropped")
	}
}
