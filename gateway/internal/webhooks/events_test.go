package webhooks

import (
	"encoding/base64"
	"encoding/binary"
	"testing"
)

// helper: build the bytes Quasar's `emit!()` would produce. Layout is
// `[discriminator: 1 byte][fields in declaration order]`.
func buildEvent(disc uint8, fields ...[]byte) string {
	total := 1
	for _, f := range fields {
		total += len(f)
	}
	buf := make([]byte, 0, total)
	buf = append(buf, disc)
	for _, f := range fields {
		buf = append(buf, f...)
	}
	return base64.StdEncoding.EncodeToString(buf)
}

func u64LE(v uint64) []byte {
	b := make([]byte, 8)
	binary.LittleEndian.PutUint64(b, v)
	return b
}

func TestParseEvent_PolicyDeployed(t *testing.T) {
	policy := bytes32(1)
	dwallet := bytes32(2)
	owner := bytes32(3)
	b64 := buildEvent(0, policy, dwallet, owner, u64LE(1700000000))

	ev, err := ParseEvent(b64, "prog", 42, "sig")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if ev == nil {
		t.Fatalf("expected event, got nil")
	}
	if ev.Type != "policy.deployed" {
		t.Errorf("type = %q, want policy.deployed", ev.Type)
	}
	if ev.TS != 1700000000 {
		t.Errorf("ts = %d, want 1700000000", ev.TS)
	}
	if ev.Slot != 42 {
		t.Errorf("slot = %d, want 42", ev.Slot)
	}
}

func TestParseEvent_SignatureRequested(t *testing.T) {
	b64 := buildEvent(1, bytes32(7), bytes32(8), u64LE(123))
	ev, err := ParseEvent(b64, "prog", 1, "sig")
	if err != nil || ev == nil {
		t.Fatalf("parse: %v ev=%v", err, ev)
	}
	if ev.Type != "signature.requested" {
		t.Errorf("type = %q, want signature.requested", ev.Type)
	}
}

func TestParseEvent_SignatureRejected(t *testing.T) {
	b64 := buildEvent(3, bytes32(1), bytes32(2), u64LE(99), u64LE(6042))
	ev, err := ParseEvent(b64, "prog", 1, "sig")
	if err != nil || ev == nil {
		t.Fatalf("parse: %v ev=%v", err, ev)
	}
	if ev.Type != "signature.rejected" {
		t.Errorf("type = %q, want signature.rejected", ev.Type)
	}
	if ev.ReasonCode == nil || *ev.ReasonCode != 6042 {
		t.Errorf("reason_code = %v, want 6042", ev.ReasonCode)
	}
}

func TestParseEvent_PolicyPausedAndResumed(t *testing.T) {
	pausedB64 := buildEvent(4, bytes32(1), u64LE(10))
	resumedB64 := buildEvent(5, bytes32(1), u64LE(20))

	for _, tc := range []struct {
		name string
		b64  string
		want string
	}{
		{"paused", pausedB64, "policy.paused"},
		{"resumed", resumedB64, "policy.resumed"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ev, err := ParseEvent(tc.b64, "prog", 0, "")
			if err != nil || ev == nil {
				t.Fatalf("parse: %v ev=%v", err, ev)
			}
			if ev.Type != tc.want {
				t.Errorf("type = %q, want %s", ev.Type, tc.want)
			}
		})
	}
}

func TestParseEvent_UnknownDiscriminator(t *testing.T) {
	b64 := buildEvent(99, bytes32(1))
	ev, err := ParseEvent(b64, "prog", 0, "")
	if err != nil {
		t.Fatalf("err = %v, want nil", err)
	}
	if ev != nil {
		t.Errorf("ev = %v, want nil for unknown discriminator", ev)
	}
}

func TestParseEvent_TruncatedPayload(t *testing.T) {
	// Discriminator says PolicyDeployed (104 bytes payload) but we only ship 50.
	short := append([]byte{0}, make([]byte, 50)...)
	b64 := base64.StdEncoding.EncodeToString(short)
	ev, err := ParseEvent(b64, "prog", 0, "")
	if err != nil {
		t.Fatalf("err = %v, want nil for short payload", err)
	}
	if ev != nil {
		t.Errorf("ev = %v, want nil for truncated payload", ev)
	}
}

func TestExtractEventLines(t *testing.T) {
	logs := []string{
		"Program 11 invoke [1]",
		"Program data: AAECAwQ=",
		"Program log: hello",
		"Program data: BQYHCAk=",
		"Program 11 success",
	}
	got := extractEventLines(logs)
	if len(got) != 2 {
		t.Fatalf("got %d, want 2", len(got))
	}
	if got[0] != "AAECAwQ=" || got[1] != "BQYHCAk=" {
		t.Errorf("payloads = %v", got)
	}
}

func TestBase58Encode_KnownPubkey(t *testing.T) {
	// "11111111111111111111111111111111" — 32 zero bytes.
	zeros := make([]byte, 32)
	got := base58Encode(zeros)
	want := "11111111111111111111111111111111"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func bytes32(seed byte) []byte {
	out := make([]byte, 32)
	for i := range out {
		out[i] = seed + byte(i)
	}
	return out
}

// ----- Ika event parser tests (Phase 3) -----

func buildIkaEvent(disc uint8, fields ...[]byte) string {
	total := 8 + 1
	for _, f := range fields {
		total += len(f)
	}
	buf := make([]byte, 0, total)
	buf = append(buf, ikaEventTagLE[:]...) // 8-byte tag
	buf = append(buf, disc)
	for _, f := range fields {
		buf = append(buf, f...)
	}
	return base64.StdEncoding.EncodeToString(buf)
}

func TestParseEvent_IkaDWalletCreated(t *testing.T) {
	dwallet := bytes32(10)
	authority := bytes32(20)
	curve := []byte{2}
	b64 := buildIkaEvent(0, dwallet, authority, curve)

	ev, err := ParseEvent(b64, "ika", 99, "sig-ika")
	if err != nil || ev == nil {
		t.Fatalf("parse: %v ev=%v", err, ev)
	}
	if ev.Type != "dwallet.created" {
		t.Errorf("type = %q, want dwallet.created", ev.Type)
	}
	if ev.Slot != 99 {
		t.Errorf("slot = %d, want 99", ev.Slot)
	}
	if ev.Raw["source"] != "ika" {
		t.Errorf("expected raw.source=ika, got %v", ev.Raw["source"])
	}
}

func TestParseEvent_IkaSignatureCommitted(t *testing.T) {
	ma := bytes32(7)
	sigLen := []byte{0x40, 0x00} // 64 LE
	b64 := buildIkaEvent(2, ma, sigLen)

	ev, err := ParseEvent(b64, "ika", 0, "")
	if err != nil || ev == nil {
		t.Fatalf("parse: %v ev=%v", err, ev)
	}
	if ev.Type != "signature.completed" {
		t.Errorf("type = %q, want signature.completed", ev.Type)
	}
	if got := ev.Raw["signature_len"]; got != uint16(64) {
		t.Errorf("signature_len = %v, want 64", got)
	}
}

func TestParseEvent_IkaUnknownDiscriminator(t *testing.T) {
	b64 := buildIkaEvent(99, bytes32(1))
	ev, err := ParseEvent(b64, "ika", 0, "")
	if err != nil || ev == nil {
		t.Fatalf("expected non-nil event for unknown disc, got %v err=%v", ev, err)
	}
	if ev.Type != "ika.event.unknown.99" {
		t.Errorf("type = %q, want ika.event.unknown.99", ev.Type)
	}
}

func TestParseEvent_AndromedaStillWorksWithIkaParserPresent(t *testing.T) {
	// PolicyDeployed (Andromeda template event) should still parse as before.
	policy := bytes32(1)
	dwallet := bytes32(2)
	owner := bytes32(3)
	b64 := buildEvent(0, policy, dwallet, owner, u64LE(1700000000))

	ev, err := ParseEvent(b64, "tpl", 0, "")
	if err != nil || ev == nil {
		t.Fatalf("parse: %v ev=%v", err, ev)
	}
	if ev.Type != "policy.deployed" {
		t.Errorf("type = %q, want policy.deployed", ev.Type)
	}
}
