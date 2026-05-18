package audit

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestBuildNDJSONGzip_RoundTrip(t *testing.T) {
	rows := []snapshotRow{
		{
			Seq:          1,
			APIKeyID:     uuid.NewString(),
			TS:           time.Date(2026, 5, 18, 12, 0, 0, 0, time.UTC),
			EventType:    "policy.created",
			ResourceType: "policy",
			ResourceID:   "policyA",
			Actor:        "operator-1",
			Payload:      json.RawMessage(`{"x":1}`),
			PrevHashHex:  "00",
			EntryHashHex: "ab",
			SignatureHex: "cd",
		},
		{
			Seq:          2,
			APIKeyID:     uuid.NewString(),
			TS:           time.Date(2026, 5, 18, 12, 0, 1, 0, time.UTC),
			EventType:    "policy.member.added",
			ResourceType: "policy",
			ResourceID:   "policyA",
			Actor:        "operator-2",
			Payload:      json.RawMessage(`{"member":"abc"}`),
			PrevHashHex:  "ab",
			EntryHashHex: "ef",
			SignatureHex: "01",
		},
	}
	out, err := buildNDJSONGzip(rows)
	if err != nil {
		t.Fatalf("buildNDJSONGzip: %v", err)
	}
	if len(out) == 0 {
		t.Fatal("output is empty")
	}
	// Decompress and verify each row decodes back to the original.
	gz, err := gzip.NewReader(bytes.NewReader(out))
	if err != nil {
		t.Fatalf("gzip reader: %v", err)
	}
	defer gz.Close()
	body, err := io.ReadAll(gz)
	if err != nil {
		t.Fatalf("read gzipped: %v", err)
	}
	lines := strings.Split(strings.TrimRight(string(body), "\n"), "\n")
	if len(lines) != len(rows) {
		t.Fatalf("got %d lines, want %d", len(lines), len(rows))
	}
	for i, line := range lines {
		var decoded snapshotRow
		if err := json.Unmarshal([]byte(line), &decoded); err != nil {
			t.Fatalf("decode line %d: %v (line=%s)", i, err, line)
		}
		if decoded.Seq != rows[i].Seq {
			t.Errorf("seq mismatch line %d: got %d want %d", i, decoded.Seq, rows[i].Seq)
		}
		if decoded.EntryHashHex != rows[i].EntryHashHex {
			t.Errorf("entry hash mismatch line %d: got %q want %q", i, decoded.EntryHashHex, rows[i].EntryHashHex)
		}
	}
}

func TestBuildNDJSONGzip_EmptyInput(t *testing.T) {
	// Empty input must produce a valid (empty) gzip stream — not nil.
	out, err := buildNDJSONGzip(nil)
	if err != nil {
		t.Fatalf("empty input failed: %v", err)
	}
	gz, err := gzip.NewReader(bytes.NewReader(out))
	if err != nil {
		t.Fatalf("gzip reader on empty: %v", err)
	}
	defer gz.Close()
	body, _ := io.ReadAll(gz)
	if len(body) != 0 {
		t.Errorf("expected empty body, got %d bytes", len(body))
	}
}

func TestBuildNDJSONGzip_DoesNotEscapeHTML(t *testing.T) {
	// Without SetEscapeHTML(false), `<` becomes `<` etc. The
	// snapshot must preserve raw payload bytes so the off-chain
	// verifier can re-hash the canonical record. This test guards that
	// invariant.
	row := snapshotRow{
		Seq:     1,
		Payload: json.RawMessage(`{"html":"<script>"}`),
	}
	out, err := buildNDJSONGzip([]snapshotRow{row})
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	gz, _ := gzip.NewReader(bytes.NewReader(out))
	defer gz.Close()
	body, _ := io.ReadAll(gz)
	// Raw `<script>` must survive — escapeHTML(false) keeps it
	// unencoded so external verifiers can re-hash the payload bytes.
	if !strings.Contains(string(body), `"<script>"`) {
		t.Errorf("expected raw <script> in JSON output, got: %s", string(body))
	}
	// And the encoder MUST NOT have inserted the literal escape
	// sequence (the 6-char string `<`, not the rune `<`). When
	// SetEscapeHTML is left on, Go writes that 6-char sequence instead
	// of the raw `<`.
	escaped := "\\u003c" // 6 chars: backslash, u, 0, 0, 3, c
	if strings.Contains(string(body), escaped) {
		t.Errorf("HTML unexpectedly escaped: %s", string(body))
	}
}

func TestEnvIntSnap_OverrideWins(t *testing.T) {
	// override > 0 returns immediately without consulting env.
	t.Setenv("FOO_X", "999")
	got := envIntSnap("FOO_X", 42, 100)
	if got != 42 {
		t.Errorf("got %d want 42 (override should win)", got)
	}
}

func TestEnvIntSnap_EnvWhenNoOverride(t *testing.T) {
	t.Setenv("FOO_Y", "55")
	got := envIntSnap("FOO_Y", 0, 100)
	if got != 55 {
		t.Errorf("got %d want 55", got)
	}
}

func TestEnvIntSnap_FallbackOnMalformed(t *testing.T) {
	t.Setenv("FOO_Z", "abc")
	got := envIntSnap("FOO_Z", 0, 7)
	if got != 7 {
		t.Errorf("got %d want fallback 7", got)
	}
}

func TestEnvDurSnap_SuffixHours(t *testing.T) {
	t.Setenv("AUDIT_SNAPSHOT_INTERVAL_HOURS", "3")
	got := envDurSnap("AUDIT_SNAPSHOT_INTERVAL_HOURS", 0, 24*time.Hour)
	if got != 3*time.Hour {
		t.Errorf("got %v want 3h", got)
	}
}

func TestEnvDurSnap_OverrideWins(t *testing.T) {
	os.Unsetenv("AUDIT_SNAPSHOT_INTERVAL_HOURS")
	got := envDurSnap("AUDIT_SNAPSHOT_INTERVAL_HOURS", 5*time.Minute, 24*time.Hour)
	if got != 5*time.Minute {
		t.Errorf("override should win: got %v", got)
	}
}
