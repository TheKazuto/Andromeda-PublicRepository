package openapi

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

// TestSnapshotYAMLInSync guards gateway/openapi.yaml against drift: the
// committed file must be byte-identical to SnapshotYAML() (newline-normalized,
// so a CRLF checkout on Windows doesn't cause a false failure). When this fails,
// the generator changed (a route was added/removed, etc.) and the file needs to
// be regenerated.
func TestSnapshotYAMLInSync(t *testing.T) {
	want, err := SnapshotYAML()
	if err != nil {
		t.Fatalf("SnapshotYAML: %v", err)
	}

	// internal/openapi → gateway root.
	path := filepath.Join("..", "..", "openapi.yaml")
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}

	if !bytes.Equal(normalizeNewlines(got), normalizeNewlines(want)) {
		t.Fatalf("gateway/openapi.yaml is out of sync with the OpenAPI generator.\n" +
			"Regenerate it with:\n\tcd gateway && go run ./cmd/openapi-gen")
	}
}

// TestSnapshotYAMLDeterministic ensures repeated renders are byte-identical, so
// the guard test never flaps on map iteration order.
func TestSnapshotYAMLDeterministic(t *testing.T) {
	a, err := SnapshotYAML()
	if err != nil {
		t.Fatalf("SnapshotYAML #1: %v", err)
	}
	b, err := SnapshotYAML()
	if err != nil {
		t.Fatalf("SnapshotYAML #2: %v", err)
	}
	if !bytes.Equal(a, b) {
		t.Fatal("SnapshotYAML is not deterministic across calls")
	}
}

func normalizeNewlines(b []byte) []byte {
	return bytes.ReplaceAll(b, []byte("\r\n"), []byte("\n"))
}
