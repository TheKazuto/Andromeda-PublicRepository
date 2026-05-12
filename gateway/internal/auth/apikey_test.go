package auth

import (
	"net/http"
	"strings"
	"testing"
)

func TestGenerate(t *testing.T) {
	full, pubPrefix, hash, err := Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if !strings.HasPrefix(full, Prefix) {
		t.Fatalf("full key %q missing prefix %q", full, Prefix)
	}
	if !strings.HasPrefix(pubPrefix, Prefix) || !strings.HasSuffix(pubPrefix, "…") {
		t.Fatalf("public prefix %q has unexpected shape", pubPrefix)
	}
	if hash != Hash(full) {
		t.Fatalf("returned hash does not match Hash(full)")
	}
	if len(hash) != 64 {
		t.Fatalf("hash len = %d, want 64 hex chars", len(hash))
	}
	// Two calls must not collide.
	full2, _, _, err := Generate()
	if err != nil {
		t.Fatalf("Generate(2): %v", err)
	}
	if full == full2 {
		t.Fatalf("Generate produced the same key twice")
	}
}

func TestHashDeterministic(t *testing.T) {
	if Hash("sk_live_abc") != Hash("sk_live_abc") {
		t.Fatal("Hash is not deterministic")
	}
	if Hash("a") == Hash("b") {
		t.Fatal("Hash collision on distinct inputs")
	}
}

func TestExtractAPIKey(t *testing.T) {
	cases := []struct {
		name    string
		headers map[string]string
		want    string
	}{
		{"x-api-key", map[string]string{"X-Api-Key": "sk_live_abc"}, "sk_live_abc"},
		{"x-api-key trimmed", map[string]string{"X-Api-Key": "  sk_live_abc  "}, "sk_live_abc"},
		{"bearer", map[string]string{"Authorization": "Bearer sk_live_xyz"}, "sk_live_xyz"},
		{"bearer case-insensitive", map[string]string{"Authorization": "bEaReR sk_live_xyz"}, "sk_live_xyz"},
		{"x-api-key wins over bearer", map[string]string{"X-Api-Key": "sk_live_a", "Authorization": "Bearer sk_live_b"}, "sk_live_a"},
		{"no headers", nil, ""},
		{"authorization without bearer", map[string]string{"Authorization": "Basic Zm9v"}, ""},
		{"bare bearer", map[string]string{"Authorization": "Bearer "}, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r, _ := http.NewRequest(http.MethodGet, "/", nil)
			for k, v := range c.headers {
				r.Header.Set(k, v)
			}
			if got := ExtractAPIKey(r); got != c.want {
				t.Fatalf("ExtractAPIKey = %q, want %q", got, c.want)
			}
		})
	}
}

func TestConstantTimeEqual(t *testing.T) {
	if !ConstantTimeEqual("token-value", "token-value") {
		t.Fatal("equal strings reported unequal")
	}
	if ConstantTimeEqual("token-value", "token-valuE") {
		t.Fatal("different strings reported equal")
	}
	if ConstantTimeEqual("short", "longer-value") {
		t.Fatal("different-length strings reported equal")
	}
	if !ConstantTimeEqual("", "") {
		t.Fatal("empty strings reported unequal")
	}
}
