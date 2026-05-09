package mcp

import (
	"context"
	"strings"
	"testing"

	"github.com/shinkalabs/andromeda-gateway/internal/routes"
)

func TestPathParamNames(t *testing.T) {
	tests := []struct {
		path string
		want []string
	}{
		{"/v1/dwallet/dkg/prepare", nil},
		{"/v1/dwallet/presigns/{userPubkey}", []string{"userPubkey"}},
		{"/v1/recovery/policy/{dwalletAddress}", []string{"dwalletAddress"}},
		{"/v1/private-tx/status/{signature}", []string{"signature"}},
		{"/v1/decrypt/poll/{account}", []string{"account"}},
	}
	for _, tc := range tests {
		got := pathParamNames(tc.path)
		if !equalSlices(got, tc.want) {
			t.Errorf("pathParamNames(%q) = %v, want %v", tc.path, got, tc.want)
		}
	}
}

func TestSubstitutePathParams(t *testing.T) {
	out, err := substitutePathParams("/v1/recovery/policy/{dwalletAddress}", map[string]any{
		"dwalletAddress": "5nFrBSDXkME6qt2yXh2Y5N1je3ptQnYgXg9BtpTiyqqX",
	})
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if out != "/v1/recovery/policy/5nFrBSDXkME6qt2yXh2Y5N1je3ptQnYgXg9BtpTiyqqX" {
		t.Errorf("unexpected substitution: %s", out)
	}

	if _, err := substitutePathParams("/v1/foo/{id}", map[string]any{}); err == nil {
		t.Error("expected error for missing param")
	}
}

func TestNewToolRegistryWithoutUpstreams(t *testing.T) {
	reg := NewToolRegistry(nil)
	if reg.Count() < len(routes.All) {
		t.Fatalf("expected at least %d tools, got %d", len(routes.All), reg.Count())
	}

	// gateway.routes.list should always be present.
	h, ok := reg.Handler("gateway.routes.list")
	if !ok {
		t.Fatal("gateway.routes.list tool not registered")
	}
	res, err := h(context.Background(), nil)
	if err != nil {
		t.Fatalf("routes.list handler err: %v", err)
	}
	if len(res.Content) == 0 || !strings.Contains(res.Content[0].Text, "ika.dkg.prepare") {
		t.Errorf("routes.list output missing expected route: %v", res)
	}
}

func TestProxyHandlerFailsWhenUpstreamMissing(t *testing.T) {
	reg := NewToolRegistry(nil)
	h, ok := reg.Handler("ika.dkg.prepare")
	if !ok {
		t.Fatal("ika.dkg.prepare not registered")
	}
	res, err := h(context.Background(), map[string]any{"body": map[string]any{}})
	if err != nil {
		t.Fatalf("handler err: %v", err)
	}
	if !res.IsError {
		t.Error("expected error result when upstream not configured")
	}
}

func equalSlices(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
