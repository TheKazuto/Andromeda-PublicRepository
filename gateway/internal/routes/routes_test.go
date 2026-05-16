package routes

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// F10: every PolicyEngine entry must be Local (not proxied) and every
// admin submit must require an Idempotency-Key. Drift-test the catalogue.
func TestPolicyEngineRoutesAreLocalAndIdempotent(t *testing.T) {
	for _, r := range All {
		if !strings.HasPrefix(r.Path, "/v1/policy/") {
			continue
		}
		if !r.Local {
			t.Errorf("%s %s: PolicyEngine route must be Local=true", r.Method, r.Path)
		}
		if r.Upstream != UpstreamLocal {
			t.Errorf("%s %s: PolicyEngine route Upstream must be %q, got %q",
				r.Method, r.Path, UpstreamLocal, r.Upstream)
		}
		if r.Method == http.MethodPost && strings.HasSuffix(r.Path, "/submit") {
			if !r.RequiresIdempotencyKey {
				t.Errorf("%s %s: /submit must set RequiresIdempotencyKey=true",
					r.Method, r.Path)
			}
		}
	}
}

func TestRequiresIdempotencyKeyForRequest(t *testing.T) {
	tests := []struct {
		method string
		path   string
		want   bool
	}{
		// Listed routes:
		{"POST", "/v1/dwallet/dkg/submit", true},
		{"POST", "/v1/dwallet/sign/submit", true},
		{"POST", "/v1/policy/recover-as-primary/submit", true},
		{"POST", "/v1/policy/init/submit", true},
		{"POST", "/v1/policy/request-signature/submit", true},
		// `{ruleIndex}` placeholder must match:
		{"POST", "/v1/policy/rules/3/items/add/submit", true},
		// Read routes — no key required:
		{"POST", "/v1/policy/init/challenge", false},
		{"GET", "/v1/policy/SomeDwalletAddress", false},
		// Method mismatch:
		{"GET", "/v1/dwallet/dkg/submit", false},
		// Unknown path:
		{"POST", "/v1/nonexistent", false},
	}
	for _, tc := range tests {
		req := httptest.NewRequest(tc.method, tc.path, nil)
		got := RequiresIdempotencyKeyForRequest(req)
		if got != tc.want {
			t.Errorf("%s %s: got %v, want %v", tc.method, tc.path, got, tc.want)
		}
	}
}

// F11b-Phase1 + Phase2: every v3 recovery flow (primary + quorum + passkey)
// must be present in the catalogue, Local, and the mutating half must
// require an Idempotency-Key. Catches regressions on rename/delete.
func TestRecoverAsPrimaryRoutesPresent(t *testing.T) {
	expectKeys := []string{
		// Phase1
		"policy.engine.recover-as-primary.challenge",
		"policy.engine.recover-as-primary.submit",
		// Phase2 — quorum
		"policy.engine.quorum.open.challenge",
		"policy.engine.quorum.open.submit",
		"policy.engine.quorum.contribute.challenge",
		"policy.engine.quorum.contribute.submit",
		"policy.engine.quorum.finalize",
		"policy.engine.quorum.close",
		// Phase2 — passkey
		"policy.engine.passkey.open.challenge",
		"policy.engine.passkey.open.submit",
		"policy.engine.passkey.use.challenge",
		"policy.engine.passkey.use.submit",
		"policy.engine.passkey.close",
	}
	seen := map[string]bool{}
	for _, r := range All {
		for _, k := range expectKeys {
			if r.Key == k {
				seen[k] = true
				if !r.Local {
					t.Errorf("%s: must be Local=true", r.Key)
				}
				// Any path that ISN'T a `*/challenge` is a mutating
				// /submit-equivalent (also covers finalize + close).
				if !strings.HasSuffix(r.Path, "/challenge") && !r.RequiresIdempotencyKey {
					t.Errorf("%s: mutating route must require Idempotency-Key", r.Key)
				}
			}
		}
	}
	for _, k := range expectKeys {
		if !seen[k] {
			t.Errorf("route catalogue missing key %q", k)
		}
	}
}

func TestRequiredScopeRespectsAdminFlag(t *testing.T) {
	r := Route{RateClass: RateClassTx, AdminScope: true}
	if got := r.RequiredScope(); got != "admin" {
		t.Errorf("AdminScope route: got %q, want admin", got)
	}
	r2 := Route{RateClass: RateClassRead}
	if got := r2.RequiredScope(); got != "read" {
		t.Errorf("read-class: got %q, want read", got)
	}
	r3 := Route{RateClass: RateClassTx}
	if got := r3.RequiredScope(); got != "write" {
		t.Errorf("tx-class: got %q, want write", got)
	}
}
