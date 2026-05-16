package policy

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gagliardetto/solana-go"
	"github.com/go-chi/chi/v5"
)

func newTestRouter() *chi.Mux {
	r := chi.NewRouter()
	svc := NewService(solana.PublicKey{})
	svc.MountRoutes(r)
	return r
}

func TestRoutes_SubmitEndpoints_503WithoutGasSponsor(t *testing.T) {
	// Service without WithGasSponsor / WithRPC — every /submit must return 503.
	r := newTestRouter()
	tests := []struct {
		path       string
		expectCode string
		expectHTTP int
	}{
		{"/v1/policy/init/submit", "no_gas_sponsor", http.StatusServiceUnavailable},
		{"/v1/policy/rules/add/submit", "no_gas_sponsor", http.StatusServiceUnavailable},
		{"/v1/policy/rules/0/items/add/submit", "no_gas_sponsor", http.StatusServiceUnavailable},
		{"/v1/policy/request-signature/submit", "no_gas_sponsor", http.StatusServiceUnavailable},
	}
	for _, tc := range tests {
		t.Run(tc.path, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, tc.path, bytes.NewBufferString("{}"))
			req.Header.Set("Content-Type", "application/json")
			rec := httptest.NewRecorder()
			r.ServeHTTP(rec, req)
			if rec.Code != tc.expectHTTP {
				t.Fatalf("%s: expected %d, got %d (body=%s)", tc.path, tc.expectHTTP, rec.Code, rec.Body.String())
			}
			var body map[string]string
			if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}
			if body["code"] != tc.expectCode {
				t.Fatalf("expected code=%q, got %q", tc.expectCode, body["code"])
			}
		})
	}
}

func TestRoutes_InitChallenge_HappyPath(t *testing.T) {
	r := newTestRouter()

	payload := map[string]any{
		"dwallet_address": "4aNkFccW7p2nZDC72wMqFxoKvJMVJQ28Pm7WcpqS9d14",
		"init_authority_slot": map[string]any{
			"scheme":         0,
			"identifier_hex": "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20",
		},
		"owner_slot": map[string]any{
			"scheme":         0,
			"identifier_hex": "2122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f40",
		},
	}
	body, _ := json.Marshal(payload)
	req := httptest.NewRequest(http.MethodPost, "/v1/policy/init/challenge", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d (body=%s)", rec.Code, rec.Body.String())
	}
	var resp initChallengeResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if resp.OpTag != "init" {
		t.Fatalf("expected op_tag=init, got %q", resp.OpTag)
	}
	if resp.ProgramID != "ARfJadMTH8mvAWprE8oMoRGNamKVDX9GV3URvudYyXgL" {
		t.Fatalf("unexpected program_id: %q", resp.ProgramID)
	}
	if len(resp.ChallengeHex) != 64 {
		t.Fatalf("expected 64-char hex, got %d", len(resp.ChallengeHex))
	}
}

func TestRoutes_AddRuleChallenge_AllowlistMatchesFixture(t *testing.T) {
	// Loads the canonical fixture and confirms the handler reproduces it
	// byte-for-byte. Deterministic inputs come from gen_policy_engine_fixtures.py
	// (`policy_engine_v3_test::*` namespace).
	f := loadFixture(t, "challenges/admin/add-rule-allowlist.json")
	in := f.Input

	// The fixture stores the engine PDA directly (not the dwallet). For the
	// route to recompute that engine, we need a matching (dwallet, init_hash)
	// pair. Skipping until we wire a `tools/dump_test_engine_inputs.json`
	// fixture in F2.6b.
	_ = in
	t.Skip("requires (dwallet,init_authority_hash) → engine reverse-mapping fixture (F2.6b)")
}
