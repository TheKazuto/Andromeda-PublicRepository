package policy

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestQuorumPasskey_HappyPath_Challenges exercises the read-only challenge
// endpoints end-to-end and asserts they return well-formed responses with
// the canonical OpTag wired into the body.
func TestQuorumPasskey_HappyPath_Challenges(t *testing.T) {
	r := newTestRouter()

	cases := []struct {
		path      string
		body      map[string]any
		expectOp  string
		expectKey string // a field that must be present in response
	}{
		{
			path: "/v1/policy/quorum/session/open/challenge",
			body: map[string]any{
				"dwallet_address":         "4aNkFccW7p2nZDC72wMqFxoKvJMVJQ28Pm7WcpqS9d14",
				"init_authority_hash_hex": "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20",
				"primary_slot": map[string]any{
					"scheme":         0,
					"identifier_hex": "2122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f40",
				},
				"message_digest_hex":     "131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132",
				"metadata_digest_hex":    "1415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f30313233",
				"user_pubkey_hex":        "15161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f3031323334",
				"destination_hex":        "303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f",
				"signature_scheme":       0,
				"amount":                 5000000000,
				"expires_at":             1900000000,
				"session_nonce":          7,
				"rule_index":             0,
				"ika_curve":              0,
				"ika_dwallet_pubkey_hex": "15161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f3031323334",
			},
			expectOp:  "quorum-session-open",
			expectKey: "session_address",
		},
		{
			path: "/v1/policy/quorum/session/contribute/challenge",
			body: map[string]any{
				"dwallet_address":         "4aNkFccW7p2nZDC72wMqFxoKvJMVJQ28Pm7WcpqS9d14",
				"init_authority_hash_hex": "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20",
				"member_slot": map[string]any{
					"scheme":         0,
					"identifier_hex": "2122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f40",
				},
				"message_digest_hex":     "131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132",
				"metadata_digest_hex":    "1415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f30313233",
				"user_pubkey_hex":        "15161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f3031323334",
				"destination_hex":        "303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f",
				"signature_scheme":       0,
				"amount":                 2500000000,
				"expires_at":             1900000000,
				"session_nonce":          7,
				"rule_index":             0,
				"ika_curve":              0,
				"ika_dwallet_pubkey_hex": "15161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f3031323334",
			},
			expectOp:  "quorum-contribute",
			expectKey: "session_address",
		},
		{
			path: "/v1/policy/passkey/session/open/challenge",
			body: map[string]any{
				"dwallet_address":         "4aNkFccW7p2nZDC72wMqFxoKvJMVJQ28Pm7WcpqS9d14",
				"init_authority_hash_hex": "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20",
				"primary_slot": map[string]any{
					"scheme":         3,
					"identifier_hex": "030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20212223",
				},
				"eph_pk_hex":             "404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f",
				"not_after_unix_ts":      1900000000,
				"credential_id_hash_hex": "505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f",
				"passkey_session_nonce":  3,
				"rule_index":             0,
			},
			expectOp:  "passkey-session-open",
			expectKey: "session_address",
		},
		{
			path: "/v1/policy/passkey/use/challenge",
			body: map[string]any{
				"dwallet_address":         "4aNkFccW7p2nZDC72wMqFxoKvJMVJQ28Pm7WcpqS9d14",
				"init_authority_hash_hex": "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20",
				"primary_slot": map[string]any{
					"scheme":         3,
					"identifier_hex": "030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20212223",
				},
				"eph_pk_hex":             "404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f",
				"message_digest_hex":     "131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132",
				"metadata_digest_hex":    "1415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f30313233",
				"user_pubkey_hex":        "15161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f3031323334",
				"signature_scheme":       5,
				"use_nonce":              1,
				"passkey_session_nonce":  3,
				"rule_index":             0,
				"ika_curve":              0,
				"ika_dwallet_pubkey_hex": "15161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f3031323334",
			},
			expectOp:  "passkey-primary-use",
			expectKey: "session_address",
		},
	}

	for _, tc := range cases {
		t.Run(tc.path, func(t *testing.T) {
			body, _ := json.Marshal(tc.body)
			req := httptest.NewRequest(http.MethodPost, tc.path, bytes.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			rec := httptest.NewRecorder()
			r.ServeHTTP(rec, req)
			if rec.Code != http.StatusOK {
				t.Fatalf("expected 200, got %d (body=%s)", rec.Code, rec.Body.String())
			}
			var resp map[string]any
			if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}
			if resp["op_tag"] != tc.expectOp {
				t.Errorf("op_tag = %v, want %q", resp["op_tag"], tc.expectOp)
			}
			if _, ok := resp[tc.expectKey]; !ok {
				t.Errorf("missing key %q in response: %+v", tc.expectKey, resp)
			}
			if cb, ok := resp["challenge_hex"].(string); !ok || len(cb) != 64 {
				t.Errorf("challenge_hex missing or wrong length: %v", resp["challenge_hex"])
			}
		})
	}
}

// TestQuorumPasskey_Submit_503WithoutGasSponsor confirms every /submit and
// the permissionless quorum.finalize return 503 when gas sponsor isn't
// wired, mirroring the pattern used by Phase1's `TestRecoverAsPrimary_Submit_*`.
func TestQuorumPasskey_Submit_503WithoutGasSponsor(t *testing.T) {
	r := newTestRouter()
	paths := []string{
		"/v1/policy/quorum/session/open/submit",
		"/v1/policy/quorum/session/contribute/submit",
		"/v1/policy/quorum/session/finalize",
		"/v1/policy/quorum/session/close",
		"/v1/policy/passkey/session/open/submit",
		"/v1/policy/passkey/use/submit",
		"/v1/policy/passkey/session/close",
	}
	for _, p := range paths {
		t.Run(p, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, p, bytes.NewBufferString("{}"))
			req.Header.Set("Content-Type", "application/json")
			rec := httptest.NewRecorder()
			r.ServeHTTP(rec, req)
			if rec.Code != http.StatusServiceUnavailable {
				t.Fatalf("%s: expected 503, got %d (body=%s)", p, rec.Code, rec.Body.String())
			}
			var body map[string]string
			if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}
			if body["code"] != "no_gas_sponsor" {
				t.Errorf("%s: expected code=no_gas_sponsor, got %q", p, body["code"])
			}
		})
	}
}
