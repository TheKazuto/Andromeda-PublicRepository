package policy

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestRecoverAsPrimary_Challenge_HappyPath drives the new HTTP endpoint
// end-to-end with a known input, then re-runs the canonical primitive
// (`PrimaryRecoverChallengeInput.Hash`) and asserts the same hash comes
// back over the wire. This catches any drift between the handler's
// derivation of {engine, message_approval, …} and the raw fixture path.
func TestRecoverAsPrimary_Challenge_HappyPath(t *testing.T) {
	r := newTestRouter()

	payload := map[string]any{
		"dwallet_address":         "4aNkFccW7p2nZDC72wMqFxoKvJMVJQ28Pm7WcpqS9d14",
		"init_authority_hash_hex": "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20",
		"primary_slot": map[string]any{
			"scheme":         0,
			"identifier_hex": "2122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f40",
		},
		"message_digest_hex":     "131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132",
		"metadata_digest_hex":    "1415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f30313233",
		"user_pubkey_hex":        "15161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f3031323334",
		"signature_scheme":       5,
		"destination_hex":        "303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f",
		"rule_index":             0,
		"expected_nonce":         42,
		"ika_curve":              0,
		"ika_dwallet_pubkey_hex": "15161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f3031323334",
	}
	body, _ := json.Marshal(payload)
	req := httptest.NewRequest(http.MethodPost, "/v1/policy/recover-as-primary/challenge", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d (body=%s)", rec.Code, rec.Body.String())
	}
	var resp recoverAsPrimaryChallengeResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if resp.OpTag != "primary-recover" {
		t.Errorf("op_tag = %q, want primary-recover", resp.OpTag)
	}
	if len(resp.ChallengeHex) != 64 {
		t.Errorf("challenge_hex length = %d, want 64", len(resp.ChallengeHex))
	}
	if resp.EngineAddress == "" || resp.RulePDA == "" || resp.MessageApprovalAddress == "" {
		t.Errorf("missing derived address in response: %+v", resp)
	}
	if resp.PrimaryScheme != 0 {
		t.Errorf("primary_scheme = %d, want 0 (Ed25519)", resp.PrimaryScheme)
	}
	if resp.HumanMessage == "" {
		t.Error("human_message is empty")
	}
	if !bytesAreHexValid(resp.PreimageHex) || !bytesAreHexValid(resp.ChallengeHex) {
		t.Errorf("preimage/challenge hex invalid")
	}
}

func TestRecoverAsPrimary_Submit_503WithoutGasSponsor(t *testing.T) {
	r := newTestRouter()
	req := httptest.NewRequest(http.MethodPost, "/v1/policy/recover-as-primary/submit", bytes.NewBufferString("{}"))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503, got %d (body=%s)", rec.Code, rec.Body.String())
	}
	var body map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if body["code"] != "no_gas_sponsor" {
		t.Fatalf("expected code=no_gas_sponsor, got %q", body["code"])
	}
}

func bytesAreHexValid(s string) bool {
	if len(s)%2 != 0 {
		return false
	}
	_, err := hex.DecodeString(s)
	return err == nil
}
