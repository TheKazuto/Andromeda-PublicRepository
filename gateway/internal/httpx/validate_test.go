package httpx

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type sampleDTO struct {
	Pubkey  string `json:"pubkey" validate:"required,solana_pubkey"`
	Digest  string `json:"digest" validate:"required,base64_len=32"`
	Note    string `json:"note,omitempty" validate:"omitempty,max=64"`
	Scheme  uint16 `json:"scheme" validate:"required,oneof=0 1 2"`
	HexSig  string `json:"hex_sig,omitempty" validate:"omitempty,hex_len=64"`
	Counter int    `json:"counter" validate:"min=0,max=100"`
}

func decodeErrBody(t *testing.T, rr *httptest.ResponseRecorder) map[string]string {
	t.Helper()
	out := map[string]string{}
	if err := json.Unmarshal(rr.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode error body: %v (raw=%q)", err, rr.Body.String())
	}
	return out
}

func newReq(body string) *http.Request {
	return httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
}

func TestBindAndValidate_Success(t *testing.T) {
	body := `{
		"pubkey": "11111111111111111111111111111112",
		"digest": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
		"scheme": 1,
		"counter": 0
	}`
	var dto sampleDTO
	rr := httptest.NewRecorder()
	ok := BindAndValidate(rr, newReq(body), &dto, 1<<10)
	if !ok {
		t.Fatalf("expected ok, got body=%q status=%d", rr.Body.String(), rr.Code)
	}
	if dto.Pubkey == "" || dto.Digest == "" || dto.Scheme != 1 {
		t.Errorf("dto not populated: %+v", dto)
	}
}

func TestBindAndValidate_RejectsInvalidJSON(t *testing.T) {
	var dto sampleDTO
	rr := httptest.NewRecorder()
	ok := BindAndValidate(rr, newReq("not json"), &dto, 1<<10)
	if ok {
		t.Fatalf("expected fail")
	}
	if rr.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rr.Code)
	}
	if got := decodeErrBody(t, rr)["code"]; got != "invalid_body" {
		t.Errorf("code = %q, want invalid_body", got)
	}
}

func TestBindAndValidate_RejectsUnknownField(t *testing.T) {
	body := `{
		"pubkey": "11111111111111111111111111111112",
		"digest": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
		"scheme": 1,
		"counter": 0,
		"surprise": "boom"
	}`
	var dto sampleDTO
	rr := httptest.NewRecorder()
	ok := BindAndValidate(rr, newReq(body), &dto, 1<<10)
	if ok {
		t.Fatalf("expected fail on unknown field")
	}
	if got := decodeErrBody(t, rr)["code"]; got != "unknown_field" {
		t.Errorf("code = %q, want unknown_field", got)
	}
}

func TestBindAndValidate_RejectsMissingRequired(t *testing.T) {
	body := `{"scheme": 1, "counter": 0, "digest": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}`
	var dto sampleDTO
	rr := httptest.NewRecorder()
	ok := BindAndValidate(rr, newReq(body), &dto, 1<<10)
	if ok {
		t.Fatalf("expected fail on missing pubkey")
	}
	got := decodeErrBody(t, rr)
	if got["code"] != "invalid_field" {
		t.Errorf("code = %q, want invalid_field", got["code"])
	}
	if !strings.Contains(got["error"], "pubkey") {
		t.Errorf("error = %q, want to mention pubkey", got["error"])
	}
}

func TestBindAndValidate_RejectsBadSolanaPubkey(t *testing.T) {
	body := `{
		"pubkey": "not-base58",
		"digest": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
		"scheme": 1,
		"counter": 0
	}`
	var dto sampleDTO
	rr := httptest.NewRecorder()
	ok := BindAndValidate(rr, newReq(body), &dto, 1<<10)
	if ok {
		t.Fatalf("expected fail")
	}
	got := decodeErrBody(t, rr)
	if got["code"] != "invalid_field" {
		t.Errorf("code = %q", got["code"])
	}
	if !strings.Contains(got["error"], "solana") && !strings.Contains(got["error"], "base58") {
		t.Errorf("error = %q, want to mention rule", got["error"])
	}
}

func TestBindAndValidate_RejectsWrongBase64Length(t *testing.T) {
	body := `{
		"pubkey": "11111111111111111111111111111112",
		"digest": "AAAA",
		"scheme": 1,
		"counter": 0
	}`
	var dto sampleDTO
	rr := httptest.NewRecorder()
	ok := BindAndValidate(rr, newReq(body), &dto, 1<<10)
	if ok {
		t.Fatalf("expected fail")
	}
	if !strings.Contains(decodeErrBody(t, rr)["error"], "32 bytes") {
		t.Errorf("error = %q", rr.Body.String())
	}
}

func TestBindAndValidate_RejectsBadOneOf(t *testing.T) {
	body := `{
		"pubkey": "11111111111111111111111111111112",
		"digest": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
		"scheme": 99,
		"counter": 0
	}`
	var dto sampleDTO
	rr := httptest.NewRecorder()
	ok := BindAndValidate(rr, newReq(body), &dto, 1<<10)
	if ok {
		t.Fatalf("expected fail")
	}
	if !strings.Contains(decodeErrBody(t, rr)["error"], "one of") {
		t.Errorf("error = %q", rr.Body.String())
	}
}

func TestBindAndValidate_PayloadTooLarge(t *testing.T) {
	// 200 bytes of payload but the cap is 64.
	body := `{"pubkey":"` + strings.Repeat("x", 200) + `","digest":"x","scheme":1,"counter":0}`
	var dto sampleDTO
	rr := httptest.NewRecorder()
	ok := BindAndValidate(rr, newReq(body), &dto, 64)
	if ok {
		t.Fatalf("expected fail")
	}
	if rr.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("status = %d, want 413", rr.Code)
	}
	if got := decodeErrBody(t, rr)["code"]; got != "payload_too_large" {
		t.Errorf("code = %q, want payload_too_large", got)
	}
}

func TestBindAndValidate_RejectsTrailingJSON(t *testing.T) {
	body := `{"pubkey":"11111111111111111111111111111112","digest":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=","scheme":1,"counter":0}{"extra":1}`
	var dto sampleDTO
	rr := httptest.NewRecorder()
	ok := BindAndValidate(rr, newReq(body), &dto, 1<<10)
	if ok {
		t.Fatalf("expected fail on trailing JSON")
	}
	if got := decodeErrBody(t, rr)["code"]; got != "invalid_body" {
		t.Errorf("code = %q, want invalid_body", got)
	}
}

func TestBindAndValidate_OptionalFieldEmptyOK(t *testing.T) {
	body := `{
		"pubkey": "11111111111111111111111111111112",
		"digest": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
		"scheme": 1,
		"counter": 50
	}`
	var dto sampleDTO
	rr := httptest.NewRecorder()
	ok := BindAndValidate(rr, newReq(body), &dto, 1<<10)
	if !ok {
		t.Fatalf("optional fields should be accepted: %s", rr.Body.String())
	}
}

func TestBindAndValidate_HexLenValidator(t *testing.T) {
	good := strings.Repeat("ab", 64) // 64 bytes when decoded
	bad := "abcdef"
	for _, tc := range []struct {
		name string
		hex  string
		want bool
	}{
		{"valid 64-byte hex", good, true},
		{"too short", bad, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body := `{
				"pubkey": "11111111111111111111111111111112",
				"digest": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
				"scheme": 1,
				"counter": 0,
				"hex_sig": "` + tc.hex + `"
			}`
			var dto sampleDTO
			rr := httptest.NewRecorder()
			ok := BindAndValidate(rr, newReq(body), &dto, 1<<10)
			if ok != tc.want {
				t.Errorf("ok=%v want=%v body=%q", ok, tc.want, rr.Body.String())
			}
		})
	}
}
