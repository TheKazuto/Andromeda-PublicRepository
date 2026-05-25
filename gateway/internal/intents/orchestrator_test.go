package intents

import (
	"errors"
	"net/http"
	"testing"
)

func TestNonZeroDigest(t *testing.T) {
	zero := ""
	for i := 0; i < 32; i++ {
		zero += "00"
	}
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"empty", "", ""},
		{"all zero (Solana)", zero, ""},
		{"non-zero", "01" + zero[2:], "01" + zero[2:]},
		{"bad hex", "zz", ""},
	}
	for _, tc := range tests {
		if got := nonZeroDigest(tc.in); got != tc.want {
			t.Errorf("%s: nonZeroDigest(%q) = %q, want %q", tc.name, tc.in, got, tc.want)
		}
	}
}

func TestAtoiOrZero(t *testing.T) {
	if atoiOrZero("1151111081099710") != 1151111081099710 {
		t.Error("expected numeric parse")
	}
	if atoiOrZero("") != 0 || atoiOrZero("abc") != 0 {
		t.Error("expected 0 for non-numeric")
	}
}

func TestUpstreamUserError(t *testing.T) {
	tests := []struct {
		status   int
		wantCode string
		wantHTTP int
	}{
		{http.StatusUnprocessableEntity, "no_route", http.StatusUnprocessableEntity},
		{http.StatusTooManyRequests, "backpressure", http.StatusTooManyRequests},
		{http.StatusInternalServerError, "upstream_error", http.StatusBadGateway},
	}
	for _, tc := range tests {
		ue := upstreamUserError(tc.status, nil, "fallback")
		if ue.code != tc.wantCode || ue.status != tc.wantHTTP {
			t.Errorf("status %d → code=%q http=%d, want code=%q http=%d",
				tc.status, ue.code, ue.status, tc.wantCode, tc.wantHTTP)
		}
	}
}

func TestRiskLevel(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"empty", "", "none"},
		{"no risk key", `{"digestVerified":true}`, "none"},
		{"high", `{"risk":{"level":"high","reasons":["x"]}}`, "high"},
		{"critical", `{"risk":{"level":"critical"},"simulation":{}}`, "critical"},
		{"bad json", `not-json`, "none"},
	}
	for _, tc := range tests {
		if got := riskLevel([]byte(tc.in)); got != tc.want {
			t.Errorf("%s: riskLevel(%q) = %q, want %q", tc.name, tc.in, got, tc.want)
		}
	}
}

func TestNormAddr(t *testing.T) {
	tests := []struct{ in, want string }{
		{"  0xAbCd  ", "0xabcd"},                 // EVM: trimmed + lowercased
		{"0XABCD", "0xabcd"},                     // EVM uppercase prefix
		{"So1anaBase58Addr", "So1anaBase58Addr"}, // base58: exact (case-sensitive)
	}
	for _, tc := range tests {
		if got := normAddr(tc.in); got != tc.want {
			t.Errorf("normAddr(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestUserErrorIsError(t *testing.T) {
	var err error = &userError{status: 400, code: "x", msg: "bad"}
	var ue *userError
	if !errors.As(err, &ue) || ue.msg != "bad" {
		t.Error("userError should satisfy error and unwrap via errors.As")
	}
}
