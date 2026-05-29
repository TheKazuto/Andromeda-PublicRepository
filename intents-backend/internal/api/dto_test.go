package api

import (
	"strings"
	"testing"
)

func validQuote() quoteRequest {
	return quoteRequest{
		FromChain:   "1",
		ToChain:     "1",
		FromToken:   "0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
		ToToken:     "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48",
		FromAmount:  "1000000",
		FromAddress: "0x1111111111111111111111111111111111111111",
	}
}

// FromAmount must be a non-negative base-unit integer: the old `numeric` tag
// accepted "-100" and "1.5", which are never valid and break SetString later.
func TestValidateFromAmount(t *testing.T) {
	cases := []struct {
		name    string
		amount  string
		wantErr bool
	}{
		{"valid", "1000000", false},
		{"zero", "0", false},
		{"large uint256", strings.Repeat("9", 78), false},
		{"negative", "-100", true},
		{"decimal", "1.5", true},
		{"empty", "", true},
		{"letters", "abc", true},
		{"leading space", " 100", true},
		{"plus sign", "+100", true},
		{"too long", strings.Repeat("9", 81), true},
		{"hex", "0x10", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			q := validQuote()
			q.FromAmount = tc.amount
			err := validate.Struct(&q)
			if (err != nil) != tc.wantErr {
				t.Errorf("FromAmount=%q: err=%v, wantErr=%v", tc.amount, err, tc.wantErr)
			}
		})
	}
}

// finalizeRequest enforces base64 bodies, a hex signer key, and a positive
// chainId so obvious garbage fails at the boundary (400) instead of deep in an
// adapter (422).
func TestValidateFinalizeRequest(t *testing.T) {
	valid := finalizeRequest{
		ChainKind:       "evm",
		UnsignedTxB64:   "eyJhIjoxfQ==", // base64 of {"a":1}
		SignatureB64:    "AAAA",
		SignerPubkeyHex: "abcdef0123456789",
		ChainID:         1,
	}
	if err := validate.Struct(&valid); err != nil {
		t.Fatalf("valid finalize rejected: %v", err)
	}

	bad := []struct {
		name  string
		mutate func(*finalizeRequest)
	}{
		{"non-base64 unsignedTx", func(r *finalizeRequest) { r.UnsignedTxB64 = "not base64!" }},
		{"non-base64 signature", func(r *finalizeRequest) { r.SignatureB64 = "@@@" }},
		{"non-hex signer", func(r *finalizeRequest) { r.SignerPubkeyHex = "xyz" }},
		{"zero chainId", func(r *finalizeRequest) { r.ChainID = 0 }},
		{"negative chainId", func(r *finalizeRequest) { r.ChainID = -1 }},
	}
	for _, tc := range bad {
		t.Run(tc.name, func(t *testing.T) {
			r := valid
			tc.mutate(&r)
			if err := validate.Struct(&r); err == nil {
				t.Errorf("%s: expected validation error, got nil", tc.name)
			}
		})
	}
}
