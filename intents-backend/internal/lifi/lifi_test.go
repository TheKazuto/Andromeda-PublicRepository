package lifi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"
)

func TestFeeDecimal(t *testing.T) {
	tests := []struct {
		bps  int
		want string
	}{
		{0, ""},
		{30, "0.0030"},
		{200, "0.0200"},
		{10000, "1.0000"},
		{12345, "1.2345"},
	}
	for _, tc := range tests {
		c := &Client{feeBps: tc.bps}
		if got := c.FeeDecimal(); got != tc.want {
			t.Errorf("FeeDecimal(%d) = %q, want %q", tc.bps, got, tc.want)
		}
	}
}

func TestSlippageDecimal(t *testing.T) {
	if got := slippageDecimal(50); got != "0.005" {
		t.Errorf("slippageDecimal(50) = %q, want 0.005", got)
	}
}

func TestQuoteInjectsIntegratorAndFee(t *testing.T) {
	var gotQuery url.Values
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotQuery = r.URL.Query()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"tool":"jupiter",
			"action":{"fromChainId":1151111081099710,"toChainId":1151111081099710,
				"fromToken":{"symbol":"USDC"},"toToken":{"symbol":"SOL"}},
			"estimate":{"fromAmount":"1000000","toAmount":"5000000","toAmountMin":"4950000",
				"feeCosts":[{"name":"integrator fee","amountUSD":"0.30"}],
				"gasCosts":[{"name":"gas","amount":"5000","amountUSD":"0.01"}]}
		}`))
	}))
	defer srv.Close()

	c := New(Options{
		BaseURL:    srv.URL,
		Integrator: "andromeda",
		FeeBps:     30,
		Timeout:    5 * time.Second,
	})

	step, err := c.Quote(context.Background(), QuoteParams{
		FromChain: "SOL", ToChain: "SOL", FromToken: "USDC", ToToken: "SOL",
		FromAmount: "1000000", FromAddress: "dWalletAddr",
	})
	if err != nil {
		t.Fatalf("Quote: %v", err)
	}

	if got := gotQuery.Get("integrator"); got != "andromeda" {
		t.Errorf("integrator = %q, want andromeda", got)
	}
	if got := gotQuery.Get("fee"); got != "0.0030" {
		t.Errorf("fee = %q, want 0.0030", got)
	}
	if step.Estimate.ToAmount != "5000000" {
		t.Errorf("toAmount = %q", step.Estimate.ToAmount)
	}
	if got := step.Estimate.TransactionFeeUSD(); got != "0.300000" {
		t.Errorf("TransactionFeeUSD = %q, want 0.300000", got)
	}
	if got := step.Estimate.NativeFeeEstimate(); got != "5000" {
		t.Errorf("NativeFeeEstimate = %q, want 5000", got)
	}
}

func TestQuoteUpstreamErrorIsTyped(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"message":"no route"}`))
	}))
	defer srv.Close()

	c := New(Options{BaseURL: srv.URL, Timeout: 5 * time.Second})
	_, err := c.Quote(context.Background(), QuoteParams{
		FromChain: "SOL", ToChain: "SOL", FromToken: "USDC", ToToken: "SOL",
		FromAmount: "1", FromAddress: "x",
	})
	if err == nil {
		t.Fatal("expected error")
	}
	var up *ErrUpstream
	if !asUpstreamErr(err, &up) || up.StatusCode != http.StatusBadRequest {
		t.Errorf("expected ErrUpstream 400, got %v", err)
	}
}

// asUpstreamErr is a local errors.As shim kept tiny so the test reads clearly.
func asUpstreamErr(err error, target **ErrUpstream) bool {
	for err != nil {
		if e, ok := err.(*ErrUpstream); ok {
			*target = e
			return true
		}
		type unwrapper interface{ Unwrap() error }
		u, ok := err.(unwrapper)
		if !ok {
			return false
		}
		err = u.Unwrap()
	}
	return false
}

func TestRequiresAtaCreation(t *testing.T) {
	est := Estimate{GasCosts: []CostItem{{Name: "Token Account Rent"}}}
	if !est.RequiresAtaCreation() {
		t.Error("expected RequiresAtaCreation=true for rent cost item")
	}
	est2 := Estimate{GasCosts: []CostItem{{Name: "gas"}}}
	if est2.RequiresAtaCreation() {
		t.Error("expected RequiresAtaCreation=false for plain gas")
	}
}
