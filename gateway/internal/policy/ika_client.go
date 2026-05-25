package policy

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/sony/gobreaker/v2"
)

// IkaSimulateClientImpl provides HTTP-based simulation for transaction digest verification.
// It calls the internal ika-backend endpoint POST /v1/dwallet/simulate with circuit breaker protection.
type IkaSimulateClientImpl struct {
	httpClient  *http.Client
	baseURL     string
	internalKey string
	breaker     *gobreaker.CircuitBreaker[*SimulateTransactionResponse]
	timeout     time.Duration
}

// NewIkaSimulateClient creates a new ika-backend simulation client with circuit breaker.
// baseURL should be e.g. "http://ika-backend:3000"
// internalKey is the X-Internal-Key or X-Api-Key header value.
// settings control circuit breaker behavior.
func NewIkaSimulateClient(baseURL, internalKey string, settings gobreaker.Settings, timeout time.Duration) (*IkaSimulateClientImpl, error) {
	if baseURL == "" {
		return nil, fmt.Errorf("baseURL required")
	}
	if internalKey == "" {
		return nil, fmt.Errorf("internalKey required")
	}
	if timeout == 0 {
		timeout = 10 * time.Second
	}

	breaker := gobreaker.NewCircuitBreaker[*SimulateTransactionResponse](settings)

	return &IkaSimulateClientImpl{
		httpClient:  &http.Client{Timeout: timeout},
		baseURL:     baseURL,
		internalKey: internalKey,
		breaker:     breaker,
		timeout:     timeout,
	}, nil
}

// SimulateTransactionRequest is the payload sent to ika-backend simulate endpoint.
type SimulateTransactionRequest struct {
	ChainID             string `json:"chain_id"`            // CAIP-2 format (e.g. "eip155:1", "solana:101")
	PayloadHex          string `json:"payload_hex"`         // raw transaction hex
	Kind                string `json:"kind"`                // "transaction"
	ExpectedDigestHex   string `json:"expected_digest_hex"` // the digest we expect
	DWalletPublicKeyHex string `json:"dwallet_public_key_hex"`
	RPCURL              string `json:"rpc_url,omitempty"` // client-funded destination-chain RPC (SSRF-checked in ika-backend)
}

// SimulateTransactionResponse is the response from ika-backend simulate endpoint.
type SimulateTransactionResponse struct {
	DigestMatches   bool            `json:"digest_matches"`
	ActualDigestHex string          `json:"actual_digest_hex,omitempty"`
	Destination     string          `json:"destination,omitempty"`
	Simulation      json.RawMessage `json:"simulation,omitempty"`    // raw simulation result (passthrough)
	CalldataRisk    json.RawMessage `json:"calldata_risk,omitempty"` // heuristic risk (passthrough)
	Error           string          `json:"error,omitempty"`
}

// SimulateTransaction calls the internal ika-backend simulate endpoint with
// circuit breaker protection. Returns the typed response or an error.
func (c *IkaSimulateClientImpl) SimulateTransaction(ctx context.Context, req *SimulateTransactionRequest) (*SimulateTransactionResponse, error) {
	if req == nil {
		return nil, fmt.Errorf("request must not be nil")
	}
	return c.breaker.Execute(func() (*SimulateTransactionResponse, error) {
		return c.simulateInternal(ctx, req)
	})
}

// simulateInternal performs the actual HTTP call without circuit breaker.
func (c *IkaSimulateClientImpl) simulateInternal(ctx context.Context, req *SimulateTransactionRequest) (*SimulateTransactionResponse, error) {
	url := c.baseURL + "/v1/dwallet/simulate"

	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("marshal request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}

	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("X-Api-Key", c.internalKey)

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("http call failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("simulate returned %d: %s", resp.StatusCode, string(respBody))
	}

	var simResp SimulateTransactionResponse
	if err := json.Unmarshal(respBody, &simResp); err != nil {
		return nil, fmt.Errorf("parse response: %w", err)
	}
	return &simResp, nil
}
