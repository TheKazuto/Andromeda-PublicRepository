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
	breaker     *gobreaker.CircuitBreaker[interface{}]
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

	breaker := gobreaker.NewCircuitBreaker[interface{}](settings)

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
	DigestMatches   bool        `json:"digest_matches"`
	ActualDigestHex string      `json:"actual_digest_hex,omitempty"`
	Destination     string      `json:"destination,omitempty"`
	Simulation      interface{} `json:"simulation,omitempty"`    // raw simulation result
	CalldataRisk    interface{} `json:"calldata_risk,omitempty"` // heuristic risk
	Error           string      `json:"error,omitempty"`
}

// SimulateTransaction calls the internal ika-backend simulate endpoint with circuit breaker.
// Returns the response (as map[string]interface{} to match the interface contract) or error.
func (c *IkaSimulateClientImpl) SimulateTransaction(ctx context.Context, req interface{}) (interface{}, error) {
	// Convert req to the proper typed request (caller passes a map, we convert it).
	var simReq SimulateTransactionRequest
	if reqMap, ok := req.(map[string]interface{}); ok {
		// Marshal and unmarshal to convert map to typed struct.
		data, _ := json.Marshal(reqMap)
		if err := json.Unmarshal(data, &simReq); err != nil {
			return nil, fmt.Errorf("invalid request format: %w", err)
		}
	} else {
		return nil, fmt.Errorf("request must be map[string]interface{}")
	}

	// Use circuit breaker to protect the HTTP call.
	result, err := c.breaker.Execute(func() (interface{}, error) {
		return c.simulateInternal(ctx, &simReq)
	})

	if err != nil {
		return nil, err
	}

	return result, nil
}

// simulateInternal performs the actual HTTP call without circuit breaker.
func (c *IkaSimulateClientImpl) simulateInternal(ctx context.Context, req *SimulateTransactionRequest) (interface{}, error) {
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

	// Return response as map for interface{} compatibility.
	var result map[string]interface{}
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, fmt.Errorf("convert response to map: %w", err)
	}

	return result, nil
}
