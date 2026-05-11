// Package mcp implements a minimal MCP (Model Context Protocol) endpoint
// for the gateway. The transport is JSON-RPC over HTTP POST. SSE
// streaming is not implemented yet — the structure is in place to add
// it later without changing tool authoring.
//
// Spec reference: https://modelcontextprotocol.io/specification
package mcp

import "encoding/json"

const ProtocolVersion = "2025-03-26"

// JSON-RPC envelopes.
type rpcRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    any    `json:"data,omitempty"`
}

type rpcResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Result  any             `json:"result,omitempty"`
	Error   *rpcError       `json:"error,omitempty"`
}

const (
	rpcParseError     = -32700
	rpcInvalidRequest = -32600
	rpcMethodNotFound = -32601
	rpcInvalidParams  = -32602
	rpcInternalError  = -32603
)

// initializeResult is sent in response to initialize. Instructions is an
// optional, free-form hint clients pass to the model — Andromeda uses it
// to state up front that the server is gas-sponsored and custody-free so
// the model doesn't stall asking the user for fee-payer keypairs etc.
type initializeResult struct {
	ProtocolVersion string         `json:"protocolVersion"`
	Capabilities    map[string]any `json:"capabilities"`
	ServerInfo      map[string]any `json:"serverInfo"`
	Instructions    string         `json:"instructions,omitempty"`
}

// Tool describes one MCP tool. Annotations follow the MCP spec hints
// (readOnlyHint, destructiveHint, idempotentHint, openWorldHint) so
// AI clients can rank / batch / dedupe tool calls without inspecting
// route semantics out-of-band.
type Tool struct {
	Name        string           `json:"name"`
	Description string           `json:"description"`
	InputSchema map[string]any   `json:"inputSchema"`
	Annotations *ToolAnnotations `json:"annotations,omitempty"`
}

// ToolAnnotations are advisory hints — the gateway still enforces auth,
// quota and rate limits regardless of what the client claims.
type ToolAnnotations struct {
	ReadOnlyHint    bool `json:"readOnlyHint,omitempty"`
	DestructiveHint bool `json:"destructiveHint,omitempty"`
	IdempotentHint  bool `json:"idempotentHint,omitempty"`
	// OpenWorldHint flags tools that interact with the network /
	// external systems. Always true for our MCP tools — they all
	// proxy to ika or encrypt engines.
	OpenWorldHint bool `json:"openWorldHint,omitempty"`
}

type toolsListResult struct {
	Tools []Tool `json:"tools"`
}

type callToolParams struct {
	Name      string         `json:"name"`
	Arguments map[string]any `json:"arguments"`
}

type contentBlock struct {
	Type string `json:"type"`
	Text string `json:"text,omitempty"`
}

type toolCallResult struct {
	Content []contentBlock `json:"content"`
	IsError bool           `json:"isError,omitempty"`
}
