package openapi

// Extra describes one hand-listed endpoint that isn't proxied via
// routes.All — pricing/me/billing/gifts/webhooks/MCP/health.
type Extra struct {
	Path      string
	Method    string
	Operation Document
}

// extraEndpoints returns the first-party endpoints (not engine proxies)
// the gateway exposes. Keep this in sync with internal/api/server.go —
// when a new endpoint is added there, add a corresponding entry here.
func extraEndpoints() []Extra {
	return []Extra{
		// ---- Health ----
		{Path: "/health", Method: "GET", Operation: Document{
			"operationId": "healthLiveness",
			"summary":     "Liveness probe (always 200 if process up).",
			"tags":        []string{"health"},
			"security":    []Document{},
			"responses": Document{
				"200": Document{"description": "OK"},
			},
		}},
		{Path: "/health/ready", Method: "GET", Operation: Document{
			"operationId": "healthReadiness",
			"summary":     "Readiness probe with per-component breakdown.",
			"tags":        []string{"health"},
			"security":    []Document{},
			"responses": Document{
				"200": Document{"description": "All critical checks pass."},
				"503": errorResponse("Critical component (DB) failed."),
			},
		}},

		// ---- Pricing (public) ----
		{Path: "/v1/pricing", Method: "GET", Operation: Document{
			"operationId": "getPricingCatalog",
			"summary":     "Token cost per route + balcão rate.",
			"tags":        []string{"pricing"},
			"security":    []Document{},
			"responses":   simpleOKResponse(),
		}},
		{Path: "/v1/pricing/estimate", Method: "POST", Operation: Document{
			"operationId": "postPricingEstimate",
			"summary":     "Estimate total tokens for a planned workload.",
			"tags":        []string{"pricing"},
			"security":    []Document{},
			"requestBody": passthroughBody(),
			"responses":   simpleOKResponse(),
		}},

		// /v1/me/* and /v1/gifts/* moved to backend in M3 — they no
		// longer appear in the gateway's OpenAPI surface.

		// /v1/billing/* moved to backend in M1 — no longer in the
		// gateway's OpenAPI surface.

		// ---- Webhooks (per-tenant management) ----
		{Path: "/v1/webhooks/endpoints", Method: "GET", Operation: Document{
			"operationId": "listWebhookEndpoints",
			"summary":     "List webhook endpoints for the calling API key.",
			"tags":        []string{"webhooks"},
			"responses":   standardResponses(),
		}},
		{Path: "/v1/webhooks/endpoints", Method: "POST", Operation: Document{
			"operationId": "createWebhookEndpoint",
			"summary":     "Register a new webhook URL.",
			"tags":        []string{"webhooks"},
			"requestBody": passthroughBody(),
			"responses":   standardResponses(),
		}},
		{Path: "/v1/webhooks/deliveries", Method: "GET", Operation: Document{
			"operationId": "listWebhookDeliveries",
			"summary":     "List recent deliveries (filter by status / endpoint).",
			"tags":        []string{"webhooks"},
			"parameters": []Document{{
				"name": "status", "in": "query", "required": false,
				"schema": Document{"type": "string", "enum": []string{"pending", "delivered", "in_flight", "dead_letter"}},
			}},
			"responses": standardResponses(),
		}},

		// ---- MCP ----
		{Path: "/mcp", Method: "POST", Operation: Document{
			"operationId": "postMCPRPC",
			"summary":     "JSON-RPC over HTTP for MCP clients (initialize, tools/list, tools/call).",
			"tags":        []string{"mcp"},
			"requestBody": passthroughBody(),
			"responses": Document{
				"200": Document{"description": "JSON-RPC 2.0 response."},
				"401": errorResponse("Missing or invalid API key."),
				"402": errorResponse("Token quota exceeded for the current period."),
				"403": errorResponse("Scope missing or no active subscription."),
				"429": errorResponse("Rate limit exceeded."),
			},
		}},
		{Path: "/mcp", Method: "GET", Operation: Document{
			"operationId": "getMCPSSEStream",
			"summary":     "Open the SSE stream (text/event-stream). Sends keepalive every 15s.",
			"tags":        []string{"mcp"},
			"responses": Document{
				"200": Document{"description": "Stream open. Connection stays alive until closed by either side."},
			},
		}},
	}
}

// passthroughBody is the request body declaration used by every endpoint
// that accepts arbitrary JSON. We don't pin shapes — pricing.Estimate,
// gift redeem, etc are stable enough that consumers learn from the
// dashboard examples.
func passthroughBody() Document {
	return Document{
		"required": false,
		"content": Document{
			"application/json": Document{
				"schema": Document{"$ref": "#/components/schemas/PassthroughObject"},
			},
		},
	}
}

// simpleOKResponse is the slim variant for unauthenticated, no-error
// endpoints (pricing catalogue, plans, etc).
func simpleOKResponse() Document {
	return Document{
		"200": Document{
			"description": "Success",
			"content": Document{
				"application/json": Document{
					"schema": Document{"type": "object", "additionalProperties": true},
				},
			},
		},
	}
}
