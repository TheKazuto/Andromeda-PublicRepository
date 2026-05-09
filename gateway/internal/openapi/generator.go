// Package openapi assembles an OpenAPI 3.1 document from the gateway's
// route catalogue. The output is consumed by `/openapi.json` so SDK
// generators (openapi-generator-cli, openapi-typescript, etc) can fetch
// it directly from the deployment.
//
// Two route sources are merged:
//
//  1. Auto-discovered proxy routes from internal/routes.All.
//  2. Hand-listed first-party endpoints (pricing, me, gifts, billing,
//     webhooks meta) declared in `extras.go`. We can't auto-discover
//     these because they're chi-mounted handlers without a shared
//     catalogue.
//
// Body schemas are intentionally permissive (`additionalProperties: true`)
// — proxy routes forward the body verbatim to the upstream engine, and
// pinning a strict shape would couple the spec to ika/encrypt internals.
package openapi

import (
	"regexp"
	"sort"
	"strings"

	"github.com/shinkalabs/andromeda-gateway/internal/routes"
)

// Document is a JSON-marshalable map representing the OpenAPI spec.
// Using map[string]any rather than typed structs keeps the dependency
// surface zero (no kin-openapi or libopenapi) and makes incremental
// extensions trivial — most of OpenAPI is permissive nested maps.
type Document = map[string]any

// Generator assembles the document. Call Build() once at request time;
// the cost is small (sub-millisecond) so we don't bother caching.
type Generator struct {
	ServiceName  string
	ServiceVersion string
	BaseURL      string // production URL, e.g. https://gateway.shinkalabs.com
}

// Build returns the OpenAPI document. If g.BaseURL is empty, the spec
// is generated without a `servers` block — clients fall back to the
// host they fetched the spec from.
func (g Generator) Build() Document {
	doc := Document{
		"openapi": "3.1.0",
		"info":    g.info(),
		"paths":   g.paths(),
		"components": Document{
			"securitySchemes": g.securitySchemes(),
			"schemas":         g.schemas(),
		},
		"security": []Document{
			{"ApiKeyAuth": []string{}},
			{"BearerAuth": []string{}},
		},
		"tags": g.tags(),
	}
	if g.BaseURL != "" {
		doc["servers"] = []Document{
			{"url": g.BaseURL, "description": "Production"},
		}
	}
	return doc
}

func (g Generator) info() Document {
	return Document{
		"title":       g.ServiceName,
		"version":     g.ServiceVersion,
		"description": "Andromeda gateway — REST + MCP front for the ika-backend (MPC) and encrypt-backend (FHE) engines. All paid endpoints require X-Api-Key or Authorization: Bearer.",
		"contact":     Document{"name": "Shinka Labs", "email": "support@shinkalabs.com"},
	}
}

func (g Generator) securitySchemes() Document {
	return Document{
		"ApiKeyAuth": Document{
			"type": "apiKey",
			"in":   "header",
			"name": "X-Api-Key",
		},
		"BearerAuth": Document{
			"type":   "http",
			"scheme": "bearer",
			"description": "API key passed as Bearer token. Equivalent to X-Api-Key.",
		},
		"AdminToken": Document{
			"type": "apiKey",
			"in":   "header",
			"name": "X-Admin-Token",
		},
	}
}

func (g Generator) tags() []Document {
	return []Document{
		{"name": "ika", "description": "MPC engine: dWallet creation, signing, recovery, identity."},
		{"name": "encrypt", "description": "FHE engine: ciphertexts, graph execution, decrypt, NEK."},
		{"name": "pricing", "description": "Public pricing — plans, route costs, estimator."},
		{"name": "me", "description": "Authenticated user — balance and usage."},
		{"name": "gifts", "description": "Gift card preview, redeem, and Stripe checkout."},
		{"name": "billing", "description": "Subscription checkout, customer portal, overage."},
		{"name": "webhooks", "description": "Per-tenant webhook endpoints + delivery management."},
		{"name": "mcp", "description": "Model Context Protocol over JSON-RPC."},
		{"name": "health", "description": "Liveness and readiness probes."},
	}
}

// paths combines auto-generated proxy routes with the hand-listed
// extras into a single chi-pattern → method-operation map.
func (g Generator) paths() Document {
	out := Document{}

	for _, r := range routes.All {
		path := convertChiToOpenAPIPath(r.Path)
		op := operationForRoute(r)
		methodKey := strings.ToLower(r.Method)
		appendOperation(out, path, methodKey, op)
	}

	for _, extra := range extraEndpoints() {
		appendOperation(out, extra.Path, strings.ToLower(extra.Method), extra.Operation)
	}

	return out
}

// schemas declares the shared object shapes referenced by responses.
func (g Generator) schemas() Document {
	return Document{
		"Error": Document{
			"type": "object",
			"properties": Document{
				"error":  Document{"type": "string", "description": "Human-readable error message."},
				"code":   Document{"type": "string", "description": "Machine-readable error code (e.g. 'quota_exceeded')."},
				"detail": Document{"type": "string"},
			},
			"required": []string{"error"},
		},
		"PassthroughObject": Document{
			"type":                 "object",
			"description":          "Free-form JSON object forwarded verbatim to the upstream engine.",
			"additionalProperties": true,
		},
	}
}

func operationForRoute(r routes.Route) Document {
	op := Document{
		"operationId": operationID(r),
		"summary":     r.Method + " " + r.Path,
		"description": "Proxied to " + r.Upstream + "-backend. Cost in tokens is set per route — see /v1/pricing.",
		"tags":        []string{r.Upstream},
		"x-andromeda-rate-class": r.EffectiveRateClass(),
		"x-andromeda-idempotent": r.Idempotent,
		"parameters":             pathParameters(r.Path),
		"responses":              standardResponses(),
	}
	if r.Idempotent {
		op["parameters"] = append(op["parameters"].([]Document), idempotencyKeyHeader())
	}
	if methodAcceptsBody(r.Method) {
		op["requestBody"] = Document{
			"required": false,
			"content": Document{
				"application/json": Document{
					"schema": Document{"$ref": "#/components/schemas/PassthroughObject"},
				},
			},
		}
	}
	return op
}

// pathParameters extracts {placeholder} segments from a chi pattern and
// declares each as a required string path parameter.
var chiParamRE = regexp.MustCompile(`\{([a-zA-Z_][a-zA-Z0-9_]*)\}`)

func pathParameters(path string) []Document {
	matches := chiParamRE.FindAllStringSubmatch(path, -1)
	out := make([]Document, 0, len(matches))
	seen := map[string]bool{}
	for _, m := range matches {
		if len(m) < 2 || seen[m[1]] {
			continue
		}
		seen[m[1]] = true
		out = append(out, Document{
			"name":     m[1],
			"in":       "path",
			"required": true,
			"schema":   Document{"type": "string"},
		})
	}
	return out
}

func idempotencyKeyHeader() Document {
	return Document{
		"name":        "Idempotency-Key",
		"in":          "header",
		"required":    false,
		"schema":      Document{"type": "string"},
		"description": "Caller-provided key. Two requests with the same body and key replay the cached response.",
	}
}

// standardResponses is the set of status codes every authenticated route
// can return. Per-route nuances (402 quota, 429 rate, 503 circuit) are
// documented on each operation but the schemas are shared.
func standardResponses() Document {
	return Document{
		"200": Document{
			"description": "Success",
			"content": Document{
				"application/json": Document{
					"schema": Document{"type": "object", "additionalProperties": true},
				},
			},
		},
		"401": errorResponse("Missing or invalid API key."),
		"402": errorResponse("Token quota exceeded for the current period."),
		"403": errorResponse("Scope missing, IP not allowed, or no active subscription."),
		"413": errorResponse("Request body exceeds 25 MiB."),
		"429": errorResponse("Rate limit exceeded for this bucket."),
		"502": errorResponse("Upstream engine unavailable."),
		"503": errorResponse("Service temporarily unavailable (e.g. circuit breaker open)."),
	}
}

func errorResponse(desc string) Document {
	return Document{
		"description": desc,
		"content": Document{
			"application/json": Document{
				"schema": Document{"$ref": "#/components/schemas/Error"},
			},
		},
	}
}

// operationID derives a stable, OpenAPI-friendly id from the route's
// dotted key (`ika.sign.submit` → `ikaSignSubmit`).
func operationID(r routes.Route) string {
	parts := strings.Split(r.Key, ".")
	if len(parts) == 0 {
		return r.Key
	}
	out := strings.Builder{}
	for i, p := range parts {
		if p == "" {
			continue
		}
		// dashes become underscores then we capitalise per segment.
		p = strings.ReplaceAll(p, "-", "")
		if i == 0 {
			out.WriteString(p)
			continue
		}
		out.WriteString(strings.ToUpper(p[:1]))
		if len(p) > 1 {
			out.WriteString(p[1:])
		}
	}
	return out.String()
}

// convertChiToOpenAPIPath turns a chi pattern ("/v1/dwallet/{id}") into
// the OpenAPI form (the same — both use {curly} placeholders, so this
// is a no-op today but kept as a hook for divergence later).
func convertChiToOpenAPIPath(p string) string { return p }

// appendOperation merges into the path map, creating the per-path
// container on first reference.
func appendOperation(paths Document, path, method string, op Document) {
	pathMap, ok := paths[path].(Document)
	if !ok {
		pathMap = Document{}
		paths[path] = pathMap
	}
	pathMap[method] = op
}

func methodAcceptsBody(method string) bool {
	switch strings.ToUpper(method) {
	case "POST", "PUT", "PATCH", "DELETE":
		return true
	}
	return false
}

// SortedPathKeys returns paths sorted alphabetically — handy for tests
// or any consumer that wants a deterministic ordering of the spec.
func SortedPathKeys(doc Document) []string {
	paths, _ := doc["paths"].(Document)
	keys := make([]string, 0, len(paths))
	for k := range paths {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
