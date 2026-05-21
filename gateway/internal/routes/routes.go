// Package routes defines the catalogue of upstream routes that the
// gateway proxies. Each entry pins:
//
//   - a chi router pattern (Method + Path)
//   - the upstream engine to forward to
//   - a stable Key for pricing & analytics
//   - the path on the upstream (defaults to the same Path)
//   - a RateClass that decides which RPS bucket throttles the call
//
// Adding a new route only requires extending this list and (optionally)
// inserting a row into request_costs to override the default token cost.
package routes

import (
	"net/http"
	"strings"
)

const (
	UpstreamIka     = "ika"
	UpstreamEncrypt = "encrypt"
	// UpstreamLocal — gateway handles the route in-process. Used by
	// PolicyEngine v3 (`/v1/policy/*`) which builds Solana transactions
	// locally rather than proxying to an engine. Pairs with Route.Local.
	UpstreamLocal = "local"
)

// Rate-limit classes. The middleware enforces a separate sliding window
// per class so a flood of cheap reads never starves the (much smaller)
// transactions bucket.
const (
	// RateClassRead — T1 cost: GETs, POST reads (challenge, preview,
	// ciphertext/read). Cheap, can sustain high RPS.
	RateClassRead = "read"
	// RateClassTx — T2-T5 cost: prepares, submits, signing, recovery,
	// future-sign. The MPC engines are sensitive here.
	RateClassTx = "tx"
)

type Route struct {
	Method       string
	Path         string
	Upstream     string
	UpstreamPath string // empty = same as Path
	Key          string
	// Idempotent indicates the route accepts the Idempotency-Key header.
	// True for any POST/PATCH/DELETE that creates side effects upstream.
	Idempotent bool
	// RequiresIdempotencyKey, when true, makes the `Idempotency-Key`
	// header MANDATORY: the middleware rejects requests without it with
	// 400 `missing_idempotency_key`. Use for highly-destructive mutating
	// routes (init, add/update/remove rules, pause/resume/revoke,
	// request-signature submit, recovery primary/submit, DKG submit,
	// future-sign submit). Implies Idempotent=true.
	RequiresIdempotencyKey bool
	// RateClass decides which bucket of the per-API-key rate limiter
	// gates the call. Defaults to "tx" if left empty.
	RateClass string
	// TimeoutSeconds overrides the global UPSTREAM_TIMEOUT_SECONDS.
	// 0 = use global. Heavy MPC operations (DKG, sign, presign,
	// future-sign, quorum finalize) need more wall-clock than typical
	// REST calls — set this per-route rather than raising the global.
	TimeoutSeconds int
	// DeprecatedAt, when set, marks the route as scheduled for removal.
	// The middleware adds RFC 8594 `Sunset` and `Deprecation` headers
	// so clients see the change in their dashboards. Empty = active.
	DeprecatedAt string // ISO 8601, e.g. "2026-12-01T00:00:00Z"
	// SunsetAt names the date the route stops responding entirely.
	// Optional — when blank but DeprecatedAt is set, the route stays
	// callable indefinitely (just flagged deprecated).
	SunsetAt string
	// MaxBodyBytes, when > 0, caps the request body for this route at a
	// tighter limit than the global one (server.go applies an extra
	// `limitPayload`). Used by the OIDC routes (a staged `id_token` is
	// ≤ 4 KiB; an 8 KiB cap leaves slack without inviting payload DoS).
	MaxBodyBytes int64
	// Local, when true, means the gateway handles this route in-process
	// (no upstream proxy). Used for PolicyEngine v3 routes (`/v1/policy/*`)
	// that build Solana transactions locally. `registerProxyRoute` skips
	// Local routes; the locally-mounted service is responsible for the
	// actual handler. Catalogue entry still feeds pricing, metrics,
	// OpenAPI, and the MCP tool registry.
	Local bool
	// AdminScope, when true, requires the API key to hold ScopeAdmin
	// instead of the default `read`/`write` derived from RateClass.
	// Used for policy management, recovery config, future-sign triggers.
	AdminScope bool
}

// All catalogues every public route. Order does not matter — the
// gateway registers each one explicitly with chi.
//
// Convention: external paths mirror upstream paths verbatim so devs see a
// consistent surface. Use UpstreamPath only when an external alias is needed.
var All = []Route{
	// --- ika-backend (MPC engine) ---
	// dWallet creation = DKG (Distributed Key Generation)
	{Method: "POST", Path: "/v1/dwallet/dkg/prepare", Upstream: UpstreamIka, Key: "ika.dkg.prepare", RateClass: RateClassTx},
	{Method: "POST", Path: "/v1/dwallet/dkg/submit", Upstream: UpstreamIka, Key: "ika.dkg.submit", Idempotent: true, RequiresIdempotencyKey: true, RateClass: RateClassTx, TimeoutSeconds: 120},
	{Method: "GET", Path: "/v1/dwallet/presigns/{userPubkey}", Upstream: UpstreamIka, Key: "ika.presigns.list", RateClass: RateClassRead},

	// High-level, tenant-scoped dWallet ops (option A2): Andromeda does the
	// client side; the tenant only supplies a passphrase. These auto-register
	// as the MCP tools `create_dwallet` / `transfer_ownership` / `presign` /
	// `sign_message`.
	//
	// F11b-Phase4b SUNSET (2026-05-15): `/v1/dwallet/approve` and
	// `/v1/dwallet/admin/add-member` are retired. Message authorisation moved
	// to the PolicyEngine v3 surface at `/v1/policy/recover-as-primary/*`;
	// quorum-member management moved to `/v1/policy/rules/{ruleIndex}/items/add/*`.
	{Method: "POST", Path: "/v1/dwallet/create", Upstream: UpstreamIka, Key: "ika.dwallet.create", Idempotent: true, RateClass: RateClassTx, TimeoutSeconds: 120},
	{Method: "POST", Path: "/v1/dwallet/transfer-ownership", Upstream: UpstreamIka, Key: "ika.dwallet.transferOwnership", Idempotent: true, RateClass: RateClassTx, TimeoutSeconds: 90},
	{Method: "POST", Path: "/v1/dwallet/presign", Upstream: UpstreamIka, Key: "ika.dwallet.presign", Idempotent: true, RateClass: RateClassTx, TimeoutSeconds: 90},
	{Method: "POST", Path: "/v1/dwallet/sign", Upstream: UpstreamIka, Key: "ika.dwallet.sign", Idempotent: true, RateClass: RateClassTx, TimeoutSeconds: 90},

	// Signing
	{Method: "POST", Path: "/v1/dwallet/sign/submit", Upstream: UpstreamIka, Key: "ika.sign.submit", Idempotent: true, RequiresIdempotencyKey: true, RateClass: RateClassTx, TimeoutSeconds: 90},
	{Method: "POST", Path: "/v1/dwallet/presign/submit", Upstream: UpstreamIka, Key: "ika.presign.submit", Idempotent: true, RequiresIdempotencyKey: true, RateClass: RateClassTx, TimeoutSeconds: 90},
	{Method: "POST", Path: "/v1/dwallet/future-sign/submit", Upstream: UpstreamIka, Key: "ika.future-sign.submit", Idempotent: true, RequiresIdempotencyKey: true, RateClass: RateClassTx, TimeoutSeconds: 120},
	{Method: "POST", Path: "/v1/dwallet/future-sign/complete/submit", Upstream: UpstreamIka, Key: "ika.future-sign.complete.submit", Idempotent: true, RequiresIdempotencyKey: true, RateClass: RateClassTx, TimeoutSeconds: 120},

	// Share management
	{Method: "POST", Path: "/v1/dwallet/re-encrypt-share/submit", Upstream: UpstreamIka, Key: "ika.re-encrypt-share.submit", Idempotent: true, RateClass: RateClassTx},
	{Method: "POST", Path: "/v1/dwallet/make-share-public/submit", Upstream: UpstreamIka, Key: "ika.make-share-public.submit", Idempotent: true, RateClass: RateClassTx},

	// Login Social — pre-step: server picks not_after + nonce_randomness and
	// returns the canonical `oidc_nonce` (so the client carries no crypto-layout
	// code). Not idempotent — fresh randomness each call. The legacy
	// /v1/recovery/primary/oidc/* flow that consumed this is retired; the
	// PolicyEngine v3 OIDC successor (F9c) is gated on the `sol_big_mod_exp`
	// syscall and will reuse these read-only helpers when it lands.
	{Method: "POST", Path: "/v1/oidc/nonce", Upstream: UpstreamIka, Key: "ika.oidc.nonce", RateClass: RateClassRead, MaxBodyBytes: 1 << 10},
	// Login Social — obligatory server-side `id_token` pre-validation (JWKS) before staging.
	{Method: "POST", Path: "/v1/oidc/validate", Upstream: UpstreamIka, Key: "ika.oidc.validate", Idempotent: true, RateClass: RateClassRead, MaxBodyBytes: 8 << 10},

	// --- encrypt-backend (FHE engine) ---
	// Private transactions
	{Method: "POST", Path: "/v1/private-tx/submit", Upstream: UpstreamEncrypt, Key: "encrypt.private-tx.submit", Idempotent: true, RateClass: RateClassTx},
	{Method: "GET", Path: "/v1/private-tx/status/{signature}", Upstream: UpstreamEncrypt, Key: "encrypt.private-tx.status", RateClass: RateClassRead},

	// Ciphertexts
	{Method: "POST", Path: "/v1/ciphertext/create", Upstream: UpstreamEncrypt, Key: "encrypt.ciphertext.create", Idempotent: true, RateClass: RateClassTx},
	{Method: "POST", Path: "/v1/ciphertext/read", Upstream: UpstreamEncrypt, Key: "encrypt.ciphertext.read", RateClass: RateClassRead},
	{Method: "GET", Path: "/v1/ciphertext/account/{address}", Upstream: UpstreamEncrypt, Key: "encrypt.ciphertext.account.get", RateClass: RateClassRead},

	// Graph (FHE op pipelines)
	{Method: "POST", Path: "/v1/graph/execute/prepare", Upstream: UpstreamEncrypt, Key: "encrypt.graph.execute.prepare", Idempotent: true, RateClass: RateClassTx},
	{Method: "POST", Path: "/v1/graph/register/prepare", Upstream: UpstreamEncrypt, Key: "encrypt.graph.register.prepare", Idempotent: true, RateClass: RateClassTx},
	{Method: "POST", Path: "/v1/graph/execute-registered/prepare", Upstream: UpstreamEncrypt, Key: "encrypt.graph.execute-registered.prepare", Idempotent: true, RateClass: RateClassTx},
	{Method: "POST", Path: "/v1/graph/commit/prepare", Upstream: UpstreamEncrypt, Key: "encrypt.graph.commit.prepare", Idempotent: true, RateClass: RateClassTx},
	{Method: "POST", Path: "/v1/graph/submit", Upstream: UpstreamEncrypt, Key: "encrypt.graph.submit", Idempotent: true, RateClass: RateClassTx},
	{Method: "GET", Path: "/v1/graph/status/{signature}", Upstream: UpstreamEncrypt, Key: "encrypt.graph.status", RateClass: RateClassRead},
	{Method: "GET", Path: "/v1/graph/operations", Upstream: UpstreamEncrypt, Key: "encrypt.graph.operations.list", RateClass: RateClassRead},
	{Method: "POST", Path: "/v1/graph/operations/register-bytes", Upstream: UpstreamEncrypt, Key: "encrypt.graph.operations.register-bytes", Idempotent: true, RateClass: RateClassTx},

	// DSL
	{Method: "GET", Path: "/v1/dsl/types", Upstream: UpstreamEncrypt, Key: "encrypt.dsl.types", RateClass: RateClassRead},
	{Method: "POST", Path: "/v1/dsl/op/prepare", Upstream: UpstreamEncrypt, Key: "encrypt.dsl.op.prepare", Idempotent: true, RateClass: RateClassTx},

	// Decrypt
	{Method: "POST", Path: "/v1/decrypt/request/prepare", Upstream: UpstreamEncrypt, Key: "encrypt.decrypt.request.prepare", Idempotent: true, RateClass: RateClassTx},
	{Method: "GET", Path: "/v1/decrypt/poll/{account}", Upstream: UpstreamEncrypt, Key: "encrypt.decrypt.poll", RateClass: RateClassRead},

	// NEK
	{Method: "GET", Path: "/v1/nek/current", Upstream: UpstreamEncrypt, Key: "encrypt.nek.current", RateClass: RateClassRead},

	// Events
	{Method: "POST", Path: "/v1/events/emit/prepare", Upstream: UpstreamEncrypt, Key: "encrypt.events.emit.prepare", Idempotent: true, RateClass: RateClassTx},
	{Method: "GET", Path: "/v1/events/by-signature/{signature}", Upstream: UpstreamEncrypt, Key: "encrypt.events.by-signature", RateClass: RateClassRead},

	// Wallet
	{Method: "POST", Path: "/v1/wallet/balance/init", Upstream: UpstreamEncrypt, Key: "encrypt.wallet.balance.init", Idempotent: true, RateClass: RateClassTx},

	// Authority
	{Method: "POST", Path: "/v1/authority/add/prepare", Upstream: UpstreamEncrypt, Key: "encrypt.authority.add.prepare", RateClass: RateClassTx},
	{Method: "POST", Path: "/v1/authority/remove/prepare", Upstream: UpstreamEncrypt, Key: "encrypt.authority.remove.prepare", RateClass: RateClassTx},
	{Method: "POST", Path: "/v1/authority/register-nek/prepare", Upstream: UpstreamEncrypt, Key: "encrypt.authority.register-nek.prepare", RateClass: RateClassTx},

	// Fees
	{Method: "POST", Path: "/v1/fees/deposit/create/prepare", Upstream: UpstreamEncrypt, Key: "encrypt.fees.deposit.create.prepare", RateClass: RateClassTx},
	{Method: "POST", Path: "/v1/fees/deposit/top-up/prepare", Upstream: UpstreamEncrypt, Key: "encrypt.fees.deposit.top-up.prepare", RateClass: RateClassTx},
	{Method: "POST", Path: "/v1/fees/deposit/withdraw/prepare", Upstream: UpstreamEncrypt, Key: "encrypt.fees.deposit.withdraw.prepare", RateClass: RateClassTx},
	{Method: "POST", Path: "/v1/fees/deposit/request-withdraw/prepare", Upstream: UpstreamEncrypt, Key: "encrypt.fees.deposit.request-withdraw.prepare", RateClass: RateClassTx},
	{Method: "POST", Path: "/v1/fees/deposit/reimburse/prepare", Upstream: UpstreamEncrypt, Key: "encrypt.fees.deposit.reimburse.prepare", RateClass: RateClassTx},
	{Method: "POST", Path: "/v1/fees/config/update/prepare", Upstream: UpstreamEncrypt, Key: "encrypt.fees.config.update.prepare", RateClass: RateClassTx},

	// Ownership
	{Method: "POST", Path: "/v1/ownership/transfer/prepare", Upstream: UpstreamEncrypt, Key: "encrypt.ownership.transfer.prepare", RateClass: RateClassTx},
	{Method: "POST", Path: "/v1/ownership/copy/prepare", Upstream: UpstreamEncrypt, Key: "encrypt.ownership.copy.prepare", RateClass: RateClassTx},
	{Method: "POST", Path: "/v1/ownership/make-public/prepare", Upstream: UpstreamEncrypt, Key: "encrypt.ownership.make-public.prepare", RateClass: RateClassTx},

	// --- PolicyEngine v3 (local; Solana txs built in-process) -----------------
	// Each entry is `Local: true`, so registerProxyRoute() skips it; the
	// PolicyEngine service mounts its own chi router under the same paths
	// (see internal/policy/routes.go MountRoutes). Catalogue entries exist
	// so pricing, metrics, OpenAPI 3.1 generator and the MCP tool registry
	// see PolicyEngine just like proxied routes. Idempotency is MANDATORY
	// on every admin submit (init, add/update/remove rule, pause, resume,
	// revoke, request-signature submit) so dashboard retries can't
	// double-mutate the engine.
	{Method: "GET", Path: "/v1/policy/{dwallet}", Upstream: UpstreamLocal, Local: true, Key: "policy.engine.read", RateClass: RateClassRead},
	{Method: "POST", Path: "/v1/policy/init/challenge", Upstream: UpstreamLocal, Local: true, Key: "policy.engine.init.challenge", AdminScope: true, RateClass: RateClassRead},
	{Method: "POST", Path: "/v1/policy/init/submit", Upstream: UpstreamLocal, Local: true, Key: "policy.engine.init.submit", Idempotent: true, RequiresIdempotencyKey: true, AdminScope: true, RateClass: RateClassTx, TimeoutSeconds: 60},
	{Method: "POST", Path: "/v1/policy/rules/add/challenge", Upstream: UpstreamLocal, Local: true, Key: "policy.engine.rules.add.challenge", AdminScope: true, RateClass: RateClassRead},
	{Method: "POST", Path: "/v1/policy/rules/add/submit", Upstream: UpstreamLocal, Local: true, Key: "policy.engine.rules.add.submit", Idempotent: true, RequiresIdempotencyKey: true, AdminScope: true, RateClass: RateClassTx},
	{Method: "POST", Path: "/v1/policy/rules/{ruleIndex}/items/add/challenge", Upstream: UpstreamLocal, Local: true, Key: "policy.engine.rules.items.add.challenge", AdminScope: true, RateClass: RateClassRead},
	{Method: "POST", Path: "/v1/policy/rules/{ruleIndex}/items/add/submit", Upstream: UpstreamLocal, Local: true, Key: "policy.engine.rules.items.add.submit", Idempotent: true, RequiresIdempotencyKey: true, AdminScope: true, RateClass: RateClassTx},
	{Method: "POST", Path: "/v1/policy/request-signature/challenge", Upstream: UpstreamLocal, Local: true, Key: "policy.engine.request-signature.challenge", RateClass: RateClassRead},
	{Method: "POST", Path: "/v1/policy/request-signature/submit", Upstream: UpstreamLocal, Local: true, Key: "policy.engine.request-signature.submit", Idempotent: true, RequiresIdempotencyKey: true, RateClass: RateClassTx, TimeoutSeconds: 60},
	// F11b-Phase1 — recover_as_primary. NOT AdminScope: the primary owner is
	// the user; gateway is just gas sponsor + tx relayer.
	{Method: "POST", Path: "/v1/policy/recover-as-primary/challenge", Upstream: UpstreamLocal, Local: true, Key: "policy.engine.recover-as-primary.challenge", RateClass: RateClassRead},
	{Method: "POST", Path: "/v1/policy/recover-as-primary/submit", Upstream: UpstreamLocal, Local: true, Key: "policy.engine.recover-as-primary.submit", Idempotent: true, RequiresIdempotencyKey: true, RateClass: RateClassTx, TimeoutSeconds: 60},
	// F11b-Phase2 — quorum_session_*. Same scope semantics as Phase1.
	{Method: "POST", Path: "/v1/policy/quorum/session/open/challenge", Upstream: UpstreamLocal, Local: true, Key: "policy.engine.quorum.open.challenge", RateClass: RateClassRead},
	{Method: "POST", Path: "/v1/policy/quorum/session/open/submit", Upstream: UpstreamLocal, Local: true, Key: "policy.engine.quorum.open.submit", Idempotent: true, RequiresIdempotencyKey: true, RateClass: RateClassTx, TimeoutSeconds: 60},
	{Method: "POST", Path: "/v1/policy/quorum/session/contribute/challenge", Upstream: UpstreamLocal, Local: true, Key: "policy.engine.quorum.contribute.challenge", RateClass: RateClassRead},
	{Method: "POST", Path: "/v1/policy/quorum/session/contribute/submit", Upstream: UpstreamLocal, Local: true, Key: "policy.engine.quorum.contribute.submit", Idempotent: true, RequiresIdempotencyKey: true, RateClass: RateClassTx, TimeoutSeconds: 60},
	{Method: "POST", Path: "/v1/policy/quorum/session/finalize", Upstream: UpstreamLocal, Local: true, Key: "policy.engine.quorum.finalize", Idempotent: true, RequiresIdempotencyKey: true, RateClass: RateClassTx, TimeoutSeconds: 120},
	{Method: "POST", Path: "/v1/policy/quorum/session/close", Upstream: UpstreamLocal, Local: true, Key: "policy.engine.quorum.close", Idempotent: true, RequiresIdempotencyKey: true, RateClass: RateClassTx},
	// F11b-Phase2 — passkey_session_*.
	{Method: "POST", Path: "/v1/policy/passkey/session/open/challenge", Upstream: UpstreamLocal, Local: true, Key: "policy.engine.passkey.open.challenge", RateClass: RateClassRead, MaxBodyBytes: 4 << 10},
	{Method: "POST", Path: "/v1/policy/passkey/session/open/submit", Upstream: UpstreamLocal, Local: true, Key: "policy.engine.passkey.open.submit", Idempotent: true, RequiresIdempotencyKey: true, RateClass: RateClassTx, TimeoutSeconds: 60, MaxBodyBytes: 8 << 10},
	{Method: "POST", Path: "/v1/policy/passkey/use/challenge", Upstream: UpstreamLocal, Local: true, Key: "policy.engine.passkey.use.challenge", RateClass: RateClassRead},
	{Method: "POST", Path: "/v1/policy/passkey/use/submit", Upstream: UpstreamLocal, Local: true, Key: "policy.engine.passkey.use.submit", Idempotent: true, RequiresIdempotencyKey: true, RateClass: RateClassTx, TimeoutSeconds: 60},
	{Method: "POST", Path: "/v1/policy/passkey/session/close", Upstream: UpstreamLocal, Local: true, Key: "policy.engine.passkey.close", Idempotent: true, RequiresIdempotencyKey: true, RateClass: RateClassTx},

	// --- Oracle price triggers (local; F7.5 managed Pyth keeper) --------------
	// `Local: true`, so registerProxyRoute() skips them; the oraclemonitor
	// service mounts the handlers under the same paths (internal/oraclemonitor
	// MountRoutes), gated by the tenant API key + ScopeWrite. Catalogue entries
	// exist so pricing, OpenAPI 3.1 and the MCP tool registry see the
	// price-trigger surface like any other route. Arming a trigger schedules a
	// gas-sponsored request_signature when the price band holds; idempotency is
	// mandatory on arm/cancel so a client retry can't double-arm.
	{Method: "POST", Path: "/v1/oracle/triggers", Upstream: UpstreamLocal, Local: true, Key: "oracle.triggers.arm", Idempotent: true, RequiresIdempotencyKey: true, RateClass: RateClassTx},
	{Method: "GET", Path: "/v1/oracle/triggers", Upstream: UpstreamLocal, Local: true, Key: "oracle.triggers.list", RateClass: RateClassRead},
	{Method: "GET", Path: "/v1/oracle/triggers/{id}", Upstream: UpstreamLocal, Local: true, Key: "oracle.triggers.get", RateClass: RateClassRead},
	{Method: "DELETE", Path: "/v1/oracle/triggers/{id}", Upstream: UpstreamLocal, Local: true, Key: "oracle.triggers.cancel", Idempotent: true, RequiresIdempotencyKey: true, RateClass: RateClassTx},
}

// EffectiveRateClass returns r.RateClass with a default of "tx" when
// the route was registered without an explicit class — keeps newer
// routes safe by default.
func (r Route) EffectiveRateClass() string {
	if r.RateClass == "" {
		return RateClassTx
	}
	return r.RateClass
}

// RequiredScope maps a route's RateClass to the API-key scope the
// caller must hold. Read-class routes need "read", everything else
// needs "write". Routes marked `AdminScope` require the explicit
// "admin" scope regardless of class — used for policy management,
// recovery config, future-sign triggers, audit reads.
func (r Route) RequiredScope() string {
	if r.AdminScope {
		return "admin"
	}
	if r.EffectiveRateClass() == RateClassRead {
		return "read"
	}
	return "write"
}

func (r Route) TargetPath() string {
	if r.UpstreamPath != "" {
		return r.UpstreamPath
	}
	return r.Path
}

// RequiresIdempotencyKeyForRequest reports whether the request's path
// matches a catalogue entry with `RequiresIdempotencyKey: true`. Matches
// chi's `{param}` placeholders by splitting on `/` and treating any
// catalogue segment starting with `{` as a wildcard. Wired into the
// idempotency middleware so destructive submits hard-fail with 400 when
// the client forgets to send the header.
func RequiresIdempotencyKeyForRequest(req *http.Request) bool {
	if req == nil {
		return false
	}
	method := req.Method
	reqSegs := splitPath(req.URL.Path)
	for _, rt := range All {
		if !rt.RequiresIdempotencyKey {
			continue
		}
		if rt.Method != method {
			continue
		}
		if pathMatchesPattern(rt.Path, reqSegs) {
			return true
		}
	}
	return false
}

func splitPath(p string) []string {
	p = strings.Trim(p, "/")
	if p == "" {
		return nil
	}
	return strings.Split(p, "/")
}

func pathMatchesPattern(pattern string, reqSegs []string) bool {
	patSegs := splitPath(pattern)
	if len(patSegs) != len(reqSegs) {
		return false
	}
	for i, p := range patSegs {
		if strings.HasPrefix(p, "{") && strings.HasSuffix(p, "}") {
			continue
		}
		if p != reqSegs[i] {
			return false
		}
	}
	return true
}
