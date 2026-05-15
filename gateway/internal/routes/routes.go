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

const (
	UpstreamIka     = "ika"
	UpstreamEncrypt = "encrypt"
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
	{Method: "POST", Path: "/v1/dwallet/dkg/submit", Upstream: UpstreamIka, Key: "ika.dkg.submit", Idempotent: true, RateClass: RateClassTx, TimeoutSeconds: 120},
	{Method: "GET", Path: "/v1/dwallet/presigns/{userPubkey}", Upstream: UpstreamIka, Key: "ika.presigns.list", RateClass: RateClassRead},

	// High-level, tenant-scoped dWallet ops (option A2): Andromeda does the
	// client side; the tenant only supplies a passphrase. These auto-register
	// as the MCP tools `create_dwallet` / `transfer_ownership` / `approve` /
	// `presign` / `sign_message`.
	{Method: "POST", Path: "/v1/dwallet/create", Upstream: UpstreamIka, Key: "ika.dwallet.create", Idempotent: true, RateClass: RateClassTx, TimeoutSeconds: 120},
	{Method: "POST", Path: "/v1/dwallet/transfer-ownership", Upstream: UpstreamIka, Key: "ika.dwallet.transferOwnership", Idempotent: true, RateClass: RateClassTx, TimeoutSeconds: 90},
	{Method: "POST", Path: "/v1/dwallet/approve", Upstream: UpstreamIka, Key: "ika.dwallet.approve", Idempotent: true, RateClass: RateClassTx, TimeoutSeconds: 90},
	// Passphrase-driven "add a quorum recovery member" — only for dWallets whose
	// policy primary owner is the server keystore key (the default). The engine
	// signs the on-chain admin challenge with the unwrapped keystore key and
	// submits, gas-sponsored — so an agent can add a member without an external
	// wallet on screen. External-primary policies use /v1/recovery/policy/admin/*.
	{Method: "POST", Path: "/v1/dwallet/admin/add-member", Upstream: UpstreamIka, Key: "ika.dwallet.adminAddMember", Idempotent: true, RateClass: RateClassTx, TimeoutSeconds: 90},
	{Method: "POST", Path: "/v1/dwallet/presign", Upstream: UpstreamIka, Key: "ika.dwallet.presign", Idempotent: true, RateClass: RateClassTx, TimeoutSeconds: 90},
	{Method: "POST", Path: "/v1/dwallet/sign", Upstream: UpstreamIka, Key: "ika.dwallet.sign", Idempotent: true, RateClass: RateClassTx, TimeoutSeconds: 90},

	// Signing
	{Method: "POST", Path: "/v1/dwallet/sign/submit", Upstream: UpstreamIka, Key: "ika.sign.submit", Idempotent: true, RateClass: RateClassTx, TimeoutSeconds: 90},
	{Method: "POST", Path: "/v1/dwallet/presign/submit", Upstream: UpstreamIka, Key: "ika.presign.submit", Idempotent: true, RateClass: RateClassTx, TimeoutSeconds: 90},
	{Method: "POST", Path: "/v1/dwallet/future-sign/submit", Upstream: UpstreamIka, Key: "ika.future-sign.submit", Idempotent: true, RateClass: RateClassTx, TimeoutSeconds: 120},
	{Method: "POST", Path: "/v1/dwallet/future-sign/complete/submit", Upstream: UpstreamIka, Key: "ika.future-sign.complete.submit", Idempotent: true, RateClass: RateClassTx, TimeoutSeconds: 120},

	// Share management
	{Method: "POST", Path: "/v1/dwallet/re-encrypt-share/submit", Upstream: UpstreamIka, Key: "ika.re-encrypt-share.submit", Idempotent: true, RateClass: RateClassTx},
	{Method: "POST", Path: "/v1/dwallet/make-share-public/submit", Upstream: UpstreamIka, Key: "ika.make-share-public.submit", Idempotent: true, RateClass: RateClassTx},

	// Recovery — discovery (proves ownership of an external wallet; gated by appId)
	{Method: "POST", Path: "/v1/recovery/challenge", Upstream: UpstreamIka, Key: "ika.recovery.challenge", Idempotent: true, RateClass: RateClassRead},
	{Method: "POST", Path: "/v1/recovery/resolve", Upstream: UpstreamIka, Key: "ika.recovery.resolve", Idempotent: true, RateClass: RateClassTx},

	// Recovery — primary (RulesPolicy primary-owner bypass; single tx, challenge-based)
	{Method: "POST", Path: "/v1/recovery/primary/challenge", Upstream: UpstreamIka, Key: "ika.recovery.primary.challenge", Idempotent: true, RateClass: RateClassRead},
	{Method: "POST", Path: "/v1/recovery/primary/submit", Upstream: UpstreamIka, Key: "ika.recovery.primary.submit", Idempotent: true, RateClass: RateClassTx},

	// Recovery — quorum (M-of-N members; staged in a PDA, challenge-based)
	{Method: "POST", Path: "/v1/recovery/quorum/session/open/challenge", Upstream: UpstreamIka, Key: "ika.recovery.quorum.open.challenge", Idempotent: true, RateClass: RateClassRead},
	{Method: "POST", Path: "/v1/recovery/quorum/session/open", Upstream: UpstreamIka, Key: "ika.recovery.quorum.open", Idempotent: true, RateClass: RateClassTx},
	{Method: "POST", Path: "/v1/recovery/quorum/session/contribute/challenge", Upstream: UpstreamIka, Key: "ika.recovery.quorum.contribute.challenge", Idempotent: true, RateClass: RateClassRead},
	{Method: "POST", Path: "/v1/recovery/quorum/session/contribute", Upstream: UpstreamIka, Key: "ika.recovery.quorum.contribute", Idempotent: true, RateClass: RateClassTx},
	{Method: "POST", Path: "/v1/recovery/quorum/session/finalize", Upstream: UpstreamIka, Key: "ika.recovery.quorum.finalize", Idempotent: true, RateClass: RateClassTx, TimeoutSeconds: 120},
	{Method: "POST", Path: "/v1/recovery/quorum/session/close", Upstream: UpstreamIka, Key: "ika.recovery.quorum.close", Idempotent: true, RateClass: RateClassTx},
	{Method: "GET", Path: "/v1/recovery/quorum/session/{address}", Upstream: UpstreamIka, Key: "ika.recovery.quorum.get", RateClass: RateClassRead},

	// Recovery — policy (RulesPolicy on-chain config)
	{Method: "POST", Path: "/v1/recovery/policy/preview", Upstream: UpstreamIka, Key: "ika.recovery.policy.preview", RateClass: RateClassRead},
	{Method: "POST", Path: "/v1/recovery/policy/deploy", Upstream: UpstreamIka, Key: "ika.recovery.policy.deploy", Idempotent: true, RateClass: RateClassTx},
	{Method: "GET", Path: "/v1/recovery/policy/{dwalletAddress}", Upstream: UpstreamIka, Key: "ika.recovery.policy.get", RateClass: RateClassRead},
	{Method: "POST", Path: "/v1/recovery/policy/admin/challenge", Upstream: UpstreamIka, Key: "ika.recovery.policy.admin.challenge", Idempotent: true, RateClass: RateClassRead},
	{Method: "POST", Path: "/v1/recovery/policy/admin/submit", Upstream: UpstreamIka, Key: "ika.recovery.policy.admin.submit", Idempotent: true, RateClass: RateClassTx},
	{Method: "POST", Path: "/v1/recovery/policy/apply-pending", Upstream: UpstreamIka, Key: "ika.recovery.policy.apply-pending", Idempotent: true, RateClass: RateClassTx},

	// Recovery — Login Social (RulesPolicy OIDC primary; scheme = 4; loginsocial.md §6.1/§10).
	// A staged `id_token` (≤ 4 KiB) goes on-chain in a temp PDA, then the user
	// authorizes signatures with an ephemeral Ed25519 key. The JWT-bearing
	// routes get a dedicated 8 KiB body cap (MaxBodyBytes).
	{Method: "POST", Path: "/v1/recovery/primary/oidc/stage", Upstream: UpstreamIka, Key: "ika.recovery.primary.oidc.stage", Idempotent: true, RateClass: RateClassTx, TimeoutSeconds: 90, MaxBodyBytes: 8 << 10},
	{Method: "POST", Path: "/v1/recovery/primary/oidc/open/challenge", Upstream: UpstreamIka, Key: "ika.recovery.primary.oidc.open.challenge", Idempotent: true, RateClass: RateClassRead, MaxBodyBytes: 8 << 10},
	{Method: "POST", Path: "/v1/recovery/primary/oidc/open", Upstream: UpstreamIka, Key: "ika.recovery.primary.oidc.open", Idempotent: true, RateClass: RateClassTx, TimeoutSeconds: 90, MaxBodyBytes: 8 << 10},
	{Method: "POST", Path: "/v1/recovery/primary/oidc/use/challenge", Upstream: UpstreamIka, Key: "ika.recovery.primary.oidc.use.challenge", RateClass: RateClassRead},
	{Method: "POST", Path: "/v1/recovery/primary/oidc/use/submit", Upstream: UpstreamIka, Key: "ika.recovery.primary.oidc.use.submit", Idempotent: true, RateClass: RateClassTx, TimeoutSeconds: 90},
	{Method: "POST", Path: "/v1/recovery/primary/oidc/close", Upstream: UpstreamIka, Key: "ika.recovery.primary.oidc.close", Idempotent: true, RateClass: RateClassTx},
	{Method: "POST", Path: "/v1/recovery/primary/oidc/staging/close", Upstream: UpstreamIka, Key: "ika.recovery.primary.oidc.staging.close", Idempotent: true, RateClass: RateClassTx},

	// Login Social — pre-step: server picks not_after + nonce_randomness and
	// returns the canonical `oidc_nonce` (so the client carries no crypto-layout
	// code). Not idempotent — fresh randomness each call.
	{Method: "POST", Path: "/v1/oidc/nonce", Upstream: UpstreamIka, Key: "ika.oidc.nonce", RateClass: RateClassRead, MaxBodyBytes: 1 << 10},
	// Login Social — obligatory server-side `id_token` pre-validation (JWKS) before staging.
	{Method: "POST", Path: "/v1/oidc/validate", Upstream: UpstreamIka, Key: "ika.oidc.validate", Idempotent: true, RateClass: RateClassRead, MaxBodyBytes: 8 << 10},

	// Recovery — Passkey-PRF (RulesPolicy WebAuthn primary; scheme = 3 session-scoped;
	// PLAN_KEYSPRING_INTEGRATION_2026_05.md D1 Opção A). The user signs a
	// WebAuthn assertion at session open (Secp256r1 precompile validates it on-chain)
	// and per-use Ed25519 challenges with the session's ephemeral key. The on-chain
	// cap is 192 B for authData + 192 B for clientDataJSON (D13); 4 KiB body covers
	// both plus envelope. Credentials list/revoke + register-init/complete are
	// off-chain bookkeeping owned by ika-backend (D4) — gateway only reverse-proxies.
	{Method: "POST", Path: "/v1/recovery/primary/passkey/credentials/register-init", Upstream: UpstreamIka, Key: "ika.recovery.primary.passkey.credentials.register-init", Idempotent: true, RateClass: RateClassRead, MaxBodyBytes: 1 << 10},
	{Method: "POST", Path: "/v1/recovery/primary/passkey/credentials/register-complete", Upstream: UpstreamIka, Key: "ika.recovery.primary.passkey.credentials.register-complete", Idempotent: true, RateClass: RateClassTx, MaxBodyBytes: 4 << 10},
	{Method: "GET", Path: "/v1/recovery/primary/passkey/credentials", Upstream: UpstreamIka, Key: "ika.recovery.primary.passkey.credentials.list", RateClass: RateClassRead},
	{Method: "POST", Path: "/v1/recovery/primary/passkey/credentials/{id}/revoke", Upstream: UpstreamIka, Key: "ika.recovery.primary.passkey.credentials.revoke", Idempotent: true, RateClass: RateClassTx, MaxBodyBytes: 1 << 10},
	{Method: "POST", Path: "/v1/recovery/primary/passkey/open/challenge", Upstream: UpstreamIka, Key: "ika.recovery.primary.passkey.open.challenge", Idempotent: true, RateClass: RateClassRead, MaxBodyBytes: 2 << 10},
	{Method: "POST", Path: "/v1/recovery/primary/passkey/open", Upstream: UpstreamIka, Key: "ika.recovery.primary.passkey.open", Idempotent: true, RateClass: RateClassTx, TimeoutSeconds: 90, MaxBodyBytes: 4 << 10},
	{Method: "POST", Path: "/v1/recovery/primary/passkey/use/challenge", Upstream: UpstreamIka, Key: "ika.recovery.primary.passkey.use.challenge", RateClass: RateClassRead, MaxBodyBytes: 2 << 10},
	{Method: "POST", Path: "/v1/recovery/primary/passkey/use/submit", Upstream: UpstreamIka, Key: "ika.recovery.primary.passkey.use.submit", Idempotent: true, RateClass: RateClassTx, TimeoutSeconds: 90, MaxBodyBytes: 2 << 10},
	{Method: "POST", Path: "/v1/recovery/primary/passkey/close", Upstream: UpstreamIka, Key: "ika.recovery.primary.passkey.close", Idempotent: true, RateClass: RateClassTx, MaxBodyBytes: 1 << 10},
	{Method: "GET", Path: "/v1/recovery/primary/passkey/capabilities", Upstream: UpstreamIka, Key: "ika.recovery.primary.passkey.capabilities", RateClass: RateClassRead},

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
// needs "write". Admin features (webhooks, audit, policies, future-sign)
// require the explicit "admin" scope, applied at their own group.
func (r Route) RequiredScope() string {
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
