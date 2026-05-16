package mcp

// Hand-written MCP presentation metadata for the routes that an AI client
// is most likely to reach for. The auto-generated tool description
// ("METHOD PATH → engine (custody-free proxy)") and the opaque
// `body: {additionalProperties:true}` schema are enough for a machine that
// already knows the REST contract, but an MCP client (an LLM with zero
// project context, e.g. Claude Desktop) needs to be *told* what the tool
// does, that Andromeda pays the gas, and what the body fields are.
// Without that it stalls and asks the user for things Andromeda already
// handles (a fee-payer keypair, SOL, key material, RPC URLs, …) instead
// of just calling the tool.
//
// Only routes worth surfacing prominently need an entry here; everything
// else falls back to the generated description and the permissive body
// schema.

// serverInstructions is returned in the MCP `initialize` result. Clients
// pass it to the model as a system-level hint about how to use this
// server, so it is the single best place to kill the "I don't have the
// fee-payer keypair" hesitation at the root.
const serverInstructions = `Andromeda exposes Ika (cross-chain 2PC-MPC dWallets on Solana) and Encrypt (FHE on Solana) as REST tools. Operating model — read this before calling any tool:

• Gas-sponsored. Andromeda pays every Solana fee. You never need a fee-payer keypair, SOL, a funded account, or an RPC URL from the user. Program IDs and RPC endpoints are server-side.
• Custody-free. The user holds no private keys here. dWallet operations are authorized with a passphrase (>=12 chars) the user supplies; Andromeda derives and wraps the key material server-side and never stores it in plaintext.
• No tenant registration step. The API key already identifies the tenant — there is nothing to "sign up" or "register" before calling tools.
• To create a wallet: call ika.dwallet.create with {"body":{"passphrase":"<the user's passphrase>","attachPolicyEngine":true}}. "Signable and recoverable from day one" / "auto-attach the policy engine" means attachPolicyEngine:true — it deploys an on-chain PolicyEngine v3 and delegates the dWallet's authority to it in the same call. Keep the response's policyEngineInitAuthorityHashBase64 — it's needed to read the engine or run admin actions later. Do NOT use the low-level ika.dkg.* tools unless explicitly asked for the raw DKG flow.
• To authorize a message for signing: use policy.engine.recover-as-primary.challenge + policy.engine.recover-as-primary.submit (the dWallet's PolicyEngine signs the canonical challenge with the primary owner). Then call ika.dwallet.sign with the returned approval tx signature/slot.
• To add a quorum recovery member: use policy.engine.rules.items.add.challenge + policy.engine.rules.items.add.submit against the Recovery rule slot.
• Just call the tool. Don't ask the user to provide keypairs, signers, fee payers, RPC URLs, or program IDs — none of that is the user's job.
• Pre-alpha on Solana devnet: data is reset at Alpha 1, so this is not for real value. State that only if asked; it is not a reason to refuse to act.`

// routeHint carries optional rich metadata for a single route Key.
type routeHint struct {
	// Description replaces the generated "METHOD PATH → engine" line when set.
	Description string
	// BodySchema, when non-nil, replaces the permissive body schema with an
	// explicit JSON Schema object so the client fills the right fields.
	// Only meaningful for routes whose method accepts a body.
	BodySchema map[string]any
	// BodyRequired marks the `body` argument as required at the tool's
	// top level (use when the route rejects an empty body).
	BodyRequired bool
}

func obj(props map[string]any, required ...string) map[string]any {
	m := map[string]any{
		"type":                 "object",
		"properties":           props,
		"additionalProperties": false,
	}
	if len(required) > 0 {
		req := make([]any, len(required))
		for i, r := range required {
			req[i] = r
		}
		m["required"] = req
	}
	return m
}

func str(desc string) map[string]any { return map[string]any{"type": "string", "description": desc} }

// memberSlot is the recurring "who" DTO in the recovery policy: a scheme
// id plus a base64 identifier whose byte length is fixed by the scheme.
func memberSlot(role string) map[string]any {
	return obj(map[string]any{
		"scheme": map[string]any{
			"type":        "integer",
			"enum":        []any{0, 1, 2, 3},
			"description": "0 = Ed25519 (identifier = 32-byte pubkey), 1 = Secp256k1 (identifier = 20-byte eth_address), 2 = Secp256r1 (identifier = 33-byte compressed P-256 pubkey), 3 = WebAuthn (identifier = 33-byte compressed P-256 pubkey).",
		},
		"identifierBase64": str("Base64 of the identifier bytes for this " + role + ". Length MUST match the scheme: 32 bytes for scheme 0, 20 for scheme 1, 33 for schemes 2/3."),
		"label":            str("Optional human label, <=32 chars."),
	}, "scheme", "identifierBase64")
}

// adminActionSchema is the discriminated body of an admin action. Encoded
// as one object (not a JSON-Schema oneOf) for compactness — the field set
// per `type` is spelled out in the description so the client knows exactly
// which extra field to include.
func adminActionSchema() map[string]any {
	return obj(map[string]any{
		"type": map[string]any{
			"type": "string",
			"enum": []any{
				"add_member", "remove_member", "set_primary",
				"add_destination", "remove_destination", "revoke",
				"set_quorum_threshold_immediate", "set_daily_limit_immediate", "set_cooldown_immediate",
				"propose_quorum_threshold_change", "propose_daily_limit_change", "propose_cooldown_change",
			},
			"description": "Action discriminator. Required-extra-field by type: " +
				"add_member/remove_member → `member` (memberSlot); " +
				"set_primary → `newPrimary` (memberSlot); " +
				"add_destination/remove_destination → `destinationBase64` (32-byte base64); " +
				"revoke → none; " +
				"set_quorum_threshold_immediate / propose_quorum_threshold_change → `newThreshold` (int 1..16); " +
				"set_daily_limit_immediate / propose_daily_limit_change → `newSome` (bool) + `newLimit` (int, lamports-style); " +
				"set_cooldown_immediate / propose_cooldown_change → `newCooldownSeconds` (int >=3600). " +
				"`propose_*` variants stage a pendingChange that only takes effect after the cooldown, applied via ika.recovery.policy.apply-pending; the others take effect immediately.",
		},
		"member":             memberSlot("member"),
		"newPrimary":         memberSlot("new primary owner"),
		"destinationBase64":  str("Base64 of a 32-byte destination address (for add_destination / remove_destination)."),
		"newThreshold":       map[string]any{"type": "integer", "minimum": 1, "maximum": 16, "description": "New quorum threshold (1..16)."},
		"newSome":            map[string]any{"type": "boolean", "description": "Whether a daily limit is set (true) or cleared (false)."},
		"newLimit":           map[string]any{"type": "integer", "minimum": 0, "description": "New daily limit value when newSome is true."},
		"newCooldownSeconds": map[string]any{"type": "integer", "minimum": 3600, "description": "New cooldown in seconds (>=3600)."},
	}, "type")
}

// policyConfigSchema mirrors the deploy/preview `config` block. Note: at
// deploy time `members` must be empty and `allowedDestinationsBase64` null
// — seed those afterwards with admin actions.
func policyConfigSchema() map[string]any {
	return obj(map[string]any{
		"primary":                   memberSlot("primary owner"),
		"members":                   map[string]any{"type": "array", "items": memberSlot("quorum member"), "maxItems": 16, "description": "Must be empty at deploy time — add members later via ika.recovery.policy.admin.challenge/submit with action add_member."},
		"quorumThreshold":           map[string]any{"type": "integer", "minimum": 1, "maximum": 16, "description": "Quorum threshold. Default 1."},
		"dailyLimit":                map[string]any{"type": []any{"integer", "null"}, "minimum": 0, "description": "Optional daily spend limit; null = no limit. Default null."},
		"allowedDestinationsBase64": map[string]any{"type": []any{"array", "null"}, "items": str("32-byte base64 destination"), "description": "Must be null at deploy time. Default null."},
		"cooldownSeconds":           map[string]any{"type": "integer", "minimum": 3600, "description": "Cooldown for staged changes, in seconds (>=3600). Default 604800 (7 days)."},
	}, "primary")
}

// deploySchema is the body of both preview and deploy. The init_authority
// signature proves control of the transient slot that seeds the policy
// PDA — usually produced by ika.dwallet.create (attachRecoveryPolicy:true)
// internally, so a raw deploy via MCP is rare.
func deploySchema() map[string]any {
	return obj(map[string]any{
		"dwalletAddress":                            str("Base58 address of the dWallet the policy will own."),
		"config":                                    policyConfigSchema(),
		"initAuthoritySlot":                         memberSlot("init authority"),
		"initAuthoritySignatureBase64":              str("Base64 signature by the init-authority slot over the deploy challenge. Verified on-chain via precompile."),
		"initAuthorityWebauthnAuthDataBase64":       str("Base64 WebAuthn authenticatorData — only when initAuthoritySlot.scheme is 3 (WebAuthn)."),
		"initAuthorityWebauthnClientDataJsonBase64": str("Base64 WebAuthn clientDataJSON — only when initAuthoritySlot.scheme is 3 (WebAuthn)."),
	}, "dwalletAddress", "config", "initAuthoritySlot", "initAuthoritySignatureBase64")
}

var routeHints = map[string]routeHint{
	// --- high-level dWallet ops (the ones an agent should actually call) ---
	"ika.dwallet.create": {
		Description: "Create a new cross-chain wallet (an Ika 2PC-MPC dWallet) on Solana. " +
			"Andromeda runs the entire client side of the protocol and PAYS ALL SOLANA GAS — the caller never needs a fee-payer keypair, SOL, an RPC URL, or any SDK. " +
			"The only secret the caller supplies is `passphrase` (>=12 chars), which wraps the server-generated keystore key; Andromeda never persists it in plaintext. " +
			"Set `attachRecoveryPolicy: true` to also deploy an on-chain recovery policy and transfer the dWallet's authority to it in the same call — that is what \"signable and recoverable from day one\" / \"auto-attach the recovery policy\" means. The wallet is signable immediately. " +
			"Returns dwalletAddress, ownerPubkeyBase58, signable, recoverable, and (when a policy was attached) policyAddress AND initAuthorityHashBase64 — keep the latter, it is REQUIRED to later read the policy (ika.recovery.policy.get) or run admin actions on it. Prefer this over the low-level ika.dkg.* tools. " +
			"Pre-alpha / devnet — data is wiped at Alpha 1; not for real value. (REST: POST /v1/dwallet/create → ika-backend, custody-free proxy.)",
		BodyRequired: true,
		BodySchema: obj(map[string]any{
			"passphrase": map[string]any{
				"type":        "string",
				"minLength":   12,
				"description": "Secret (>=12 chars) that wraps the server-side keystore key. Required. The user picks it; Andromeda never stores it in plaintext. The same passphrase is needed later to approve/sign/transfer with this wallet.",
			},
			"curve": map[string]any{
				"type":        "string",
				"enum":        []any{"Curve25519", "Secp256k1", "Secp256r1"},
				"description": "Signing curve. Optional; defaults to Curve25519 (Ed25519 — works for Solana, NEAR, Aptos, Cosmos ed25519, Substrate ed25519). Use Secp256k1 for EVM/Bitcoin/Cosmos secp256k1, Secp256r1 for P-256/WebAuthn.",
			},
			"attachRecoveryPolicy": map[string]any{
				"type":        "boolean",
				"description": "When true, also deploy an on-chain rules-policy for this dWallet and transfer the dWallet's authority to it, in the same call — makes the wallet recoverable from day one. The recovery layer is enabled on devnet, so this is safe to set.",
			},
			"primaryRecoveryOwner": obj(map[string]any{
				"scheme": map[string]any{
					"type":        "integer",
					"enum":        []any{0, 1, 2, 3},
					"description": "0 = Ed25519 (32-byte pubkey), 1 = Secp256k1 (20-byte eth_address), 2 = Secp256r1 (33-byte compressed pubkey), 3 = WebAuthn (33-byte compressed P-256 pubkey).",
				},
				"identifierBase64": str("Base64 of the identifier bytes; length depends on scheme (see the scheme field)."),
			}, "scheme", "identifierBase64"),
		}, "passphrase"),
	},

	"ika.dwallet.presign": {
		Description:  "Allocate a single-use presignature for a dWallet (speeds up the next sign). Gas-sponsored. Returns presignSessionIdHex. (REST: POST /v1/dwallet/presign → ika-backend, custody-free proxy.)",
		BodyRequired: true,
		BodySchema: obj(map[string]any{
			"dwalletAddress": str("Base58 address of the dWallet."),
		}, "dwalletAddress"),
	},

	"ika.dwallet.sign": {
		Description: "Produce a raw signature from a dWallet over a message that was already authorized via the gateway's PolicyEngine v3 endpoint `policy.engine.recover-as-primary.submit` (or `policy.engine.request-signature.submit`). Gas-sponsored; caller supplies the wallet's `passphrase` and the approval tx signature/slot from the authorize call. Andromeda returns the raw signature bytes — the caller composes and submits the final transaction on the destination chain. " +
			"Note (pre-alpha): the Ika devnet mock signer can return \"no key for dwallet\"; authorize works regardless. (REST: POST /v1/dwallet/sign → ika-backend, custody-free proxy.)",
		BodyRequired: true,
		BodySchema: obj(map[string]any{
			"dwalletAddress":            str("Base58 address of the dWallet."),
			"passphrase":                str("The wallet's passphrase (>=12 chars)."),
			"messageHex":                str("The message to sign, as non-empty even-length hex — must match what was approved."),
			"messageMetadataHex":        str("Optional metadata bytes as even-length hex — must match the approval."),
			"scheme":                    map[string]any{"type": "integer", "minimum": 0, "maximum": 6, "description": "Signature scheme (0..6); for Solana use 5."},
			"presignSessionIdHex":       str("Optional presign session id (hex) from ika.dwallet.presign; if omitted Andromeda allocates one."),
			"approvalTxSignatureBase58": str("Base58 tx signature returned by policy.engine.recover-as-primary.submit."),
			"approvalSlot":              map[string]any{"type": "integer", "minimum": 0, "description": "Slot of the approval tx."},
		}, "dwalletAddress", "passphrase", "messageHex", "scheme", "approvalTxSignatureBase58", "approvalSlot"),
	},

	"ika.dwallet.transferOwnership": {
		Description:  "Transfer a dWallet's on-chain authority to a new owner (e.g. a PolicyEngine v3 CPI authority PDA). Gas-sponsored; caller supplies the wallet's `passphrase`. Usually you don't need this directly — ika.dwallet.create with attachPolicyEngine:true already does the transfer. (REST: POST /v1/dwallet/transfer-ownership → ika-backend, custody-free proxy.)",
		BodyRequired: true,
		BodySchema: obj(map[string]any{
			"dwalletAddress":     str("Base58 address of the dWallet."),
			"passphrase":         str("The wallet's passphrase (>=12 chars)."),
			"newAuthorityBase58": str("Base58 of the new authority. For a PolicyEngine v3 attach this is PDA([\"__ika_cpi_authority\"], policyEngineProgramId)."),
		}, "dwalletAddress", "passphrase", "newAuthorityBase58"),
	},

	"ika.recovery.policy.get": {
		Description: "Read the on-chain recovery policy (RulesPolicy) for a dWallet: primary owner, quorum members, quorum threshold, daily limit, cooldown, any pendingChange, and the nonces. " +
			"Pass the dWallet's base58 address as the path parameter `dwalletAddress` AND the base64 hash from ika.dwallet.create's response as the REQUIRED query parameter `initAuthorityHashBase64` — without it the call 400s. " +
			"Example arguments: {\"pathParams\":{\"dwalletAddress\":\"<base58>\"},\"query\":{\"initAuthorityHashBase64\":\"<base64 from create>\"}}. (REST: GET /v1/recovery/policy/{dwalletAddress} → ika-backend, custody-free proxy.)",
	},

	// --- recovery policy management (challenge-based, gas-sponsored) ---
	// IMPORTANT for all admin/* tools: the challenge must be signed by the
	// policy's *primary owner*. If the primary is an external wallet
	// (the dWallet was created with primaryRecoveryOwner — e.g. MetaMask,
	// Phantom, a passkey), that wallet signs the challengeBase64.
	"ika.recovery.policy.preview": {
		Description:  "Validate (dry-run, no chain write) a recovery-policy configuration before deploying it. Same body shape as ika.recovery.policy.deploy. Note `members` must be empty and `allowedDestinationsBase64` null here — those are added afterwards via admin actions. Returns a `summary`. Usually unnecessary: ika.dwallet.create with attachRecoveryPolicy:true deploys a sane default policy for you. (REST: POST /v1/recovery/policy/preview → ika-backend, custody-free proxy.)",
		BodyRequired: true,
		BodySchema:   deploySchema(),
	},
	"ika.recovery.policy.deploy": {
		Description:  "Deploy a RulesPolicy on-chain for an existing dWallet (gas-sponsored). Requires an init-authority signature over the deploy challenge. In almost all cases you should NOT call this directly — ika.dwallet.create with attachRecoveryPolicy:true already deploys and wires up the policy. Returns policyAddress, txSignature, initAuthorityHashBase64. (REST: POST /v1/recovery/policy/deploy → ika-backend, custody-free proxy.)",
		BodyRequired: true,
		BodySchema:   deploySchema(),
	},
	"ika.recovery.policy.admin.challenge": {
		Description: "Step 1 of a recovery-policy admin action: get the 32-byte challenge the policy's PRIMARY OWNER must sign for the given action (add/remove a quorum member, set the primary, add/remove a destination, revoke, or change quorum threshold / daily limit / cooldown). " +
			"`initAuthorityHashBase64` is the value returned by ika.dwallet.create (or ika.recovery.policy.deploy). Returns {challengeBase64, expectedNonce}. " +
			"Next: have the primary owner's wallet sign challengeBase64, then call ika.recovery.policy.admin.submit. See the note above about who can sign. (REST: POST /v1/recovery/policy/admin/challenge → ika-backend, custody-free proxy.)",
		BodyRequired: true,
		BodySchema: obj(map[string]any{
			"dwalletAddress":          str("Base58 address of the dWallet."),
			"initAuthorityHashBase64": str("32-byte base64 hash from ika.dwallet.create / ika.recovery.policy.deploy. Required to derive the policy PDA."),
			"action":                  adminActionSchema(),
		}, "dwalletAddress", "initAuthorityHashBase64", "action"),
	},
	"ika.recovery.policy.admin.submit": {
		Description: "Step 2 of a recovery-policy admin action: submit the primary owner's signature over the challenge from ika.recovery.policy.admin.challenge. Andromeda builds the Solana tx (signature precompile + main instruction), signs it as gas sponsor, and submits it. Returns {txSignature}. " +
			"The `action` and `dwalletAddress`/`initAuthorityHashBase64` must match the challenge call exactly; `expectedNonce` is the value returned by the challenge call; `primarySignatureBase64` is the signature made by the policy's primary-owner wallet over challengeBase64, using whatever scheme the primary slot declares (Ed25519 raw / Secp256k1 EIP-191 / Secp256r1 / WebAuthn assertion). " +
			"`propose_*` actions create a pendingChange — finalize it after the cooldown with ika.recovery.policy.apply-pending. See the note above about who can sign. (REST: POST /v1/recovery/policy/admin/submit → ika-backend, custody-free proxy.)",
		BodyRequired: true,
		BodySchema: obj(map[string]any{
			"dwalletAddress":          str("Base58 address of the dWallet (same as the challenge call)."),
			"initAuthorityHashBase64": str("32-byte base64 hash (same as the challenge call)."),
			"action":                  adminActionSchema(),
			"primarySignatureBase64":  str("Base64 signature by the policy's primary owner over challengeBase64 from the challenge call."),
			"expectedNonce":           map[string]any{"type": "integer", "minimum": 0, "description": "The expectedNonce value returned by ika.recovery.policy.admin.challenge."},
		}, "dwalletAddress", "initAuthorityHashBase64", "action", "primarySignatureBase64", "expectedNonce"),
	},
	"ika.recovery.policy.apply-pending": {
		Description:  "Finalize a staged (pending) recovery-policy change once its cooldown has elapsed. Callable by anyone; gas-sponsored. Use after a `propose_*` admin action whose cooldown has passed. Returns {txSignature}. (REST: POST /v1/recovery/policy/apply-pending → ika-backend, custody-free proxy.)",
		BodyRequired: true,
		BodySchema: obj(map[string]any{
			"dwalletAddress":          str("Base58 address of the dWallet."),
			"initAuthorityHashBase64": str("32-byte base64 hash from ika.dwallet.create / ika.recovery.policy.deploy."),
		}, "dwalletAddress", "initAuthorityHashBase64"),
	},

	// --- Login Social (OIDC primary recovery; scheme = 4) ---
	// Flow: stage the provider id_token → open a short-lived OidcSession bound
	// to an ephemeral Ed25519 key the user holds → authorize each signature with
	// that key → close on expiry. Andromeda pays all gas. The user's wallet is
	// never a Solana signer; they only sign the 32-byte challenges off-chain.
	// Pre-validate the id_token with ika.oidc.validate before staging.
	"ika.oidc.nonce": {
		Description: "Login Social step 0: given the user's ephemeral Ed25519 public key, the server picks `not_after` (default ≈ 9 min — short enough to fit inside an Apple id_token's life even after the OAuth round-trip) and `nonce_randomness`, and returns the canonical `oidc_nonce` to use as the OAuth `nonce` (scope=openid). The client never needs to know the byte layout. You may optionally pass `notAfterUnixTs` to override the default (must be in (now, now+3600]). Returns {oidcNonce (43-char base64url), notAfterUnixTs, nonceRandomnessBase64} — keep `notAfterUnixTs` and `nonceRandomnessBase64`, they're needed by the open step. (REST: POST /v1/oidc/nonce → ika-backend.)",
		BodyRequired: true,
		BodySchema: obj(map[string]any{
			"ephPkBase64":    str("Base64 of the user's ephemeral Ed25519 public key (32 bytes), generated on-device (e.g. WebCrypto). The matching private key stays on the device and signs the session challenges later."),
			"notAfterUnixTs": map[string]any{"type": "integer", "minimum": 0, "description": "Optional override (unix seconds, in (now, now+3600]). Omit to let the server pick a safe default."},
		}, "ephPkBase64"),
	},
	"ika.oidc.validate": {
		Description: "Login Social step 1: server-side pre-validation of an OIDC `id_token` (Google/Apple), against the provider JWKS. Run this BEFORE ika.recovery.primary.oidc.stage so you don't spend gas on a bad token. Checks signature, issuer, audience (the Andromeda auth-broker client_id), exp/iat/nbf, alg=RS256, kid, sub, and that `nonce` is a 43-char base64url string. Returns {valid, provider, addrSeed, issuerHash, audienceHash, subjectHash, expiresAt} (all base64) — never the raw sub or JWT. (REST: POST /v1/oidc/validate → ika-backend.)",
		BodyRequired: true,
		BodySchema: obj(map[string]any{
			"idToken": map[string]any{"type": "string", "minLength": 1, "maxLength": 4096, "description": "The provider `id_token` (a compact RS256 JWT, ≤ 4096 chars) obtained from Google/Apple with `scope=openid` and `nonce` = the `oidcNonce` returned by ika.oidc.nonce."},
		}, "idToken"),
	},
	"ika.recovery.primary.oidc.stage": {
		Description: "Login Social step 1: stage a verified `id_token` into a temporary on-chain PDA so the (larger) `open` step can verify it on-chain without exceeding the tx-size limit. Gas-sponsored. Validate the token first with ika.oidc.validate. Returns {txSignature, stagingAddress, stagingNonce}. Only works for a dWallet whose policy primary is an OIDC identity `[4, addr_seed, 0]`. (REST: POST /v1/recovery/primary/oidc/stage → ika-backend.)",
		BodyRequired: true,
		BodySchema: obj(map[string]any{
			"dwalletAddress":          str("Base58 address of the dWallet."),
			"initAuthorityHashBase64": str("32-byte base64 hash from ika.dwallet.create / ika.recovery.policy.deploy — required to derive the policy PDA."),
			"idToken":                 map[string]any{"type": "string", "minLength": 1, "maxLength": 4096, "description": "The provider `id_token` (compact RS256 JWT, ≤ 4096 chars). Re-validated server-side before any gas is spent."},
		}, "dwalletAddress", "initAuthorityHashBase64", "idToken"),
	},
	"ika.recovery.primary.oidc.open.challenge": {
		Description: "Login Social step 2a (read-only): given the staged JWT and the ephemeral key parameters, returns the 32-byte `oidc-session-open` challenge the EPHEMERAL Ed25519 key must sign, plus {expectedSessionNonce, sessionAddress, jwkRegistryAddress, jwkRegistryBump, oidcVerifierVersion, addrSeedBase64, jwtExpiresAt}. (REST: POST /v1/recovery/primary/oidc/open/challenge → ika-backend.)",
		BodyRequired: true,
		BodySchema: obj(map[string]any{
			"dwalletAddress":          str("Base58 address of the dWallet."),
			"initAuthorityHashBase64": str("32-byte base64 hash from ika.dwallet.create / ika.recovery.policy.deploy."),
			"stagingAddress":          str("Base58 address of the OidcJwtStaging PDA returned by ika.recovery.primary.oidc.stage."),
			"ephPkBase64":             str("Base64 of the user's ephemeral Ed25519 public key (32 bytes) — the same one whose corresponding `nonce` was in the id_token."),
			"notAfterUnixTs":          map[string]any{"type": "integer", "minimum": 0, "description": "The `not_after` (unix seconds) the client chose when deriving `oidc_nonce`; must be ≤ the JWT's `exp`."},
			"nonceRandomnessBase64":   str("Base64 of the 32 random bytes used to derive `oidc_nonce`."),
		}, "dwalletAddress", "initAuthorityHashBase64", "stagingAddress", "ephPkBase64", "notAfterUnixTs", "nonceRandomnessBase64"),
	},
	"ika.recovery.primary.oidc.open": {
		Description: "Login Social step 2b: submit the ephemeral key's signature over the `oidc-session-open` challenge. Andromeda re-validates the staged JWT, builds the Solana tx `[Ed25519 precompile (eph_pk, challenge)] + oidc_session_open` (which verifies the RSA signature + claims + JWK registry on-chain), signs it as gas sponsor, and submits — the staging PDA is consumed (rent refunded). Returns {txSignature, sessionAddress}. The session expires at `min(not_after, min(jwt.exp, now + 600s))`. (REST: POST /v1/recovery/primary/oidc/open → ika-backend.)",
		BodyRequired: true,
		BodySchema: obj(map[string]any{
			"dwalletAddress":          str("Base58 address of the dWallet."),
			"initAuthorityHashBase64": str("32-byte base64 hash (same as the challenge call)."),
			"stagingAddress":          str("Base58 address of the OidcJwtStaging PDA."),
			"ephPkBase64":             str("Base64 of the ephemeral Ed25519 public key (32 bytes)."),
			"notAfterUnixTs":          map[string]any{"type": "integer", "minimum": 0, "description": "Same `not_after` used to derive `oidc_nonce`."},
			"nonceRandomnessBase64":   str("Base64 of the 32-byte nonce randomness."),
			"ephSignatureBase64":      str("Base64 Ed25519 signature (64 bytes) by the ephemeral key over the `challengeBase64` from ika.recovery.primary.oidc.open.challenge."),
			"expectedSessionNonce":    map[string]any{"type": "integer", "minimum": 0, "description": "The `expectedSessionNonce` returned by the challenge call."},
		}, "dwalletAddress", "initAuthorityHashBase64", "stagingAddress", "ephPkBase64", "notAfterUnixTs", "nonceRandomnessBase64", "ephSignatureBase64", "expectedSessionNonce"),
	},
	"ika.recovery.primary.oidc.use.challenge": {
		Description: "Login Social step 3a (read-only): for an open OidcSession, returns the 32-byte `oidc-primary-use` challenge the ephemeral key must sign to authorize one signature, plus {expectedUseNonce, sessionExpiresAt}. (REST: POST /v1/recovery/primary/oidc/use/challenge → ika-backend.)",
		BodyRequired: true,
		BodySchema: obj(map[string]any{
			"dwalletAddress":          str("Base58 address of the dWallet."),
			"initAuthorityHashBase64": str("32-byte base64 hash from ika.dwallet.create / ika.recovery.policy.deploy."),
			"sessionAddress":          str("Base58 address of the OidcSession PDA from ika.recovery.primary.oidc.open."),
			"messageDigestBase64":     str("Base64 of the 32-byte message digest to authorize."),
			"metadataDigestBase64":    str("Base64 of the 32-byte metadata digest; omit/empty = 32 zero bytes."),
		}, "dwalletAddress", "initAuthorityHashBase64", "sessionAddress", "messageDigestBase64"),
	},
	"ika.recovery.primary.oidc.use.submit": {
		Description: "Login Social step 3b: submit the ephemeral key's signature over the `oidc-primary-use` challenge. Andromeda builds `[Ed25519 precompile (eph_pk, challenge)] + recover_as_primary_oidc_session` (which re-checks the session, the policy primary, the JWK status, and CPIs Ika `approve_message`), signs as gas sponsor, submits. Returns {txSignature, messageApprovalAddress}. Repeat with fresh challenges until the session expires. (REST: POST /v1/recovery/primary/oidc/use/submit → ika-backend.)",
		BodyRequired: true,
		BodySchema: obj(map[string]any{
			"dwalletAddress":          str("Base58 address of the dWallet."),
			"initAuthorityHashBase64": str("32-byte base64 hash (same as the challenge call)."),
			"sessionAddress":          str("Base58 address of the OidcSession PDA."),
			"messageDigestBase64":     str("Base64 of the 32-byte message digest (same as the challenge call)."),
			"metadataDigestBase64":    str("Base64 of the 32-byte metadata digest; omit/empty = 32 zero bytes."),
			"userPubkeyBase64":        str("Base64 of the dWallet's 32-byte public key (passed to Ika `approve_message`)."),
			"signatureScheme":         map[string]any{"type": "integer", "minimum": 0, "maximum": 6, "description": "Signature scheme for the MessageApproval (0..6). For Solana use 5 (EddsaSha512)."},
			"ephSignatureBase64":      str("Base64 Ed25519 signature (64 bytes) by the ephemeral key over the `challengeBase64` from ika.recovery.primary.oidc.use.challenge."),
			"expectedUseNonce":        map[string]any{"type": "integer", "minimum": 0, "description": "The `expectedUseNonce` returned by the challenge call."},
		}, "dwalletAddress", "initAuthorityHashBase64", "sessionAddress", "messageDigestBase64", "userPubkeyBase64", "signatureScheme", "ephSignatureBase64", "expectedUseNonce"),
	},
	"ika.recovery.primary.oidc.close": {
		Description:  "Login Social cleanup: close an expired OidcSession, refunding its rent (to the gas sponsor that funded it). Only callable once the session is past its expiry. Returns {txSignature}. (REST: POST /v1/recovery/primary/oidc/close → ika-backend.)",
		BodyRequired: true,
		BodySchema: obj(map[string]any{
			"dwalletAddress":          str("Base58 address of the dWallet."),
			"initAuthorityHashBase64": str("32-byte base64 hash from ika.dwallet.create / ika.recovery.policy.deploy."),
			"sessionAddress":          str("Base58 address of the OidcSession PDA to close."),
		}, "dwalletAddress", "initAuthorityHashBase64", "sessionAddress"),
	},
	"ika.recovery.primary.oidc.staging.close": {
		Description:  "Login Social cleanup: close an abandoned OidcJwtStaging PDA (one that was staged but never opened), after a short TTL (~15 min), refunding its rent. The happy path closes it automatically during `open`. Returns {txSignature}. (REST: POST /v1/recovery/primary/oidc/staging/close → ika-backend.)",
		BodyRequired: true,
		BodySchema: obj(map[string]any{
			"stagingAddress": str("Base58 address of the OidcJwtStaging PDA to close."),
		}, "stagingAddress"),
	},

	// --- low-level DKG: steer agents toward the high-level tool ---
	"ika.dkg.prepare": {
		Description: "LOW-LEVEL. Build the unsigned DKG (distributed key generation) transaction for a caller who will run the Ika client side themselves and sign client-side. Most callers should use ika.dwallet.create instead — it runs the whole flow gas-sponsored with just a passphrase. (REST: POST /v1/dwallet/dkg/prepare → ika-backend, custody-free proxy.)",
	},
	"ika.dkg.submit": {
		Description: "LOW-LEVEL. Submit the client-signed DKG transaction. Pairs with ika.dkg.prepare. Most callers should use ika.dwallet.create instead. (REST: POST /v1/dwallet/dkg/submit → ika-backend, custody-free proxy.)",
	},

	// --- F13: PolicyEngine v3 (Local routes — handled in-process) -----------
	"policy.engine.read": {
		Description: "Read the on-chain PolicyEngine state for a dWallet — header (paused, rules_generation, owner_slot) plus every active rule slot (kind, generation, sub-PDA, config_hash). The single source of truth for what policies currently gate a dWallet. (REST: GET /v1/policy/{dwallet} → handled locally by the gateway, no upstream proxy.)",
	},
	"policy.engine.init.challenge": {
		Description: "Step 1/2 of attaching a PolicyEngine v3 to a dWallet. Computes the canonical 32-byte init challenge that the dWallet owner signs off-chain. Returns the challenge hash + the deterministic PolicyEngine PDA. The owner signs it with their wallet (Ed25519 / Secp256k1 / Secp256r1 / WebAuthn / OIDC) and posts the signature to policy.engine.init.submit. ADMIN scope. (REST: POST /v1/policy/init/challenge.)",
		BodyRequired: true,
		BodySchema: obj(map[string]any{
			"dwallet_address":      str("Base58 address of the dWallet to attach the engine to."),
			"init_authority_slot":  str("34-byte canonical member slot (scheme byte + 33-byte identifier, padded). Base64."),
			"owner_slot":           str("34-byte canonical member slot of the engine's owner (who later signs admin actions). Base64."),
			"default_recovery_hash": str("Optional 32-byte hex — config_hash of a Recovery rule pre-bound at init time. Empty/omitted for plain init."),
		}, "dwallet_address", "init_authority_slot", "owner_slot"),
	},
	"policy.engine.init.submit": {
		Description: "Step 2/2: submit the owner-signed init challenge. Gateway builds `init_engine` + Ed25519/Secp256k1/Secp256r1 precompile in the same tx, signs as gas sponsor, and lands the engine on-chain. ADMIN scope. Idempotency-Key REQUIRED. Returns {tx_signature, engine_address}. (REST: POST /v1/policy/init/submit.)",
		BodyRequired: true,
	},
	"policy.engine.rules.add.challenge": {
		Description: "Step 1/2 of adding a new rule (allowlist / velocity / time-lock / oracle / passkey / fhe-gated / session-key / recovery) to an existing PolicyEngine. Computes the canonical admin challenge for the chosen rule_kind + config payload. ADMIN scope. (REST: POST /v1/policy/rules/add/challenge.)",
		BodyRequired: true,
	},
	"policy.engine.rules.add.submit": {
		Description: "Step 2/2: submit the owner-signed add-rule challenge. The on-chain handler allocates the rule sub-PDA and writes the engine.rules_flat entry. ADMIN scope. Idempotency-Key REQUIRED. (REST: POST /v1/policy/rules/add/submit.)",
		BodyRequired: true,
	},
	"policy.engine.rules.items.add.challenge": {
		Description: "Step 1/2 of adding an item to an existing rule (e.g. allowlist destination, velocity window, recovery member). PE-011 incremental pattern keeps tx size under the Solana 1232-byte limit. ADMIN scope. (REST: POST /v1/policy/rules/{ruleIndex}/items/add/challenge.)",
		BodyRequired: true,
	},
	"policy.engine.rules.items.add.submit": {
		Description: "Step 2/2: submit the owner-signed add-item challenge. ADMIN scope. Idempotency-Key REQUIRED. (REST: POST /v1/policy/rules/{ruleIndex}/items/add/submit.)",
		BodyRequired: true,
	},
	"policy.engine.request-signature.challenge": {
		Description: "Pre-flight for a signing request: compute the canonical metadata_digest binding (engine, dwallet, message_digest, destination, user_pubkey, signature_scheme, PATH_NORMAL, rules_generation). The caller signs this off-chain with the dWallet's owner key. Cheap read. (REST: POST /v1/policy/request-signature/challenge.)",
		BodyRequired: true,
	},
	"policy.engine.request-signature.submit": {
		Description: "Submit a signed request_signature. Gateway builds the tx with the owner's precompile + sub-PDAs for every active rule (in slot order), invokes Ika `approve_message` via CPI. Idempotency-Key REQUIRED. (REST: POST /v1/policy/request-signature/submit.)",
		BodyRequired: true,
	},

	// --- F11b-Phase1: recover_as_primary (RecoveryRule primary path) ---
	"policy.engine.recover-as-primary.challenge": {
		Description: "Step 1/2 of a `recover_as_primary` flow on a PolicyEngine RecoveryRule. " +
			"Computes the canonical clear-signing v2 challenge (DOMAIN=`andromeda::rules-policy::v2`, OP=`primary-recover`) that the policy's PRIMARY owner signs off-chain. " +
			"Returns {challenge_hex, human_message, message_approval_address, message_approval_bump, engine_address, rule_pda, primary_scheme}. (REST: POST /v1/policy/recover-as-primary/challenge.)",
		BodyRequired: true,
	},
	"policy.engine.recover-as-primary.submit": {
		Description: "Step 2/2: submit the primary owner's signature over the `recover_as_primary` challenge. Gateway builds [credential precompile + recover_as_primary main ix], signs as gas sponsor, and lands the tx — on-chain Ika `approve_message` is CPI'd, RecoveryRule daily-limit + destinations whitelist enforced, primary_recover_nonce bumped. Idempotency-Key REQUIRED. Returns {tx_signature, engine_address}. (REST: POST /v1/policy/recover-as-primary/submit.)",
		BodyRequired: true,
	},

	// --- F11b-Phase2: quorum_session_* (M-of-N recovery) ---
	"policy.engine.quorum.open.challenge": {
		Description: "Step 1/2 of `quorum_session_open` (disc 82). Primary owner signs the canonical `quorum-session-open` challenge that binds {dwallet, message_digest, metadata_digest, user_pubkey, scheme, amount, destination, expires_at, session_nonce, primary_slot}. Tampering with any field on submit invalidates the signature. (REST: POST /v1/policy/quorum/session/open/challenge.)",
		BodyRequired: true,
	},
	"policy.engine.quorum.open.submit": {
		Description: "Step 2/2: gateway lands [primary precompile + quorum_session_open main ix]. Allocates the ephemeral QuorumSession PDA, snapshots roster + threshold from the RecoveryRule. Idempotency-Key REQUIRED. (REST: POST /v1/policy/quorum/session/open/submit.)",
		BodyRequired: true,
	},
	"policy.engine.quorum.contribute.challenge": {
		Description: "Step 1/2 of `quorum_session_contribute` (disc 83). Each member signs the canonical `quorum-contribute` challenge that hashes the FULL session snapshot (session, member_slot, dwallet, all digests, user_pubkey, amount, destination, expires_at). Concurrent member updates do NOT affect in-flight signatures. (REST: POST /v1/policy/quorum/session/contribute/challenge.)",
		BodyRequired: true,
	},
	"policy.engine.quorum.contribute.submit": {
		Description: "Step 2/2: gateway lands [member precompile + quorum_session_contribute main ix]. Bumps the contributions bitmap; rejects double-contributions. Idempotency-Key REQUIRED. (REST: POST /v1/policy/quorum/session/contribute/submit.)",
		BodyRequired: true,
	},
	"policy.engine.quorum.finalize": {
		Description: "Permissionless: once `contributions_count >= threshold`, anyone calls finalize. Gateway lands the main ix which CPIs Ika `approve_message`. No signature needed — the session itself is the authorization. Idempotency-Key REQUIRED. (REST: POST /v1/policy/quorum/session/finalize.)",
		BodyRequired: true,
	},
	"policy.engine.quorum.close": {
		Description: "Close a finalized or expired QuorumSession, refunding rent to the recipient (must equal `session.payer_for_close` locked at open time). Returns the UNSIGNED Solana tx (base64) + recent blockhash + last_valid_block_height. The client decodes it, fills the recipient's signature slot, and submits via Solana RPC `sendTransaction`. The gateway can't fee-pay this because the recipient is the only on-chain signer. (REST: POST /v1/policy/quorum/session/close.)",
		BodyRequired: true,
	},

	// --- F11b-Phase2: passkey_session_* (Secp256r1 + WebAuthn step-up) ---
	"policy.engine.passkey.open.challenge": {
		Description: "Step 1/2 of `passkey_session_open` (disc 89). The passkey credential signs the canonical `passkey-session-open` challenge that binds {dwallet, primary_slot, eph_pk, not_after_unix_ts, credential_id_hash, session_nonce}. The on-chain handler verifies the Secp256r1 signature + WebAuthn assertion. (REST: POST /v1/policy/passkey/session/open/challenge.)",
		BodyRequired: true,
	},
	"policy.engine.passkey.open.submit": {
		Description: "Step 2/2: gateway lands [Secp256r1 precompile (auth_data || sha256(clientDataJSON)) + passkey_session_open main ix]. Allocates the PasskeySession PDA, binds eph_pk. Idempotency-Key REQUIRED. (REST: POST /v1/policy/passkey/session/open/submit.)",
		BodyRequired: true,
	},
	"policy.engine.passkey.use.challenge": {
		Description: "Step 1/2 of `recover_as_primary_passkey_session` (disc 90). The ephemeral Ed25519 key signs the canonical `passkey-primary-use` challenge that binds {session, dwallet, message_approval, digests, user_pubkey, scheme, use_nonce, primary_slot}. Single-use per session via use_nonce. (REST: POST /v1/policy/passkey/use/challenge.)",
		BodyRequired: true,
	},
	"policy.engine.passkey.use.submit": {
		Description: "Step 2/2: gateway lands [Ed25519 precompile by eph_pk + recover_as_primary_passkey_session main ix]. CPIs Ika `approve_message`. Repeat with fresh use_nonces until session expires. Idempotency-Key REQUIRED. (REST: POST /v1/policy/passkey/use/submit.)",
		BodyRequired: true,
	},
	"policy.engine.passkey.close": {
		Description: "Close an expired PasskeySession, refunding rent. Returns the UNSIGNED Solana tx (base64) + recent blockhash + last_valid_block_height; recipient signs client-side and submits via Solana RPC `sendTransaction`. Same recipient-signs constraint as quorum close. (REST: POST /v1/policy/passkey/session/close.)",
		BodyRequired: true,
	},
}
