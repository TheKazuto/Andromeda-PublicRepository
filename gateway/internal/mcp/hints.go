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

var routeHints = map[string]routeHint{
	// --- high-level dWallet ops (the ones an agent should actually call) ---
	"ika.dwallet.create": {
		Description: "Create a new cross-chain wallet (an Ika 2PC-MPC dWallet) on Solana. " +
			"Andromeda runs the entire client side of the protocol and PAYS ALL SOLANA GAS — the caller never needs a fee-payer keypair, SOL, an RPC URL, or any SDK. " +
			"The only secret the caller supplies is `passphrase` (>=12 chars), which wraps the server-generated keystore key; Andromeda never persists it in plaintext. " +
			"Set `attachPolicyEngine: true` to also deploy an on-chain PolicyEngine v3 and transfer the dWallet's authority to it in the same call — that is what \"signable and recoverable from day one\" / \"auto-attach the policy engine\" means. The wallet is signable immediately. " +
			"Returns dwalletAddress, ownerPubkeyBase58, signable, recoverable, and (when the engine was attached) policyEngineAddress AND policyEngineInitAuthorityHashBase64 — keep the latter, it is REQUIRED to later read the engine (policy.engine.read) or run admin actions on it. Prefer this over the low-level ika.dkg.* tools. " +
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
			"attachPolicyEngine": map[string]any{
				"type":        "boolean",
				"description": "When true, also deploy an on-chain PolicyEngine v3 for this dWallet and transfer the dWallet's authority to it, in the same call — makes the wallet recoverable from day one.",
			},
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

	// --- Login Social pre-flow (OIDC id_token helpers) ---
	// Read-only helpers preserved from the retired legacy /v1/recovery/primary/oidc/*
	// flow. The PolicyEngine v3 OIDC successor (F9c) is gated on the
	// `sol_big_mod_exp` syscall and will reuse these endpoints when it lands.
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
