// Package policy wires the Andromeda PolicyEngine v3 into the gateway.
//
// This package replaces `gateway/internal/policies/` (the legacy 8-template
// surface). Until F16 sunset, BOTH packages coexist — legacy routes return
// 410 Gone with a pointer to the v3 equivalent, but the code is still
// compiled and reviewable.
//
// Spec: docs/POLICY_ENGINE_ABI_V3.md.
// ADRs: docs/adr/PE-001 .. PE-011.
// Cross-language fixtures: fixtures/policy_engine_v3/.
//
// Layout:
//
//	policy/
//	├── doc.go        (this file)
//	├── pda.go        (PolicyEngine + sub-PDA derivation)
//	├── challenges.go (challenge encoders — mirror byte-for-byte of contracts/policy-engine/src/lib.rs)
//	├── codecs.go     (zero-copy decoders for account state — F2.5)
//	└── rules/
//	    └── allowlist.go (typed instruction builders for the Allowlist kind)
//
// F2.3 status (2026-05-15): challenges + PDA for Allowlist, validated against
// fixtures. Other kinds (Velocity, TimeLock, Oracle, Passkey, FheGated,
// SessionKey, Recovery) land in F3..F9. Instruction builders + REST routes
// are wired only for Allowlist for now.
package policy
