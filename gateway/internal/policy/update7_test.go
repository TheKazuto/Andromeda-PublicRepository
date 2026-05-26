package policy

import (
	"strings"
	"testing"

	"github.com/gagliardetto/solana-go"
)

// TestHumanMessageSwap_StableAndSemantic proves the SWAP renderer is a pure
// function of its inputs and renders the semantic swap line — same inputs
// always produce the same bytes, and the rendered string surfaces the
// from/to token addresses + chain so a wallet UI can clear-sign meaningfully.
func TestHumanMessageSwap_StableAndSemantic(t *testing.T) {
	dwallet := solana.SystemProgramID
	var fromToken, toToken [32]byte
	fromToken[31] = 0x01
	toToken[31] = 0x02
	var chainTag [8]byte
	copy(chainTag[:], "solana")

	a := HumanMessageSwap(dwallet, fromToken, 1500000, toToken, 12000000, chainTag, 0)
	b := HumanMessageSwap(dwallet, fromToken, 1500000, toToken, 12000000, chainTag, 0)
	if string(a) != string(b) {
		t.Fatalf("non-deterministic: %q vs %q", a, b)
	}

	got := string(a)
	mustContain := []string{
		"Swap 1500000",
		"for at least 12000000",
		"of 0000000000000000000000000000000000000000000000000000000000000001",
		"of 0000000000000000000000000000000000000000000000000000000000000002",
		"on solana",
		"for dWallet ",
		"scheme 0",
	}
	for _, want := range mustContain {
		if !strings.Contains(got, want) {
			t.Errorf("rendered message missing %q\nfull: %q", want, got)
		}
	}
}

// TestHumanMessageSwap_ChainTagStripsTrailingNUL verifies the renderer matches
// the Rust mirror's behaviour of stopping at the first NUL byte in chain_tag.
func TestHumanMessageSwap_ChainTagStripsTrailingNUL(t *testing.T) {
	dwallet := solana.SystemProgramID
	var fromToken, toToken [32]byte
	fromToken[31] = 0x01
	toToken[31] = 0x02
	var chainTag [8]byte
	copy(chainTag[:], "evm") // 3 bytes + 5 NUL

	got := string(HumanMessageSwap(dwallet, fromToken, 100, toToken, 200, chainTag, 5))
	if !strings.Contains(got, "on evm for dWallet") {
		t.Errorf("trailing NUL not stripped from chain_tag: %q", got)
	}
}

// TestSwapMetadataDigest_BindsAllSwapFields proves every swap-extension field
// is bound into the V3 digest — a single-bit change to any field changes the
// digest, so a compromised gateway can't trick the owner into signing one swap
// while broadcasting a different one.
func TestSwapMetadataDigest_BindsAllSwapFields(t *testing.T) {
	base := SwapMetadataDigestInput{
		Engine:          solana.SystemProgramID,
		DWallet:         solana.SystemProgramID,
		MessageDigest:   [32]byte{0x01},
		Destination:     [32]byte{0x02},
		UserPubkey:      [32]byte{0x03},
		SignatureScheme: 0,
		RulesGeneration: 0,
		FromAmount:      1000,
		AssetIndex:      0,
		FromToken:       [32]byte{0xAA},
		ToToken:         [32]byte{0xBB},
		MinAmountOut:    900,
	}
	copy(base.ChainTag[:], "solana")
	baseHash := base.Hash()

	// Each mutation must change the hash.
	cases := []struct {
		name   string
		mutate func(*SwapMetadataDigestInput)
	}{
		{"FromAmount", func(in *SwapMetadataDigestInput) { in.FromAmount++ }},
		{"FromToken", func(in *SwapMetadataDigestInput) { in.FromToken[0]++ }},
		{"ToToken", func(in *SwapMetadataDigestInput) { in.ToToken[0]++ }},
		{"MinAmountOut", func(in *SwapMetadataDigestInput) { in.MinAmountOut++ }},
		{"ChainTag", func(in *SwapMetadataDigestInput) { in.ChainTag[0] = 'X' }},
		{"MessageDigest", func(in *SwapMetadataDigestInput) { in.MessageDigest[0]++ }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			mut := base
			tc.mutate(&mut)
			if mut.Hash() == baseHash {
				t.Errorf("changing %s did not change the digest (binding broken)", tc.name)
			}
		})
	}
}

// TestSwapMetadataDigest_DifferentDomainThanV2 proves the SWAP V3 digest is
// distinct from the NORMAL V2 digest even with identical common fields — the
// domain bump prevents a SWAP signing from being replayed against a NORMAL
// signature check and vice versa.
func TestSwapMetadataDigest_DifferentDomainThanV2(t *testing.T) {
	engine := solana.SystemProgramID
	dwallet := solana.SystemProgramID
	msgDigest := [32]byte{0xAA}
	dest := [32]byte{0xBB}
	userPK := [32]byte{0xCC}

	v2 := (&RequestMetadataDigestInput{
		Engine: engine, DWallet: dwallet, MessageDigest: msgDigest, Destination: dest,
		UserPubkey: userPK, SignatureScheme: 0, Path: 1, RulesGeneration: 0,
		Amount: 100, AssetIndex: 0,
	}).Hash()
	v3 := (&SwapMetadataDigestInput{
		Engine: engine, DWallet: dwallet, MessageDigest: msgDigest, Destination: dest,
		UserPubkey: userPK, SignatureScheme: 0, RulesGeneration: 0,
		FromAmount: 100, AssetIndex: 0,
	}).Hash()
	if v2 == v3 {
		t.Fatal("V2 and V3 digests collide (domain bump broken)")
	}
}

// TestBundleUseChallenge_IdenticalAcrossLegs is the critical invariant: ALL
// legs of a bundle must compute the SAME challenge hash so one owner signature
// unlocks every leg. This test computes the bundle hash from each leg's
// viewpoint (this_index=0 with other=[digest_1]; this_index=1 with
// other=[digest_0]) and asserts they match.
func TestBundleUseChallenge_IdenticalAcrossLegs(t *testing.T) {
	engine := solana.SystemProgramID
	dwallet := solana.SystemProgramID
	var slot [MemberSlotLen]byte
	digest0 := [32]byte{0x01, 0x02, 0x03}
	digest1 := [32]byte{0x0A, 0x0B, 0x0C}

	leg0 := &BundleUseChallengeInput{
		Engine: engine, DWallet: dwallet, OwnerSlot: slot,
		Total: 2, ThisIndex: 0,
		ThisMetadataDigest: digest0,
		OtherDigests:       [][32]byte{digest1},
	}
	leg1 := &BundleUseChallengeInput{
		Engine: engine, DWallet: dwallet, OwnerSlot: slot,
		Total: 2, ThisIndex: 1,
		ThisMetadataDigest: digest1,
		OtherDigests:       [][32]byte{digest0},
	}
	h0, err := leg0.Hash()
	if err != nil {
		t.Fatalf("leg0.Hash: %v", err)
	}
	h1, err := leg1.Hash()
	if err != nil {
		t.Fatalf("leg1.Hash: %v", err)
	}
	if h0 != h1 {
		t.Fatalf("bundle invariant broken: leg0=%x leg1=%x", h0, h1)
	}
}

// TestBundleUseChallenge_OrderingMatters guarantees that swapping the bundle
// ordering (digest_0 and digest_1 swapped between slots 0 and 1) produces a
// DIFFERENT hash. Otherwise a gateway could re-bind an owner sig to a
// re-ordered set of digests.
func TestBundleUseChallenge_OrderingMatters(t *testing.T) {
	engine := solana.SystemProgramID
	dwallet := solana.SystemProgramID
	var slot [MemberSlotLen]byte
	digest0 := [32]byte{0x01}
	digest1 := [32]byte{0x02}

	canonical := &BundleUseChallengeInput{
		Engine: engine, DWallet: dwallet, OwnerSlot: slot,
		Total: 2, ThisIndex: 0,
		ThisMetadataDigest: digest0,
		OtherDigests:       [][32]byte{digest1},
	}
	reordered := &BundleUseChallengeInput{
		Engine: engine, DWallet: dwallet, OwnerSlot: slot,
		Total: 2, ThisIndex: 0,
		ThisMetadataDigest: digest1,
		OtherDigests:       [][32]byte{digest0},
	}
	hc, _ := canonical.Hash()
	hr, _ := reordered.Hash()
	if hc == hr {
		t.Fatal("bundle ordering is not bound into the hash (replay possible)")
	}
}

// TestBundleUseChallenge_IdenticalAcrossMixedSigningKinds is the REAL
// invariant of the EVM 2-step swap: the approve leg signs with NORMAL signing
// kind (Swap=nil) and the swap leg signs with SWAP signing kind (Swap=set),
// yet ONE owner signature must unlock both legs on-chain.
//
// This test exercises `ComputeOwnerAuthChallenge` (not just BundleUseChallengeInput
// directly) so it covers the full handler ramification path: each leg
// internally computes its own per-leg metadata_digest (V2 for approve, V3 for
// swap), feeds it as `ThisMetadataDigest` into the bundle helper, and the
// resulting hash MUST be identical across legs. If `ComputeOwnerAuthChallenge`
// ever started binding the op_tag or human into the bundle hash, this test
// would catch it.
func TestBundleUseChallenge_IdenticalAcrossMixedSigningKinds(t *testing.T) {
	engine := solana.SystemProgramID
	dwallet := solana.SystemProgramID
	var slot [MemberSlotLen]byte

	// Per-leg metadata_digests as they would be on-chain. The bundle hash binds
	// THESE digests in the canonical order [approve, swap]; each leg reaches
	// the same hash by passing its own digest as ThisMetadataDigest.
	approveMeta := [32]byte{0xAA, 0xAA, 0xAA}
	swapMeta := [32]byte{0xBB, 0xBB, 0xBB}

	// Leg 0 (approve): NORMAL signing kind, this_index=0, others=[swapMeta]
	approveLeg, err := ComputeOwnerAuthChallenge(OwnerAuthInput{
		OwnerSlot:       slot,
		Engine:          engine,
		DWallet:         dwallet,
		MetadataDigest:  approveMeta,
		Destination:     [32]byte{0x99}, // approve leg's destination — informational, NOT bound by bundle
		Amount:          1000,
		SignatureScheme: 0,
		// Swap: nil (NORMAL signing kind for the approve leg)
		Bundle: &BundleProof{
			Total:        2,
			ThisIndex:    0,
			OtherDigests: [][32]byte{swapMeta},
		},
	})
	if err != nil {
		t.Fatalf("approve leg: %v", err)
	}

	// Leg 1 (swap): SWAP signing kind, this_index=1, others=[approveMeta]
	var fromToken, toToken [32]byte
	fromToken[31] = 1
	toToken[31] = 2
	var chainTag [8]byte
	copy(chainTag[:], "evm")
	swapLeg, err := ComputeOwnerAuthChallenge(OwnerAuthInput{
		OwnerSlot:       slot,
		Engine:          engine,
		DWallet:         dwallet,
		MetadataDigest:  swapMeta,
		Destination:     [32]byte{0x77}, // different destination — informational, NOT bound by bundle
		Amount:          2000,           // different amount — informational, NOT bound by bundle
		SignatureScheme: 5,              // different scheme — informational
		Swap: &SwapMeta{
			FromToken:    fromToken,
			ToToken:      toToken,
			MinAmountOut: 50,
			ChainTag:     chainTag,
		},
		Bundle: &BundleProof{
			Total:        2,
			ThisIndex:    1,
			OtherDigests: [][32]byte{approveMeta},
		},
	})
	if err != nil {
		t.Fatalf("swap leg: %v", err)
	}

	if approveLeg.OwnerAuthChallengeHex != swapLeg.OwnerAuthChallengeHex {
		t.Fatalf("bundle hash mismatch across signing kinds (EVM 2-step would break):\n  approve: %s\n  swap   : %s",
			approveLeg.OwnerAuthChallengeHex, swapLeg.OwnerAuthChallengeHex)
	}

	// And the human messages MUST differ — the wallet UI shows a different line
	// per leg (Sign for dWallet / Swap X for Y) even though the hash is the same.
	if approveLeg.HumanMessage == swapLeg.HumanMessage {
		t.Fatalf("expected distinct per-leg human messages, got identical: %q", approveLeg.HumanMessage)
	}
}

// TestBundleUseChallenge_BindsOwnerSlot proves the bundle hash binds the
// owner_slot — a gateway can't reuse a sig from one dWallet owner to authorize
// another dWallet's bundle.
func TestBundleUseChallenge_BindsOwnerSlot(t *testing.T) {
	engine := solana.SystemProgramID
	dwallet := solana.SystemProgramID
	var slotA, slotB [MemberSlotLen]byte
	slotA[0] = 0 // Ed25519, all zero identifier
	slotB[0] = 1 // secp256k1, all zero identifier
	digest0 := [32]byte{0x01}
	digest1 := [32]byte{0x02}

	a := &BundleUseChallengeInput{
		Engine: engine, DWallet: dwallet, OwnerSlot: slotA,
		Total: 2, ThisIndex: 0,
		ThisMetadataDigest: digest0,
		OtherDigests:       [][32]byte{digest1},
	}
	b := &BundleUseChallengeInput{
		Engine: engine, DWallet: dwallet, OwnerSlot: slotB,
		Total: 2, ThisIndex: 0,
		ThisMetadataDigest: digest0,
		OtherDigests:       [][32]byte{digest1},
	}
	ha, _ := a.Hash()
	hb, _ := b.Hash()
	if ha == hb {
		t.Fatal("bundle hash does not bind owner_slot")
	}
}

// TestValidateChainTag exercises the ASCII guard on the swap chain_tag —
// surfaces a tampered tag off-chain instead of leaving it for the Rust
// renderer to reject mid-broadcast.
func TestValidateChainTag(t *testing.T) {
	cases := []struct {
		name    string
		tag     [8]byte
		wantErr bool
	}{
		{"solana", [8]byte{'s', 'o', 'l', 'a', 'n', 'a', 0, 0}, false},
		{"evm:1", [8]byte{'e', 'v', 'm', ':', '1', 0, 0, 0}, false},
		{"all-zero", [8]byte{}, false}, // trailing-zero only is allowed; rendered as empty
		{"non-ascii", [8]byte{'e', 'v', 'm', 0xFF, 0, 0, 0, 0}, true},
		{"control-byte", [8]byte{'s', 0x01, 0, 0, 0, 0, 0, 0}, true},
		{"non-printable-tail-before-nul", [8]byte{'s', 'o', 'l', 0x7F, 0, 0, 0, 0}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateChainTag(tc.tag)
			if tc.wantErr && err == nil {
				t.Errorf("ValidateChainTag(%v) = nil, want error", tc.tag)
			}
			if !tc.wantErr && err != nil {
				t.Errorf("ValidateChainTag(%v) = %v, want nil", tc.tag, err)
			}
		})
	}
}

// TestComputeOwnerAuthChallenge_RejectsBadChainTag proves the guard fires at
// the ComputeOwnerAuthChallenge boundary so the gateway returns a 4xx-shaped
// error instead of letting an invalid tag flow through to the Rust on-chain
// rejection.
func TestComputeOwnerAuthChallenge_RejectsBadChainTag(t *testing.T) {
	var slot [MemberSlotLen]byte
	var fromToken, toToken [32]byte
	fromToken[31] = 1
	toToken[31] = 2
	var badTag [8]byte
	copy(badTag[:], "ev")
	badTag[2] = 0xFF // non-ASCII byte before NUL
	_, err := ComputeOwnerAuthChallenge(OwnerAuthInput{
		OwnerSlot:       slot,
		Engine:          solana.SystemProgramID,
		DWallet:         solana.SystemProgramID,
		MetadataDigest:  [32]byte{0xAA},
		Amount:          100,
		SignatureScheme: 0,
		Swap: &SwapMeta{
			FromToken:    fromToken,
			ToToken:      toToken,
			MinAmountOut: 50,
			ChainTag:     badTag,
		},
	})
	if err == nil || !strings.Contains(err.Error(), "chain_tag") {
		t.Fatalf("expected chain_tag validation error, got %v", err)
	}
}

// TestComputeOwnerAuthChallenge_SwapVsNormal proves the SWAP signing path
// produces a DIFFERENT challenge than NORMAL even with identical metadata —
// the op_tag bump (`swap-sign` vs `normal-sign`) plus the V3 digest both
// contribute to partitioning the precompile-verified message space.
func TestComputeOwnerAuthChallenge_SwapVsNormal(t *testing.T) {
	engine := solana.SystemProgramID
	dwallet := solana.SystemProgramID
	var slot [MemberSlotLen]byte
	in := OwnerAuthInput{
		OwnerSlot:       slot,
		Engine:          engine,
		DWallet:         dwallet,
		MetadataDigest:  [32]byte{0xAA},
		Destination:     [32]byte{0xBB},
		Amount:          100,
		SignatureScheme: 0,
	}
	normal, err := ComputeOwnerAuthChallenge(in)
	if err != nil {
		t.Fatalf("normal: %v", err)
	}

	swapIn := in
	var fromToken, toToken [32]byte
	fromToken[31] = 1
	toToken[31] = 2
	var chainTag [8]byte
	copy(chainTag[:], "solana")
	swapIn.Swap = &SwapMeta{
		FromToken:    fromToken,
		ToToken:      toToken,
		MinAmountOut: 50,
		ChainTag:     chainTag,
	}
	swap, err := ComputeOwnerAuthChallenge(swapIn)
	if err != nil {
		t.Fatalf("swap: %v", err)
	}
	if normal.OwnerAuthChallengeHex == swap.OwnerAuthChallengeHex {
		t.Fatal("NORMAL and SWAP challenges collide (op_tag separation broken)")
	}
	if !strings.HasPrefix(swap.HumanMessage, "Swap ") {
		t.Errorf("swap human message: %q", swap.HumanMessage)
	}
	if !strings.HasPrefix(normal.HumanMessage, "Sign for dWallet ") {
		t.Errorf("normal human message: %q", normal.HumanMessage)
	}
}
