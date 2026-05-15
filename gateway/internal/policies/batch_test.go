package policies

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"testing"

	"github.com/gagliardetto/solana-go"
	"github.com/gagliardetto/solana-go/rpc"

	"github.com/shinkalabs/andromeda-gateway/internal/gasponsor"
)

// ── mergeWithCommon ───────────────────────────────────────────────

func TestMergeWithCommon_InheritsEmptyFields(t *testing.T) {
	common := &requestSignatureReq{
		Template:                TemplateAllowlist,
		DwalletAddress:          "DwAddressBase58111111111111111111111111111111",
		DwalletCurve:            2,
		DwalletPublicKeyB64:     "pk-b64",
		UserPubkeyB64:           "user-b64",
		SignatureScheme:         1,
		CpiAuthorityBump:        253,
		InitAuthorityHashBase64: "hash-b64",
	}
	req := requestSignatureReq{
		MessageDigestB64: "msg-b64",
		Destination:      "DestBase58222222222222222222222222222222222222",
	}
	merged := mergeWithCommon(req, common)

	if merged.Template != TemplateAllowlist {
		t.Errorf("template = %q, want %q", merged.Template, TemplateAllowlist)
	}
	if merged.DwalletAddress != common.DwalletAddress {
		t.Errorf("dwallet_address not inherited from common")
	}
	if merged.MessageDigestB64 != "msg-b64" {
		t.Errorf("message_digest_base64 lost: %q", merged.MessageDigestB64)
	}
	if merged.Destination == "" {
		t.Errorf("destination lost")
	}
	if merged.DwalletCurve != 2 {
		t.Errorf("dwallet_curve = %d, want 2", merged.DwalletCurve)
	}
	if merged.SignatureScheme != 1 {
		t.Errorf("signature_scheme = %d, want 1", merged.SignatureScheme)
	}
}

func TestMergeWithCommon_RequestOverridesCommon(t *testing.T) {
	common := &requestSignatureReq{
		Template:       TemplateAllowlist,
		DwalletAddress: "CommonAddr1111111111111111111111111111111111",
	}
	req := requestSignatureReq{
		Template:       TemplateVelocityGuard,
		DwalletAddress: "OverrideAddr11111111111111111111111111111111",
	}
	merged := mergeWithCommon(req, common)
	if merged.Template != TemplateVelocityGuard {
		t.Errorf("override lost: template = %q", merged.Template)
	}
	if merged.DwalletAddress != "OverrideAddr11111111111111111111111111111111" {
		t.Errorf("override lost: dwallet = %q", merged.DwalletAddress)
	}
}

func TestMergeWithCommon_NilCommonReturnsRequest(t *testing.T) {
	req := requestSignatureReq{Template: TemplateTimeLock}
	merged := mergeWithCommon(req, nil)
	if merged.Template != TemplateTimeLock {
		t.Errorf("nil common changed request: %q", merged.Template)
	}
}

func TestMergeWithCommon_PointerFieldsInherit(t *testing.T) {
	amt := uint64(42)
	idx := uint32(7)
	common := &requestSignatureReq{
		TxAmount:     &amt,
		SessionIndex: &idx,
	}
	req := requestSignatureReq{}
	merged := mergeWithCommon(req, common)
	if merged.TxAmount == nil || *merged.TxAmount != 42 {
		t.Errorf("tx_amount inheritance failed")
	}
	if merged.SessionIndex == nil || *merged.SessionIndex != 7 {
		t.Errorf("session_index inheritance failed")
	}
}

// ── flattenIxs / ixCountTotal / uniqueExtras ──────────────────────

func TestFlattenIxsAndCount(t *testing.T) {
	prog := solana.MustPublicKeyFromBase58("11111111111111111111111111111112")
	ix := solana.NewInstruction(prog, solana.AccountMetaSlice{}, []byte{1})
	groups := []builtRequest{
		{idx: 0, ixs: []solana.Instruction{ix}},
		{idx: 1, ixs: []solana.Instruction{ix, ix}}, // precompile + main
	}
	if got := ixCountTotal(groups); got != 3 {
		t.Fatalf("ixCountTotal = %d, want 3", got)
	}
	if got := len(flattenIxs(groups)); got != 3 {
		t.Fatalf("flattenIxs len = %d, want 3", got)
	}
}

func TestUniqueExtras_DedupAndDropPayer(t *testing.T) {
	payer := solana.MustPublicKeyFromBase58("11111111111111111111111111111112")
	a := solana.MustPublicKeyFromBase58("So11111111111111111111111111111111111111112")
	b := solana.MustPublicKeyFromBase58("ComputeBudget111111111111111111111111111111")
	groups := []builtRequest{
		{extras: []solana.PublicKey{a, payer}},
		{extras: []solana.PublicKey{b, a}}, // dup `a`, payer must be dropped
	}
	got := uniqueExtras(groups, payer)
	if len(got) != 2 {
		t.Fatalf("uniqueExtras len = %d, want 2 (%v)", len(got), got)
	}
	for _, k := range got {
		if k.Equals(payer) {
			t.Fatalf("payer leaked into extras")
		}
	}
}

// ── end-to-end build for one template (allowlist) ─────────────────

// newTestService spins up a Service backed by a temporary Registry + a fresh
// gas sponsor keypair. The Registry maps every supported template to a
// random program id so build helpers don't trip on ErrTemplateNotDeployed.
// No RPC calls are issued by `buildRequestSigInstructions` itself, so we
// leave RPCClient nil.
func newTestService(t *testing.T) *Service {
	t.Helper()
	reg := &Registry{
		IkaProgramID:   solana.NewWallet().PublicKey(),
		IkaCoordinator: solana.NewWallet().PublicKey(),
		ProgramIDs: map[string]solana.PublicKey{
			TemplateAllowlist:         solana.NewWallet().PublicKey(),
			TemplateVelocityGuard:     solana.NewWallet().PublicKey(),
			TemplateTimeLock:          solana.NewWallet().PublicKey(),
			TemplateOracleConditional: solana.NewWallet().PublicKey(),
			TemplatePasskeyStepUp:     solana.NewWallet().PublicKey(),
			TemplateFHEGated:          solana.NewWallet().PublicKey(),
			TemplateSessionKeys:       solana.NewWallet().PublicKey(),
		},
	}

	// Build a gas sponsor from a fresh ed25519 keypair serialized in the
	// `solana-keygen` 64-byte JSON format the gasponsor package expects.
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate sponsor key: %v", err)
	}
	raw := make([]int, 64)
	for i, b := range priv {
		raw[i] = int(b)
	}
	keypairJSON, err := json.Marshal(raw)
	if err != nil {
		t.Fatalf("marshal sponsor key: %v", err)
	}
	// Real *rpc.Client is needed by gasponsor.New; we never dial it from
	// these pure-build tests (no `SignAndSend` / `Balance` calls).
	sponsor, err := gasponsor.New(string(keypairJSON), rpc.New("http://invalid.localhost:0"))
	if err != nil {
		t.Fatalf("gasponsor.New: %v", err)
	}

	return &Service{
		Registry:   reg,
		GasSponsor: sponsor,
	}
}

// Lightweight sanity: building each template via the SDK's request-shape
// inputs produces non-nil ixs and the expected extras shape. Each case
// uses freshly-generated bytes so PDA derivation succeeds.
func TestBuildRequestSigInstructions_TemplateMatrix(t *testing.T) {
	s := newTestService(t)
	dw := solana.NewWallet().PublicKey().String()
	pk := make([]byte, 32)
	_, _ = rand.Read(pk)
	digest := make([]byte, 32)
	_, _ = rand.Read(digest)
	user := make([]byte, 32)
	_, _ = rand.Read(user)
	initAuth := make([]byte, 32)
	_, _ = rand.Read(initAuth)

	base := requestSignatureReq{
		DwalletAddress:          dw,
		DwalletCurve:            2,
		DwalletPublicKeyB64:     base64.StdEncoding.EncodeToString(pk),
		MessageDigestB64:        base64.StdEncoding.EncodeToString(digest),
		UserPubkeyB64:           base64.StdEncoding.EncodeToString(user),
		SignatureScheme:         1,
		InitAuthorityHashBase64: base64.StdEncoding.EncodeToString(initAuth),
	}

	t.Run("allowlist single ix no extras", func(t *testing.T) {
		req := base
		req.Template = TemplateAllowlist
		req.Destination = solana.NewWallet().PublicKey().String()
		ixs, extras, err := s.buildRequestSigInstructions(context.Background(), req)
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		if len(ixs) != 1 {
			t.Errorf("ixs = %d, want 1", len(ixs))
		}
		if len(extras) != 0 {
			t.Errorf("extras = %v, want none", extras)
		}
	})

	t.Run("velocity-guard single ix no extras", func(t *testing.T) {
		req := base
		req.Template = TemplateVelocityGuard
		ixs, extras, err := s.buildRequestSigInstructions(context.Background(), req)
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		if len(ixs) != 1 || len(extras) != 0 {
			t.Errorf("ixs=%d extras=%v", len(ixs), extras)
		}
	})

	t.Run("time-lock single ix no extras", func(t *testing.T) {
		req := base
		req.Template = TemplateTimeLock
		ixs, _, err := s.buildRequestSigInstructions(context.Background(), req)
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		if len(ixs) != 1 {
			t.Errorf("ixs = %d, want 1", len(ixs))
		}
	})

	t.Run("oracle-conditional needs feed", func(t *testing.T) {
		req := base
		req.Template = TemplateOracleConditional
		_, _, err := s.buildRequestSigInstructions(context.Background(), req)
		if err == nil {
			t.Fatalf("missing oracle_feed should error")
		}
		req.OracleFeed = solana.NewWallet().PublicKey().String()
		ixs, _, err := s.buildRequestSigInstructions(context.Background(), req)
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		if len(ixs) != 1 {
			t.Errorf("ixs = %d, want 1", len(ixs))
		}
	})

	t.Run("passkey below-threshold one ix", func(t *testing.T) {
		amt := uint64(10)
		req := base
		req.Template = TemplatePasskeyStepUp
		req.TxAmount = &amt
		ixs, _, err := s.buildRequestSigInstructions(context.Background(), req)
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		if len(ixs) != 1 {
			t.Errorf("below-threshold ixs = %d, want 1", len(ixs))
		}
	})

	t.Run("passkey step-up emits precompile+main", func(t *testing.T) {
		amt := uint64(10_000)
		nonce := uint64(1)
		pkBytes := make([]byte, 33)
		_, _ = rand.Read(pkBytes)
		sig := make([]byte, 64)
		_, _ = rand.Read(sig)
		req := base
		req.Template = TemplatePasskeyStepUp
		req.StepUp = true
		req.TxAmount = &amt
		req.ExpectedStepUpNonce = &nonce
		req.PasskeyPubkeyB64 = base64.StdEncoding.EncodeToString(pkBytes)
		req.WebauthnAuthDataB64 = base64.StdEncoding.EncodeToString([]byte{1, 2, 3, 4})
		req.WebauthnCDJB64 = base64.StdEncoding.EncodeToString([]byte(`{"type":"webauthn.get"}`))
		req.WebauthnSignatureB64 = base64.StdEncoding.EncodeToString(sig)
		ixs, _, err := s.buildRequestSigInstructions(context.Background(), req)
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		if len(ixs) != 2 {
			t.Errorf("step-up ixs = %d, want 2 (precompile + main)", len(ixs))
		}
	})

	t.Run("fhe-gated emits precompile+main", func(t *testing.T) {
		slot := uint64(123_456)
		auth := uint8(1)
		sig := make([]byte, 64)
		_, _ = rand.Read(sig)
		req := base
		req.Template = TemplateFHEGated
		req.DecisionCreatedSlot = &slot
		req.DecisionAuthorize = &auth
		req.DecisionSignatureB64 = base64.StdEncoding.EncodeToString(sig)
		req.FHEAuthority = solana.NewWallet().PublicKey().String()
		ixs, _, err := s.buildRequestSigInstructions(context.Background(), req)
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		if len(ixs) != 2 {
			t.Errorf("fhe-gated ixs = %d, want 2", len(ixs))
		}
	})

	t.Run("session-keys reports session_signer as extra", func(t *testing.T) {
		idx := uint32(0)
		amt := uint64(1_000)
		nonce := uint64(0)
		signer := solana.NewWallet().PublicKey()
		req := base
		req.Template = TemplateSessionKeys
		req.SessionIndex = &idx
		req.SessionSigner = signer.String()
		req.Amount = &amt
		req.ExpectedSignatureNonceB = &nonce
		req.DestinationProgram = solana.NewWallet().PublicKey().String()
		ixs, extras, err := s.buildRequestSigInstructions(context.Background(), req)
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		if len(ixs) != 1 {
			t.Errorf("session-keys ixs = %d, want 1", len(ixs))
		}
		if len(extras) != 1 || !extras[0].Equals(signer) {
			t.Errorf("extras = %v, want [%s]", extras, signer)
		}
	})
}
