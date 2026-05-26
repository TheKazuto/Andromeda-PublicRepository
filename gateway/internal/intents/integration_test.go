package intents

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/shinkalabs/andromeda-gateway/internal/config"
	"github.com/shinkalabs/andromeda-gateway/internal/policy"
	"github.com/shinkalabs/andromeda-gateway/internal/upstream"
)

// --- fakes ----------------------------------------------------------------

type fakeStore struct {
	mu sync.Mutex
	m  map[string]*Intent
}

func newFakeStore() *fakeStore { return &fakeStore{m: map[string]*Intent{}} }

func (f *fakeStore) InsertPrepared(_ context.Context, it *Intent) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	it.ID = uuid.NewString()
	it.UpdatedAt = time.Now()
	cp := *it
	f.m[it.ID] = &cp
	return nil
}
func (f *fakeStore) GetForUser(_ context.Context, id, userID string) (*Intent, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	it, ok := f.m[id]
	if !ok || it.UserID != userID {
		return nil, ErrNotFound
	}
	cp := *it
	return &cp, nil
}
func (f *fakeStore) set(id string, fn func(*Intent)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if it, ok := f.m[id]; ok {
		fn(it)
		it.UpdatedAt = time.Now()
	}
}
func (f *fakeStore) CASStatus(_ context.Context, id, from, to, _ string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	it, ok := f.m[id]
	if !ok || it.Status != from {
		return ErrConflict
	}
	it.Status = to
	return nil
}
func (f *fakeStore) SetStatus(_ context.Context, id, status string) error {
	f.set(id, func(it *Intent) { it.Status = status })
	return nil
}
func (f *fakeStore) SetError(_ context.Context, id, status, _ string) error {
	f.set(id, func(it *Intent) { it.Status = status })
	return nil
}
func (f *fakeStore) SaveApproval(_ context.Context, id, txSig string, slot uint64, presign, digest string) error {
	f.set(id, func(it *Intent) { it.ApprovalTxSig = txSig; it.ApprovalSlot = slot; it.PresignSessionID = presign })
	return nil
}
func (f *fakeStore) SaveERC20Approve(_ context.Context, id, txHash string) error {
	f.set(id, func(it *Intent) { it.Status = StatusApproving; it.ApproveTxHash = txHash })
	return nil
}
func (f *fakeStore) SaveRisk(_ context.Context, _ string, _ json.RawMessage) error { return nil }
func (f *fakeStore) SaveBroadcast(_ context.Context, id, status, txHash string) error {
	f.set(id, func(it *Intent) { it.Status = status; it.SwapTxHash = txHash })
	return nil
}
func (f *fakeStore) ListOpenOlderThan(context.Context, time.Duration, int) ([]*Intent, error) {
	return nil, nil
}
func (f *fakeStore) OldestOpenAgeByStatus(context.Context) (map[string]float64, error) {
	return map[string]float64{}, nil
}

type fakeAuthorizer struct {
	requireOwnerAuth bool // when true, AuthorizeSwap rejects calls without OwnerSlotHex / OwnerSignatureBase64
}

// fakeChallengeDigest is a deterministic, distinct-per-leg 32-byte digest
// the fakeAuthorizer returns from SwapChallengeDigest / AuthorizeSwap. It
// depends on `MessageDigestHex` so the EVM 2-step path produces DIFFERENT
// metadata_digests for the approve and swap legs (otherwise the bundle
// ordering test would degenerate). Hex string, always 64 chars.
func fakeChallengeDigest(in policy.SwapAuthorizeInput) string {
	// Prefix the input message digest into a 32-byte output; pad with zeros.
	// Truncate the input to 60 chars max to keep length ≤ 64.
	src := in.MessageDigestHex
	if len(src) > 60 {
		src = src[:60]
	}
	pad := ""
	for i := 0; i < 64-len(src); i++ {
		pad += "0"
	}
	return src + pad
}

func (f fakeAuthorizer) AuthorizeSwap(_ context.Context, in policy.SwapAuthorizeInput) (policy.AuthorizeResult, error) {
	if f.requireOwnerAuth && (in.OwnerSlotHex == "" || in.OwnerSignatureBase64 == "") {
		return policy.AuthorizeResult{}, errOwnerAuthRequired
	}
	return policy.AuthorizeResult{
		TxSignature:       "FakeApprovalSig",
		ApprovalSlot:      123,
		MetadataDigestHex: fakeChallengeDigest(in),
	}, nil
}
func (fakeAuthorizer) SwapChallengeDigest(in policy.SwapAuthorizeInput) (string, error) {
	return fakeChallengeDigest(in), nil
}
func (fakeAuthorizer) SwapOwnerAuthChallenge(in policy.SwapAuthorizeInput) (policy.OwnerAuthChallenge, error) {
	if in.OwnerSlotHex == "" {
		return policy.OwnerAuthChallenge{}, errOwnerAuthRequired
	}
	return policy.OwnerAuthChallenge{
		OwnerAuthChallengeHex: "cafebabe" + in.MessageDigestHex,
		OwnerAuthPreimageHex:  "deadbeef",
		HumanMessage:          "Sign for dWallet (test) amount 0 scheme 0",
	}, nil
}
func (fakeAuthorizer) FirePresignPrefetchDirect(string, string, string) {}
func (fakeAuthorizer) HarvestPresignDirect(context.Context, string, string) string {
	return ""
}
func (fakeAuthorizer) EvaluateSwapRisk(context.Context, policy.SwapRiskInput) json.RawMessage {
	return json.RawMessage(`{"digestVerified":true}`)
}

var errOwnerAuthRequired = newFakeErr("owner_auth_required")

type fakeErr string

func (e fakeErr) Error() string { return string(e) }

func newFakeErr(s string) error { return fakeErr(s) }

// Canonical owner slot used by tests: scheme=0 (Ed25519), 33-byte zero-padded
// identifier. 34 bytes total = 68 hex chars.
const testOwnerSlotHex = "00000000000000000000000000000000000000000000000000000000000000000000"

// validSubmitOwnerAuth returns the swap-only owner_signatures payload the
// fakeAuthorizer accepts (1 entry, kind=swap, non-empty base64).
func validSubmitOwnerAuth() []ownerSignature {
	return []ownerSignature{{Kind: "swap", SignatureBase64: "ZmFrZXNpZw=="}}
}

// --- mock upstreams -------------------------------------------------------

// consistent signing material shared across the mock /prepare, prepare-message
// and /derive-message so re-validation passes.
const (
	mMsgHex    = "abcd"
	mDigestHex = "00ff"
	mTxHash    = "1111"
	mUnsignedB = "AQID" // base64; opaque to the gateway (mock derives from it)
)

func mockIntentsBackend(t *testing.T) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/prepare":
			_, _ = io.WriteString(w, `{"chainKind":"solana","chainId":1151111081099710,"signChainId":"solana:x",
				"signScheme":5,"chainNativeAddress":"SoLaddr","unsignedTxB64":"`+mUnsignedB+`",
				"messageToSignHex":"`+mMsgHex+`","unsignedTxHash":"`+mTxHash+`","amountOut":"5000000",
				"amountOutMin":"4950000","transactionFeeUsd":"0.30","nativeFeeEstimate":"5000","routeSnapshot":{"tool":"jupiter"}}`)
		case r.Method == http.MethodPost && r.URL.Path == "/derive-message":
			_, _ = io.WriteString(w, `{"messageToSignHex":"`+mMsgHex+`","digestHex":"`+mDigestHex+`","unsignedTxHash":"`+mTxHash+`"}`)
		case r.Method == http.MethodGet && r.URL.Path == "/native-balance":
			_, _ = io.WriteString(w, `{"balance":"1000000000"}`)
		case r.Method == http.MethodPost && r.URL.Path == "/finalize":
			_, _ = io.WriteString(w, `{"txHash":"FakeSwapTxHash","broadcastUnknown":false}`)
		default:
			http.Error(w, "not found", http.StatusNotFound)
		}
	}))
}

func mockIka(t *testing.T) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/v1/dwallet/prepare-message":
			_, _ = io.WriteString(w, `{"data":{"preprocessedHex":"`+mMsgHex+`","digestHex":"`+mDigestHex+`",
				"scheme":5,"messageMetadataHex":"","ikaMsgMetadataDigestHex":"`+zero32hex()+`"}}`)
		case "/v1/dwallet/sign":
			_, _ = io.WriteString(w, `{"data":{"signatureBase64":"ZmFrZXNpZw=="}}`)
		default:
			http.Error(w, "not found", http.StatusNotFound)
		}
	}))
}

func zero32hex() string {
	s := ""
	for i := 0; i < 32; i++ {
		s += "00"
	}
	return s
}

func newTestRegistry(t *testing.T, intentsURL, ikaURL string) *upstream.Registry {
	t.Helper()
	cfg := &config.Config{
		IkaUpstreamURL:     ikaURL,
		IntentsUpstreamURL: intentsURL,
		InternalAPIKey:     "test-key",
		UpstreamTimeout:    5 * time.Second,
	}
	ups, err := upstream.NewRegistry(cfg)
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}
	return ups
}

// --- test -----------------------------------------------------------------

func TestSwapFlowSolana(t *testing.T) {
	ib := mockIntentsBackend(t)
	defer ib.Close()
	ika := mockIka(t)
	defer ika.Close()

	store := newFakeStore()
	orch := NewOrchestrator(Options{
		Store:      store,
		Upstreams:  newTestRegistry(t, ib.URL, ika.URL),
		Authorizer: fakeAuthorizer{},
		Logger:     slog.New(slog.NewTextHandler(io.Discard, nil)),
	})

	ctx := context.Background()
	userID := "user-1"
	apiKey := uuid.NewString()
	req := prepareRequest{
		DwalletAddress:       "SoLDwalletAddr",
		DwalletPublicKeyHex:  zero32hex(), // 32-byte hex
		OwnerPubkeyHex:       zero32hex(),
		InitAuthorityHashHex: zero32hex(),
		IkaCurve:             2,
		ChainKind:            "solana",
		FromChain:            "SOL",
		ToChain:              "SOL",
		FromToken:            "USDC",
		ToToken:              "SOL",
		FromAmount:           "1000000",
	}

	// Prepare
	prep, err := orch.Prepare(ctx, userID, apiKey, req)
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	if prep.Status != StatusPrepared || prep.IntentID == "" {
		t.Fatalf("unexpected prepare resp: %+v", prep)
	}
	if prep.MessageDigestHex != mDigestHex {
		t.Errorf("MessageDigestHex = %q, want %q", prep.MessageDigestHex, mDigestHex)
	}

	// Submit
	sub, err := orch.Submit(ctx, userID, submitRequest{
		IntentID:        prep.IntentID,
		Passphrase:      "passphrase-123",
		OwnerSlotHex:    testOwnerSlotHex,
		OwnerSignatures: validSubmitOwnerAuth(),
	})
	if err != nil {
		t.Fatalf("Submit: %v", err)
	}
	if sub.Status != StatusSubmitted {
		t.Fatalf("submit status = %q, want SUBMITTED", sub.Status)
	}
	if sub.TxHash != "FakeSwapTxHash" {
		t.Errorf("txHash = %q, want FakeSwapTxHash", sub.TxHash)
	}

	// Persisted state reflects the broadcast.
	it, err := store.GetForUser(ctx, prep.IntentID, userID)
	if err != nil {
		t.Fatalf("GetForUser: %v", err)
	}
	if it.Status != StatusSubmitted || it.SwapTxHash != "FakeSwapTxHash" {
		t.Errorf("persisted intent = %+v", it)
	}
}

// TestSubmitRejectsMissingOwnerAuth proves the zero-trust guard: a swap submit
// without ownerSignatures returns 4xx and does NOT transition the intent out of
// PREPARED — the gateway must never relay a request_signature without the
// dWallet owner's precompile.
func TestSubmitRejectsMissingOwnerAuth(t *testing.T) {
	ib := mockIntentsBackend(t)
	defer ib.Close()
	ika := mockIka(t)
	defer ika.Close()

	store := newFakeStore()
	orch := NewOrchestrator(Options{
		Store:      store,
		Upstreams:  newTestRegistry(t, ib.URL, ika.URL),
		Authorizer: fakeAuthorizer{requireOwnerAuth: true},
		Logger:     slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	ctx := context.Background()
	req := prepareRequest{
		DwalletAddress: "d", DwalletPublicKeyHex: zero32hex(), OwnerPubkeyHex: zero32hex(),
		InitAuthorityHashHex: zero32hex(), IkaCurve: 2, ChainKind: "solana",
		FromChain: "SOL", ToChain: "SOL", FromToken: "USDC", ToToken: "SOL", FromAmount: "1000000",
	}
	prep, err := orch.Prepare(ctx, "u", uuid.NewString(), req)
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}

	if _, err := orch.Submit(ctx, "u", submitRequest{
		IntentID:   prep.IntentID,
		Passphrase: "passphrase-123",
		// no OwnerSlotHex, no OwnerSignatures → must be rejected as 4xx
	}); err == nil {
		t.Fatal("Submit without owner sigs: want error, got nil")
	} else {
		var ue *userError
		if !errorsAs(err, &ue) || ue.status < 400 || ue.status >= 500 {
			t.Fatalf("want 4xx userError, got %#v", err)
		}
	}

	// Intent stays in PREPARED — no state mutation, no on-chain leak.
	it, err := store.GetForUser(ctx, prep.IntentID, "u")
	if err != nil {
		t.Fatalf("GetForUser: %v", err)
	}
	if it.Status != StatusPrepared {
		t.Fatalf("after rejected submit, status=%q, want PREPARED", it.Status)
	}
}

// TestChallengeReturnsOwnerAuthLeg proves /v1/intents/swap/challenge derives a
// non-empty challenge for a prepared swap (single leg on Solana).
func TestChallengeReturnsOwnerAuthLeg(t *testing.T) {
	ib := mockIntentsBackend(t)
	defer ib.Close()
	ika := mockIka(t)
	defer ika.Close()

	store := newFakeStore()
	orch := NewOrchestrator(Options{
		Store:      store,
		Upstreams:  newTestRegistry(t, ib.URL, ika.URL),
		Authorizer: fakeAuthorizer{},
		Logger:     slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	ctx := context.Background()
	prep, err := orch.Prepare(ctx, "u", uuid.NewString(), prepareRequest{
		DwalletAddress: "d", DwalletPublicKeyHex: zero32hex(), OwnerPubkeyHex: zero32hex(),
		InitAuthorityHashHex: zero32hex(), IkaCurve: 2, ChainKind: "solana",
		FromChain: "SOL", ToChain: "SOL", FromToken: "USDC", ToToken: "SOL", FromAmount: "1000000",
	})
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	ch, err := orch.Challenge(ctx, "u", challengeRequest{IntentID: prep.IntentID, OwnerSlotHex: testOwnerSlotHex})
	if err != nil {
		t.Fatalf("Challenge: %v", err)
	}
	if len(ch.Challenges) != 1 {
		t.Fatalf("len(challenges)=%d, want 1 (solana same-chain has no approve)", len(ch.Challenges))
	}
	leg := ch.Challenges[0]
	if leg.Kind != "swap" || leg.OwnerAuthChallengeHex == "" || leg.HumanMessage == "" {
		t.Fatalf("unexpected leg: %+v", leg)
	}
}

// errorsAs is a thin wrapper so the test stays readable without importing
// errors at the top.
func errorsAs(err error, target any) bool {
	for err != nil {
		if t, ok := target.(**userError); ok {
			if ue, isUE := err.(*userError); isUE {
				*t = ue
				return true
			}
		}
		u, ok := err.(interface{ Unwrap() error })
		if !ok {
			return false
		}
		err = u.Unwrap()
	}
	return false
}

// EVM 2-step constants. Swap and approve carry 32-byte digests (= 64 hex
// chars) because the bundle path in the orchestrator hex-decodes them and
// requires exactly 32 bytes before computing per-leg metadata digests.
const (
	mEvmApproveMsgHex    = "deadbeef"
	mEvmApproveDigestHex = "cafe000000000000000000000000000000000000000000000000000000000000"
	mEvmSwapDigestHex    = "beef000000000000000000000000000000000000000000000000000000000000"
	mEvmApproveUnsigned  = "QkJC" // base64
	mEvmApproveTxHash    = "0xaa11"
)

// mockEvmIntentsBackend extends the Solana mock with an EVM 2-step swap:
// prepare returns an `approval` block (which triggers the approve leg),
// derive-message reflects whichever payload it gets, the receipt polls
// confirm-success, and finalize echoes back distinct tx hashes for approve
// vs swap.
func mockEvmIntentsBackend(t *testing.T) *httptest.Server {
	finalizeCount := 0
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/prepare":
			_, _ = io.WriteString(w, `{
				"chainKind":"evm","chainId":1,"signChainId":"eip155:1",
				"signScheme":1,"chainNativeAddress":"0xFromAddr",
				"unsignedTxB64":"`+mUnsignedB+`",
				"messageToSignHex":"`+mMsgHex+`","unsignedTxHash":"`+mTxHash+`",
				"amountOut":"5000000","amountOutMin":"4950000",
				"transactionFeeUsd":"0.30","nativeFeeEstimate":"5000",
				"routeSnapshot":{"tool":"lifi"},
				"evmNonce":42,
				"approval":{"unsignedTxB64":"`+mEvmApproveUnsigned+`",
				             "messageToSignHex":"`+mEvmApproveMsgHex+`",
				             "token":"0xTokenAddr","spender":"0xRouterAddr","nonce":41}
			}`)
		case r.Method == http.MethodPost && r.URL.Path == "/derive-message":
			body, _ := io.ReadAll(r.Body)
			if strings.Contains(string(body), mEvmApproveUnsigned) {
				_, _ = io.WriteString(w, `{"messageToSignHex":"`+mEvmApproveMsgHex+`","digestHex":"`+mEvmApproveDigestHex+`","unsignedTxHash":"0xapprove"}`)
				return
			}
			_, _ = io.WriteString(w, `{"messageToSignHex":"`+mMsgHex+`","digestHex":"`+mEvmSwapDigestHex+`","unsignedTxHash":"`+mTxHash+`"}`)
		case r.Method == http.MethodGet && r.URL.Path == "/native-balance":
			_, _ = io.WriteString(w, `{"balance":"1000000000"}`)
		case r.Method == http.MethodGet && r.URL.Path == "/evm/receipt":
			_, _ = io.WriteString(w, `{"found":true,"success":true}`)
		case r.Method == http.MethodPost && r.URL.Path == "/finalize":
			finalizeCount++
			if finalizeCount == 1 {
				_, _ = io.WriteString(w, `{"txHash":"`+mEvmApproveTxHash+`","broadcastUnknown":false}`)
			} else {
				_, _ = io.WriteString(w, `{"txHash":"0xswap","broadcastUnknown":false}`)
			}
		default:
			http.Error(w, "not found", http.StatusNotFound)
		}
	}))
}

// mockEvmIka mirrors mockIka but the prepare-message returns the matching
// digest for whichever payload it's given (approve or swap), so the
// orchestrator can persist distinct ApproveMessageDigestHex + MessageDigestHex.
func mockEvmIka(t *testing.T) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/v1/dwallet/prepare-message":
			body, _ := io.ReadAll(r.Body)
			if strings.Contains(string(body), mEvmApproveMsgHex) {
				_, _ = io.WriteString(w, `{"data":{"preprocessedHex":"`+mEvmApproveMsgHex+`","digestHex":"`+mEvmApproveDigestHex+`","scheme":1,"messageMetadataHex":"","ikaMsgMetadataDigestHex":"`+zero32hex()+`"}}`)
				return
			}
			_, _ = io.WriteString(w, `{"data":{"preprocessedHex":"`+mMsgHex+`","digestHex":"`+mEvmSwapDigestHex+`","scheme":1,"messageMetadataHex":"","ikaMsgMetadataDigestHex":"`+zero32hex()+`"}}`)
		case "/v1/dwallet/sign":
			_, _ = io.WriteString(w, `{"data":{"signatureBase64":"ZmFrZXNpZw=="}}`)
		default:
			http.Error(w, "not found", http.StatusNotFound)
		}
	}))
}

// TestEvmTwoStepSwap_BundleSignatureUnlocksBothLegs is the end-to-end
// integration test for Update 7's bundle path: an EVM swap that requires an
// ERC20 approve runs approve → confirm → swap with a SINGLE owner signature
// (kind "bundle") covering both legs. Proves the orchestrator wires the
// BundleProof correctly per-leg (ThisIndex 0 for approve, 1 for swap) and
// that the intent reaches SUBMITTED after a single Submit call (the inline
// approve receipt wait succeeds because the mock returns found+success
// immediately).
func TestEvmTwoStepSwap_BundleSignatureUnlocksBothLegs(t *testing.T) {
	ib := mockEvmIntentsBackend(t)
	defer ib.Close()
	ika := mockEvmIka(t)
	defer ika.Close()

	store := newFakeStore()
	orch := NewOrchestrator(Options{
		Store:      store,
		Upstreams:  newTestRegistry(t, ib.URL, ika.URL),
		Authorizer: fakeAuthorizer{},
		Logger:     slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	ctx := context.Background()
	userID := "u-evm"
	apiKey := uuid.NewString()
	req := prepareRequest{
		DwalletAddress:       "DwalletEvm",
		DwalletPublicKeyHex:  zero32hex(),
		OwnerPubkeyHex:       zero32hex(),
		InitAuthorityHashHex: zero32hex(),
		IkaCurve:             0,
		ChainKind:            "evm",
		ChainNativeAddress:   "0xFromAddr",
		FromChain:            "1",
		ToChain:              "1",
		FromToken:            "0x1111111111111111111111111111111111111111",
		ToToken:              "0x2222222222222222222222222222222222222222",
		FromAmount:           "1000000",
	}
	prep, err := orch.Prepare(ctx, userID, apiKey, req)
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	if prep.Status != StatusPrepared {
		t.Fatalf("unexpected prepare status: %s", prep.Status)
	}
	// Confirm the intent carries the approve material (the EVM 2-step path).
	it, err := store.GetForUser(ctx, prep.IntentID, userID)
	if err != nil {
		t.Fatalf("load intent: %v", err)
	}
	if it.ApproveMessageDigestHex == "" {
		t.Fatal("intent missing ApproveMessageDigestHex — mock did not surface the approval")
	}

	// Submit with ONE bundle signature. The orchestrator must:
	//  1) authorize+sign+broadcast the approve leg (ThisIndex=0),
	//  2) poll the approve receipt (mock returns confirmed immediately),
	//  3) authorize+sign+broadcast the swap leg (ThisIndex=1) reusing the
	//     SAME bundle signature.
	subReq := submitRequest{
		IntentID:        prep.IntentID,
		Passphrase:      "passphrase-bundle-12",
		OwnerSlotHex:    testOwnerSlotHex,
		OwnerSignatures: []ownerSignature{{Kind: "bundle", SignatureBase64: "ZmFrZXNpZw=="}},
	}
	resp, err := orch.Submit(ctx, userID, subReq)
	if err != nil {
		t.Fatalf("Submit: %v", err)
	}
	if resp.Status != StatusSubmitted {
		t.Fatalf("expected SUBMITTED, got %q (txHash=%q)", resp.Status, resp.TxHash)
	}
	if resp.TxHash != "0xswap" {
		t.Errorf("expected swap txHash=0xswap, got %q", resp.TxHash)
	}

	// Persisted state: the approve tx hash must have been recorded along the
	// way, and the final status is the swap broadcast.
	final, _ := store.GetForUser(ctx, prep.IntentID, userID)
	if final.ApproveTxHash != mEvmApproveTxHash {
		t.Errorf("expected approve tx hash %q, got %q", mEvmApproveTxHash, final.ApproveTxHash)
	}
	if final.SwapTxHash != "0xswap" {
		t.Errorf("expected swap tx hash 0xswap, got %q", final.SwapTxHash)
	}
}

// TestEvmTwoStepSwap_RejectsSwapKindSignature proves the orchestrator's
// validateOwnerSignatures correctly distinguishes EVM 2-step (needs "bundle")
// from single-leg (needs "swap"). Sending a "swap" sig to an EVM 2-step swap
// is rejected 400 — prevents the dev from accidentally bypassing the bundle
// signing model.
func TestEvmTwoStepSwap_RejectsSwapKindSignature(t *testing.T) {
	ib := mockEvmIntentsBackend(t)
	defer ib.Close()
	ika := mockEvmIka(t)
	defer ika.Close()

	store := newFakeStore()
	orch := NewOrchestrator(Options{
		Store:      store,
		Upstreams:  newTestRegistry(t, ib.URL, ika.URL),
		Authorizer: fakeAuthorizer{},
		Logger:     slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	ctx := context.Background()
	req := prepareRequest{
		DwalletAddress:       "DwalletEvm",
		DwalletPublicKeyHex:  zero32hex(),
		OwnerPubkeyHex:       zero32hex(),
		InitAuthorityHashHex: zero32hex(),
		IkaCurve:             0,
		ChainKind:            "evm",
		ChainNativeAddress:   "0xFromAddr",
		FromChain:            "1",
		ToChain:              "1",
		FromToken:            "0x1111111111111111111111111111111111111111",
		ToToken:              "0x2222222222222222222222222222222222222222",
		FromAmount:           "1000000",
	}
	prep, err := orch.Prepare(ctx, "u-evm-reject", uuid.NewString(), req)
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}

	// Sending a "swap" sig (single-leg shape) to an EVM 2-step intent should
	// fail with the bundle-required error.
	_, err = orch.Submit(ctx, "u-evm-reject", submitRequest{
		IntentID:        prep.IntentID,
		Passphrase:      "passphrase-bundle-12",
		OwnerSlotHex:    testOwnerSlotHex,
		OwnerSignatures: []ownerSignature{{Kind: "swap", SignatureBase64: "ZmFrZXNpZw=="}},
	})
	if err == nil {
		t.Fatal("expected error for swap-kind sig on EVM 2-step swap, got nil")
	}
	var ue *userError
	if !errorsAs(err, &ue) || ue.code != "owner_auth_bundle_required" {
		t.Fatalf("expected owner_auth_bundle_required code, got %v", err)
	}
}

// A second submit (idempotent) returns the current state, not a new swap.
func TestSubmitIdempotentAfterSubmitted(t *testing.T) {
	ib := mockIntentsBackend(t)
	defer ib.Close()
	ika := mockIka(t)
	defer ika.Close()

	store := newFakeStore()
	orch := NewOrchestrator(Options{
		Store:      store,
		Upstreams:  newTestRegistry(t, ib.URL, ika.URL),
		Authorizer: fakeAuthorizer{},
		Logger:     slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	ctx := context.Background()
	req := prepareRequest{
		DwalletAddress: "d", DwalletPublicKeyHex: zero32hex(), OwnerPubkeyHex: zero32hex(),
		InitAuthorityHashHex: zero32hex(), IkaCurve: 2, ChainKind: "solana",
		FromChain: "SOL", ToChain: "SOL", FromToken: "USDC", ToToken: "SOL", FromAmount: "1000000",
	}
	prep, err := orch.Prepare(ctx, "u", uuid.NewString(), req)
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	subReq := submitRequest{
		IntentID:        prep.IntentID,
		Passphrase:      "passphrase-123",
		OwnerSlotHex:    testOwnerSlotHex,
		OwnerSignatures: validSubmitOwnerAuth(),
	}
	if _, err := orch.Submit(ctx, "u", subReq); err != nil {
		t.Fatalf("Submit 1: %v", err)
	}
	again, err := orch.Submit(ctx, "u", subReq)
	if err != nil {
		t.Fatalf("Submit 2: %v", err)
	}
	if again.Status != StatusSubmitted {
		t.Errorf("second submit status = %q, want SUBMITTED (current state)", again.Status)
	}
}
