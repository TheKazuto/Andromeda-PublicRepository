package intents

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
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

type fakeAuthorizer struct{}

func (fakeAuthorizer) AuthorizeSwap(context.Context, policy.SwapAuthorizeInput) (policy.AuthorizeResult, error) {
	return policy.AuthorizeResult{TxSignature: "FakeApprovalSig", ApprovalSlot: 123, MetadataDigestHex: "deadbeef"}, nil
}
func (fakeAuthorizer) SwapChallengeDigest(policy.SwapAuthorizeInput) (string, error) {
	return "deadbeef", nil
}
func (fakeAuthorizer) FirePresignPrefetchDirect(string, string, string) {}
func (fakeAuthorizer) HarvestPresignDirect(context.Context, string, string) string {
	return ""
}
func (fakeAuthorizer) EvaluateSwapRisk(context.Context, policy.SwapRiskInput) json.RawMessage {
	return json.RawMessage(`{"digestVerified":true}`)
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
	sub, err := orch.Submit(ctx, userID, submitRequest{IntentID: prep.IntentID, Passphrase: "passphrase-123"})
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
	if _, err := orch.Submit(ctx, "u", submitRequest{IntentID: prep.IntentID, Passphrase: "passphrase-123"}); err != nil {
		t.Fatalf("Submit 1: %v", err)
	}
	again, err := orch.Submit(ctx, "u", submitRequest{IntentID: prep.IntentID, Passphrase: "passphrase-123"})
	if err != nil {
		t.Fatalf("Submit 2: %v", err)
	}
	if again.Status != StatusSubmitted {
		t.Errorf("second submit status = %q, want SUBMITTED (current state)", again.Status)
	}
}
