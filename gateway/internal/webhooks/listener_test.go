package webhooks

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"sync"
	"testing"

	"github.com/google/uuid"
)

// fakePublisher captures every Publish call so tests can assert what the
// listener fans out. Safe for concurrent use because the listener may publish
// from background goroutines in production.
type fakePublisher struct {
	mu     sync.Mutex
	calls  []publishCall
	errors map[string]error // keyed by event type — return on Publish
}

type publishCall struct {
	APIKeyID  uuid.UUID
	EventType string
	Event     *CanonicalEvent
}

func (f *fakePublisher) Publish(_ context.Context, apiKeyID uuid.UUID, eventType string, payload any) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err, ok := f.errors[eventType]; ok && err != nil {
		return 0, err
	}
	ev, _ := payload.(*CanonicalEvent)
	f.calls = append(f.calls, publishCall{APIKeyID: apiKeyID, EventType: eventType, Event: ev})
	return 1, nil
}

func (f *fakePublisher) callsByType(t string) []publishCall {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]publishCall, 0, len(f.calls))
	for _, c := range f.calls {
		if c.EventType == t {
			out = append(out, c)
		}
	}
	return out
}

// fakeResolver is a deterministic test resolver: maps every key to a fixed
// api_key_id, and reports `unknownKeys` as not found so we can exercise the
// "skip fanout when tenant unknown" branch.
type fakeResolver struct {
	tenant      uuid.UUID
	unknownKeys map[string]bool
}

func (r *fakeResolver) Resolve(_ context.Context, addr string) (uuid.UUID, bool) {
	if r.unknownKeys[addr] {
		return uuid.Nil, false
	}
	return r.tenant, true
}

// makeNotification builds a logsNotification JSON envelope as it'd come off
// the wire from logsSubscribe. `logs` is the array of "Program ..." lines.
func makeNotification(t *testing.T, slot int64, sig string, logs []string, txErr any) []byte {
	t.Helper()
	env := map[string]any{
		"jsonrpc": "2.0",
		"method":  "logsNotification",
		"params": map[string]any{
			"subscription": 1,
			"result": map[string]any{
				"context": map[string]any{"slot": slot},
				"value": map[string]any{
					"signature": sig,
					"err":       txErr,
					"logs":      logs,
				},
			},
		},
	}
	b, err := json.Marshal(env)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return b
}

func quietLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func newTestListener(p EventPublisher, r PolicyTenantResolver) *Listener {
	return NewListener("https://example.invalid", []string{"PROG"}, p, r, quietLogger())
}

func TestListener_FanoutOnPolicyDeployed(t *testing.T) {
	tenant := uuid.MustParse("11111111-1111-1111-1111-111111111111")
	pub := &fakePublisher{}
	res := &fakeResolver{tenant: tenant}
	l := newTestListener(pub, res.Resolve)

	policy := bytes32(1)
	dwallet := bytes32(2)
	owner := bytes32(3)
	body := append([]byte{0}, policy...)
	body = append(body, dwallet...)
	body = append(body, owner...)
	body = append(body, u64LE(1700000000)...)

	logs := []string{
		"Program PROG invoke [1]",
		"Program data: " + base64.StdEncoding.EncodeToString(body),
		"Program PROG success",
	}
	raw := makeNotification(t, 100, "sig-1", logs, nil)
	l.handle(raw)

	calls := pub.callsByType("policy.deployed")
	if len(calls) != 1 {
		t.Fatalf("got %d publishes, want 1", len(calls))
	}
	got := calls[0]
	if got.APIKeyID != tenant {
		t.Errorf("api_key_id = %s, want %s", got.APIKeyID, tenant)
	}
	if got.Event == nil || got.Event.Type != "policy.deployed" {
		t.Errorf("event type = %v", got.Event)
	}
	if got.Event.Slot != 100 {
		t.Errorf("slot = %d, want 100", got.Event.Slot)
	}
	parsed, _, _, _ := l.Stats()
	if parsed != 1 {
		t.Errorf("eventsParsed = %d, want 1", parsed)
	}
}

func TestListener_NoFanoutWhenTenantUnknown(t *testing.T) {
	pub := &fakePublisher{}
	policy := bytes32(7)
	res := &fakeResolver{
		tenant:      uuid.New(),
		unknownKeys: map[string]bool{base58Encode(policy): true},
	}
	l := newTestListener(pub, res.Resolve)

	body := append([]byte{0}, policy...)
	body = append(body, bytes32(2)...)
	body = append(body, bytes32(3)...)
	body = append(body, u64LE(0)...)

	logs := []string{
		"Program data: " + base64.StdEncoding.EncodeToString(body),
	}
	l.handle(makeNotification(t, 0, "sig-2", logs, nil))

	if len(pub.calls) != 0 {
		t.Fatalf("expected zero publishes, got %d", len(pub.calls))
	}
	parsed, _, _, _ := l.Stats()
	if parsed != 1 {
		t.Errorf("eventsParsed = %d, want 1 (still parsed even when no tenant)", parsed)
	}
}

func TestListener_IkaEventRoutesByDwallet(t *testing.T) {
	tenant := uuid.MustParse("22222222-2222-2222-2222-222222222222")
	pub := &fakePublisher{}
	res := &fakeResolver{tenant: tenant}
	l := newTestListener(pub, res.Resolve)

	dwallet := bytes32(11)
	authority := bytes32(12)
	body := append([]byte(nil), ikaEventTagLE[:]...)
	body = append(body, 0) // disc 0 = DWalletCreated
	body = append(body, dwallet...)
	body = append(body, authority...)
	body = append(body, 2) // curve = Curve25519

	logs := []string{
		"Program 87W54... invoke [1]",
		"Program data: " + base64.StdEncoding.EncodeToString(body),
		"Program 87W54... success",
	}
	l.handle(makeNotification(t, 5, "sig-ika", logs, nil))

	calls := pub.callsByType("dwallet.created")
	if len(calls) != 1 {
		t.Fatalf("got %d dwallet.created, want 1", len(calls))
	}
	if calls[0].APIKeyID != tenant {
		t.Errorf("api_key_id = %s, want %s", calls[0].APIKeyID, tenant)
	}
	// The Ika event has Dwallet but no Policy — the resolver path must use
	// the dwallet pubkey as the lookup key.
	if calls[0].Event.Dwallet == "" {
		t.Errorf("expected event.Dwallet populated")
	}
	if calls[0].Event.Policy != "" {
		t.Errorf("Ika events shouldn't carry Policy, got %q", calls[0].Event.Policy)
	}
}

func TestListener_SkipsFailedTransactions(t *testing.T) {
	pub := &fakePublisher{}
	l := newTestListener(pub, (&fakeResolver{tenant: uuid.New()}).Resolve)

	body := append([]byte{0}, bytes32(1)...)
	body = append(body, bytes32(2)...)
	body = append(body, bytes32(3)...)
	body = append(body, u64LE(0)...)

	logs := []string{
		"Program PROG invoke [1]",
		"Program data: " + base64.StdEncoding.EncodeToString(body),
		"Program PROG failed: custom program error: 0x1772",
	}
	// Tx-level err set — the listener must NOT publish anything from a failed tx.
	raw := makeNotification(t, 0, "sig-failed", logs,
		map[string]any{"InstructionError": []any{0, map[string]any{"Custom": 6002}}})
	l.handle(raw)

	if len(pub.calls) != 0 {
		t.Fatalf("expected zero publishes for failed tx, got %d", len(pub.calls))
	}
}

func TestListener_MultipleEventsInOneTransaction(t *testing.T) {
	tenant := uuid.MustParse("33333333-3333-3333-3333-333333333333")
	pub := &fakePublisher{}
	l := newTestListener(pub, (&fakeResolver{tenant: tenant}).Resolve)

	// Build two `Program data:` lines: SignatureRequested then SignatureApproved.
	policy := bytes32(8)
	hash := bytes32(9)
	requested := append([]byte{1}, policy...)
	requested = append(requested, hash...)
	requested = append(requested, u64LE(1700000000)...)

	approved := append([]byte{2}, policy...)
	approved = append(approved, hash...)
	approved = append(approved, u64LE(1700000001)...)

	logs := []string{
		"Program PROG invoke [1]",
		"Program data: " + base64.StdEncoding.EncodeToString(requested),
		"Program 87W54... invoke [2]",
		"Program 87W54... success",
		"Program data: " + base64.StdEncoding.EncodeToString(approved),
		"Program PROG success",
	}
	l.handle(makeNotification(t, 0, "sig-multi", logs, nil))

	if got := len(pub.callsByType("signature.requested")); got != 1 {
		t.Errorf("signature.requested = %d, want 1", got)
	}
	if got := len(pub.callsByType("signature.approved")); got != 1 {
		t.Errorf("signature.approved = %d, want 1", got)
	}
}

func TestListener_PublisherErrorDoesNotPanic(t *testing.T) {
	pub := &fakePublisher{errors: map[string]error{"policy.deployed": fmt.Errorf("dispatcher offline")}}
	l := newTestListener(pub, (&fakeResolver{tenant: uuid.New()}).Resolve)

	body := append([]byte{0}, bytes32(1)...)
	body = append(body, bytes32(2)...)
	body = append(body, bytes32(3)...)
	body = append(body, u64LE(0)...)
	logs := []string{"Program data: " + base64.StdEncoding.EncodeToString(body)}

	// Must not panic; published count must be 0; parsed count must be 1.
	l.handle(makeNotification(t, 0, "sig-err", logs, nil))

	parsed, _, published, _ := l.Stats()
	if parsed != 1 {
		t.Errorf("parsed = %d, want 1", parsed)
	}
	if published != 0 {
		t.Errorf("published = %d, want 0 (publisher errored)", published)
	}
}

// helper used across tests; mirrors events_test.go's util but kept local so
// the integration suite stays self-contained.
func u64LE_pkg(v uint64) []byte {
	b := make([]byte, 8)
	binary.LittleEndian.PutUint64(b, v)
	return b
}

var _ = u64LE_pkg // keep alias available for future tests
