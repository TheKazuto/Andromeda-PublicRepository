package policy

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gagliardetto/solana-go"
	"github.com/go-chi/chi/v5"
)

// newSessionTestService is a minimal Service wired with just enough to drive
// the challenge handlers (no GasSponsor, no RPCClient). Submit handlers expect
// a GasSponsor and will short-circuit with 503 — tested separately.
func newSessionTestService() *Service {
	return &Service{
		ProgramID: solana.SystemProgramID,
	}
}

func randAddr(t *testing.T) [32]byte {
	t.Helper()
	var out [32]byte
	if _, err := rand.Read(out[:]); err != nil {
		t.Fatal(err)
	}
	return out
}

// TestSessionOpenChallenge_ReturnsCanonicalEnvelope is a smoke test that the
// challenge handler accepts a well-formed body, derives the engine + session
// PDAs, and returns a non-empty owner_auth_challenge_hex with the expected
// op tag. The on-chain mirror is exercised by the Rust unit tests; this guards
// the Go-side wiring.
func TestSessionOpenChallenge_ReturnsCanonicalEnvelope(t *testing.T) {
	s := newSessionTestService()
	r := chi.NewRouter()
	r.Post("/v1/policy/session/open/challenge", s.sessionOpenChallenge)

	dwallet := solana.NewWallet().PublicKey()
	initHash := randAddr(t)
	configHash := randAddr(t)
	signer := solana.NewWallet().PublicKey()
	body := map[string]any{
		"dwallet_address":         dwallet.String(),
		"init_authority_hash_hex": hex.EncodeToString(initHash[:]),
		"rule_index":              0,
		"rule_generation":         0,
		"rule_config_hash_hex":    hex.EncodeToString(configHash[:]),
		"expected_nonce":          0,
		"owner_slot": map[string]any{
			"scheme":         0,
			"identifier_hex": hex.EncodeToString(make([]byte, 32)),
		},
		"session_index":         0,
		"session_signer_pubkey": signer.String(),
		"expires_at_ts":         1_999_999_999,
		"max_uses":              10,
		"max_amount_per_tx":     1_000_000,
	}
	raw, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/v1/policy/session/open/challenge", bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	var resp sessionAdminChallengeResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v body=%s", err, rr.Body.String())
	}
	if resp.OpTag != string(OpSessionOpen) {
		t.Errorf("op_tag=%q want %q", resp.OpTag, OpSessionOpen)
	}
	if len(resp.OwnerAuthChallengeHex) != 64 {
		t.Errorf("challenge hex len=%d want 64", len(resp.OwnerAuthChallengeHex))
	}
	if resp.EngineAddress == "" || resp.SessionAddress == "" {
		t.Errorf("missing engine/session address: %+v", resp)
	}
}

// TestSessionChallengeBindsSessionSigner proves the session_open challenge
// hash changes when the session_signer pubkey changes — the on-chain handler
// binds the signer, so a stolen signature cannot redirect the session to a
// different key.
func TestSessionChallengeBindsSessionSigner(t *testing.T) {
	s := newSessionTestService()
	r := chi.NewRouter()
	r.Post("/v1/policy/session/open/challenge", s.sessionOpenChallenge)

	dwallet := solana.NewWallet().PublicKey()
	initHash := randAddr(t)
	configHash := randAddr(t)
	mkBody := func(signer string) []byte {
		body := map[string]any{
			"dwallet_address":         dwallet.String(),
			"init_authority_hash_hex": hex.EncodeToString(initHash[:]),
			"rule_index":              0,
			"rule_generation":         0,
			"rule_config_hash_hex":    hex.EncodeToString(configHash[:]),
			"expected_nonce":          0,
			"owner_slot": map[string]any{
				"scheme":         0,
				"identifier_hex": hex.EncodeToString(make([]byte, 32)),
			},
			"session_index":         0,
			"session_signer_pubkey": signer,
			"expires_at_ts":         1_999_999_999,
			"max_uses":              10,
			"max_amount_per_tx":     1_000_000,
		}
		raw, _ := json.Marshal(body)
		return raw
	}

	hashFor := func(signer string) string {
		req := httptest.NewRequest(http.MethodPost, "/v1/policy/session/open/challenge", bytes.NewReader(mkBody(signer)))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		r.ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
		}
		var resp sessionAdminChallengeResponse
		_ = json.Unmarshal(rr.Body.Bytes(), &resp)
		return resp.OwnerAuthChallengeHex
	}

	a := hashFor(solana.NewWallet().PublicKey().String())
	b := hashFor(solana.NewWallet().PublicKey().String())
	if a == b {
		t.Fatal("session_open challenge does not bind session_signer (replay risk)")
	}
}

// TestSessionRevokeExtras_ChallengeMatchesSubmit guards against the original
// bug where sessionRevokeChallenge prepended sessionPDA to extras but
// sessionRevokeSubmit did not — the on-chain hash would not match the one
// the gateway returned at /challenge, and the precompile verification would
// always fail. Both must now produce the same admin_challenge hash for the
// same inputs.
func TestSessionRevokeExtras_ChallengeMatchesSubmit(t *testing.T) {
	s := newSessionTestService()
	rChallenge := chi.NewRouter()
	rChallenge.Post("/c", s.sessionRevokeChallenge)

	dwallet := solana.NewWallet().PublicKey()
	initHash := randAddr(t)
	body := map[string]any{
		"dwallet_address":         dwallet.String(),
		"init_authority_hash_hex": hex.EncodeToString(initHash[:]),
		"session_index":           7,
		"expected_nonce":          42,
		"owner_slot": map[string]any{
			"scheme":         0,
			"identifier_hex": hex.EncodeToString(make([]byte, 32)),
		},
	}
	raw, _ := json.Marshal(body)

	// Call the challenge handler.
	req := httptest.NewRequest(http.MethodPost, "/c", bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	rChallenge.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("challenge: status=%d body=%s", rr.Code, rr.Body.String())
	}
	var resp sessionAdminChallengeResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	// Now recompute the SAME admin_challenge using the exact extras path the
	// submit takes (sessionRevokeExtras + buildSessionAdminChallenge). The two
	// hashes MUST be identical.
	engine, _ := solana.PublicKeyFromBase58(resp.EngineAddress)
	sessionPDA, _ := solana.PublicKeyFromBase58(resp.SessionAddress)
	var ownerSlot [MemberSlotLen]byte
	extras := sessionRevokeExtras(sessionPDA, 7)
	_, _, h, err := buildSessionAdminChallenge(
		OpSessionRevoke, engine, dwallet, ownerSlot, 42, false, [32]byte{}, 0, 0, extras,
	)
	if err != nil {
		t.Fatalf("rebuild: %v", err)
	}
	want := resp.OwnerAuthChallengeHex
	got := hex.EncodeToString(h[:])
	if want != got {
		t.Fatalf("challenge/submit hash mismatch (revoke bug regression):\n  challenge: %s\n  submit  : %s", want, got)
	}
}

// TestParseSessionAccount_OffsetsMatchOnChainLayout guards against the
// original bug where parseSessionAccount assumed an 8-byte Quasar
// discriminator (matching Anchor) instead of the actual 1-byte one (matching
// DecodePolicyEngine / DecodeAllowlistRule in codecs.go). The fix reads
// `data[0]` as the disc and the struct fields immediately after.
func TestParseSessionAccount_OffsetsMatchOnChainLayout(t *testing.T) {
	engine := solana.NewWallet().PublicKey()
	sessionPDA := solana.NewWallet().PublicKey()
	signer := solana.NewWallet().PublicKey()

	data := make([]byte, SessionAccountBytes)
	data[0] = 3 // account discriminator
	copy(data[1:33], engine.Bytes())
	copy(data[33:65], signer.Bytes())
	// session_index = 5
	data[65] = 5
	// created_at_ts = 1_700_000_000
	leU64(data[73:81], 1_700_000_000)
	// expires_at_ts = 1_700_086_400 (24h)
	leU64(data[81:89], 1_700_086_400)
	// used_count = 3
	data[89] = 3
	// max_uses = 100
	data[93] = 100
	// next_signature_nonce = 7
	data[97] = 7
	// max_amount_per_tx = 500_000
	leU64(data[105:113], 500_000)
	// next_admin_nonce = 1
	data[113] = 1
	// destinations_count = 2
	data[121] = 2
	// destinations[0] = 0xAA…AA
	for i := 0; i < 32; i++ {
		data[129+i] = 0xAA
	}
	// destinations[1] = 0xBB…BB
	for i := 0; i < 32; i++ {
		data[129+32+i] = 0xBB
	}

	resp, err := parseSessionAccount(data, engine, sessionPDA)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if resp.SessionIndex != 5 {
		t.Errorf("session_index=%d want 5", resp.SessionIndex)
	}
	if resp.CreatedAtTs != 1_700_000_000 {
		t.Errorf("created_at_ts=%d want 1700000000", resp.CreatedAtTs)
	}
	if resp.ExpiresAtTs != 1_700_086_400 {
		t.Errorf("expires_at_ts=%d want 1700086400", resp.ExpiresAtTs)
	}
	if resp.UsedCount != 3 {
		t.Errorf("used_count=%d want 3", resp.UsedCount)
	}
	if resp.MaxUses != 100 {
		t.Errorf("max_uses=%d want 100", resp.MaxUses)
	}
	if resp.NextSignatureNonce != 7 {
		t.Errorf("next_signature_nonce=%d want 7", resp.NextSignatureNonce)
	}
	if resp.MaxAmountPerTx != 500_000 {
		t.Errorf("max_amount_per_tx=%d want 500000", resp.MaxAmountPerTx)
	}
	if resp.NextAdminNonce != 1 {
		t.Errorf("next_admin_nonce=%d want 1", resp.NextAdminNonce)
	}
	if len(resp.Destinations) != 2 {
		t.Fatalf("destinations len=%d want 2", len(resp.Destinations))
	}
	if resp.Destinations[0] != strings.Repeat("aa", 32) {
		t.Errorf("destinations[0]=%s want %s", resp.Destinations[0], strings.Repeat("aa", 32))
	}
	if resp.Destinations[1] != strings.Repeat("bb", 32) {
		t.Errorf("destinations[1]=%s want %s", resp.Destinations[1], strings.Repeat("bb", 32))
	}
	if resp.SessionSignerPubkey != signer.String() {
		t.Errorf("session_signer=%s want %s", resp.SessionSignerPubkey, signer.String())
	}
}

// TestParseSessionAccount_RejectsBadDiscriminator proves the parser rejects
// any account whose discriminator byte is not 3 — important defense in case
// the read endpoint is pointed at the wrong PDA (e.g. an engine PDA or a
// quorum PDA).
func TestParseSessionAccount_RejectsBadDiscriminator(t *testing.T) {
	engine := solana.NewWallet().PublicKey()
	data := make([]byte, SessionAccountBytes)
	data[0] = 1 // engine discriminator — NOT a session
	copy(data[1:33], engine.Bytes())
	_, err := parseSessionAccount(data, engine, solana.NewWallet().PublicKey())
	if err == nil || !strings.Contains(err.Error(), "discriminator") {
		t.Fatalf("expected discriminator error, got %v", err)
	}
}

// TestParseSessionAccount_RejectsEngineMismatch proves the parser rejects an
// account whose engine field does not match the caller's expected engine.
// Defense against a layout shift or a corrupted PDA derivation.
func TestParseSessionAccount_RejectsEngineMismatch(t *testing.T) {
	engineA := solana.NewWallet().PublicKey()
	engineB := solana.NewWallet().PublicKey()
	data := make([]byte, SessionAccountBytes)
	data[0] = 3
	copy(data[1:33], engineA.Bytes()) // account says engineA
	_, err := parseSessionAccount(data, engineB, solana.NewWallet().PublicKey())
	if err == nil || !strings.Contains(err.Error(), "engine mismatch") {
		t.Fatalf("expected engine mismatch error, got %v", err)
	}
}

// TestSessionOpenSubmitRequest_RuleConfigHashHexNotShadowed guards against the
// embedding bug where the outer struct re-declared RuleConfigHashHex with
// `json:"-"`, shadowing the parent's tagged field and breaking JSON
// unmarshaling + validation. The test sends a well-formed body and asserts the
// nested field is populated (the validator would have rejected it otherwise).
func TestSessionOpenSubmitRequest_RuleConfigHashHexNotShadowed(t *testing.T) {
	body := map[string]any{
		"dwallet_address":         "11111111111111111111111111111111",
		"init_authority_hash_hex": strings.Repeat("00", 32),
		"rule_index":              0,
		"rule_generation":         0,
		"rule_config_hash_hex":    strings.Repeat("11", 32),
		"expected_nonce":          0,
		"owner_slot": map[string]any{
			"scheme":         0,
			"identifier_hex": strings.Repeat("00", 32),
		},
		"session_index":         0,
		"signature_base64":      "AA==",
		"session_signer_pubkey": "11111111111111111111111111111111",
		"expires_at_ts":         1_999_999_999,
		"max_uses":              10,
		"max_amount_per_tx":     1_000_000,
	}
	raw, _ := json.Marshal(body)
	var req sessionOpenSubmitRequest
	if err := json.Unmarshal(raw, &req); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	want := strings.Repeat("11", 32)
	if req.RuleConfigHashHex != want {
		t.Fatalf("RuleConfigHashHex=%q want %q (embedding shadow bug regression)", req.RuleConfigHashHex, want)
	}
}

// TestSessionUseBuild_ReturnsInstructionBuildOnly proves the use/build endpoint
// returns a `request_signature_via_session` instruction with the session-signer
// marked as a Signer (so the dev knows they MUST sign the tx with it) and the
// dev-supplied payer as another Signer — and the gateway does NOT broadcast.
func TestSessionUseBuild_ReturnsInstructionBuildOnly(t *testing.T) {
	s := newSessionTestService()
	r := chi.NewRouter()
	r.Post("/v1/policy/session/use/build", s.sessionUseBuild)

	dwallet := solana.NewWallet().PublicKey()
	initHash := randAddr(t)
	signer := solana.NewWallet().PublicKey()
	payer := solana.NewWallet().PublicKey()
	zeros := strings.Repeat("00", 32)
	body := map[string]any{
		"dwallet_address":          dwallet.String(),
		"init_authority_hash_hex":  hex.EncodeToString(initHash[:]),
		"session_index":            0,
		"session_signer_pubkey":    signer.String(),
		"message_digest_hex":       zeros,
		"metadata_digest_hex":      zeros,
		"user_pubkey_hex":          zeros,
		"signature_scheme":         0,
		"ika_curve":                2,
		"ika_dwallet_pubkey_hex":   strings.Repeat("00", 32),
		"destination_hex":          zeros,
		"expected_signature_nonce": 0,
		"amount":                   0,
		"payer":                    payer.String(),
	}
	raw, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/v1/policy/session/use/build", bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	var resp sessionUseBuildResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v body=%s", err, rr.Body.String())
	}
	if resp.Instruction.ProgramID == "" {
		t.Errorf("instruction.program_id empty: %+v", resp)
	}
	// At minimum the session-signer + payer slots must be flagged Signer.
	var signerSlots int
	for _, a := range resp.Instruction.Accounts {
		if a.IsSigner {
			signerSlots++
		}
	}
	if signerSlots < 2 {
		t.Errorf("expected >=2 signer slots (session_signer + payer), got %d", signerSlots)
	}
	if !strings.Contains(resp.Notice, "session signer") {
		t.Errorf("notice missing build-only language: %q", resp.Notice)
	}
}
