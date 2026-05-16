package policy

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/gagliardetto/solana-go"
)

// repoRoot walks up from cwd until it finds the marker; falls back to
// "" + skip when nothing matches. Used by the cross-language fixture
// loaders to be robust to whatever cwd `go test` was invoked from.
func repoRootForMarker(t *testing.T, marker string) string {
	t.Helper()
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	dir := cwd
	for i := 0; i < 10; i++ {
		if _, err := os.Stat(filepath.Join(dir, marker)); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	return ""
}

// TestPrimaryRecoverChallengeMatchesFixture validates the Go renderer +
// hasher against the frozen golden vector in
// `fixtures/clear_signing_vectors.json`. Both Rust and TypeScript mirrors
// assert the same record. Any byte-level drift here breaks on-chain
// signature verification — fail loud.
func TestPrimaryRecoverChallengeMatchesFixture(t *testing.T) {
	vec := loadClearSigningVector(t, "primary_recover")

	dwallet := solana.PublicKeyFromBytes(mustHexBytes(t, vec.Inputs.Dwallet))
	msgApproval := solana.PublicKeyFromBytes(mustHexBytes(t, vec.Inputs.MessageApproval))
	msgDigest := mustHex32T(t, vec.Inputs.MessageDigest)
	metaDigest := mustHex32T(t, vec.Inputs.MetadataDigest)
	userPubkey := mustHex32T(t, vec.Inputs.UserPubkey)
	primarySlot := mustHexSlot(t, vec.Inputs.PrimarySlot)

	nonce := mustU64Str(t, vec.Inputs.Nonce)
	scheme := uint16(vec.Inputs.SignatureScheme)
	bump := uint8(vec.Inputs.MessageApprovalBump)

	in := &PrimaryRecoverChallengeInput{
		DWallet:             dwallet,
		MessageApproval:     msgApproval,
		MessageDigest:       msgDigest,
		MetadataDigest:      metaDigest,
		UserPubkey:          userPubkey,
		SignatureScheme:     scheme,
		MessageApprovalBump: bump,
		Nonce:               nonce,
		PrimarySlot:         primarySlot,
	}

	human := HumanMessagePrimaryRecover(dwallet, msgDigest, metaDigest, userPubkey, scheme)
	if string(human) != vec.HumanMessage {
		t.Fatalf("human message drift\n got: %q\nwant: %q", string(human), vec.HumanMessage)
	}

	hash, err := in.Hash()
	if err != nil {
		t.Fatalf("Hash: %v", err)
	}
	gotHex := hex.EncodeToString(hash[:])
	if gotHex != vec.HashHex {
		t.Fatalf("hash drift\n got: %s\nwant: %s", gotHex, vec.HashHex)
	}

	// Sanity: human_len_le_hex round-trips.
	wantLenHex := vec.HumanLenLEHex
	gotLen := uint16(len(human))
	gotLenHex := hex.EncodeToString([]byte{byte(gotLen), byte(gotLen >> 8)})
	if gotLenHex != wantLenHex {
		t.Fatalf("human_len_le drift\n got: %s\nwant: %s", gotLenHex, wantLenHex)
	}
}

// ─── fixture loader ────────────────────────────────────────────────────────

type clearSigningFixture struct {
	Vectors map[string]clearSigningVector `json:"vectors"`
}

type clearSigningVector struct {
	Inputs        clearSigningInputs `json:"inputs"`
	HumanMessage  string             `json:"human_message"`
	HumanLenLEHex string             `json:"human_len_le_hex"`
	HashHex       string             `json:"hash_hex"`
}

type clearSigningInputs struct {
	Dwallet             string `json:"dwallet"`
	MessageApproval     string `json:"messageApproval"`
	MessageApprovalBump int    `json:"messageApprovalBump"`
	MessageDigest       string `json:"messageDigest"`
	MetadataDigest      string `json:"metadataDigest"`
	UserPubkey          string `json:"userPubkey"`
	SignatureScheme     int    `json:"signatureScheme"`
	PrimarySlot         string `json:"primarySlot"`
	Nonce               string `json:"nonce"`
	// Quorum-specific:
	Amount       string `json:"amount"`
	Destination  string `json:"destination"`
	ExpiresAt    string `json:"expiresAt"`
	SessionNonce string `json:"sessionNonce"`
	Session      string `json:"session"`
	MemberSlot   string `json:"memberSlot"`
}

func loadClearSigningVector(t *testing.T, key string) clearSigningVector {
	t.Helper()
	// Walk up from the test working dir until we find the repo root (looks
	// for `fixtures/clear_signing_vectors.json`). Keeps the test runnable
	// from any go-test invocation regardless of cwd.
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	dir := cwd
	var path string
	for i := 0; i < 10; i++ {
		candidate := filepath.Join(dir, "fixtures", "clear_signing_vectors.json")
		if _, err := os.Stat(candidate); err == nil {
			path = candidate
			break
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	if path == "" {
		t.Skipf("clear_signing_vectors.json not found from %s — skipping cross-language fixture check", cwd)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	var fx clearSigningFixture
	if err := json.Unmarshal(raw, &fx); err != nil {
		t.Fatalf("parse fixture: %v", err)
	}
	v, ok := fx.Vectors[key]
	if !ok {
		t.Fatalf("fixture %q not found", key)
	}
	return v
}

func mustHexBytes(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("decode hex %q: %v", s, err)
	}
	return b
}

func mustHex32T(t *testing.T, s string) [32]byte {
	t.Helper()
	b := mustHexBytes(t, s)
	if len(b) != 32 {
		t.Fatalf("expected 32 bytes, got %d", len(b))
	}
	var out [32]byte
	copy(out[:], b)
	return out
}

func mustHexSlot(t *testing.T, s string) [MemberSlotLen]byte {
	t.Helper()
	b := mustHexBytes(t, s)
	if len(b) != MemberSlotLen {
		t.Fatalf("expected %d bytes for member slot, got %d", MemberSlotLen, len(b))
	}
	var out [MemberSlotLen]byte
	copy(out[:], b)
	return out
}

func mustU64Str(t *testing.T, s string) uint64 {
	t.Helper()
	var n uint64
	for _, c := range s {
		if c < '0' || c > '9' {
			t.Fatalf("not a u64: %q", s)
		}
		n = n*10 + uint64(c-'0')
	}
	return n
}

func mustI64Str(t *testing.T, s string) int64 {
	t.Helper()
	if len(s) == 0 {
		t.Fatalf("empty i64")
	}
	negative := false
	i := 0
	if s[0] == '-' {
		negative = true
		i = 1
	}
	var n int64
	for ; i < len(s); i++ {
		c := s[i]
		if c < '0' || c > '9' {
			t.Fatalf("not an i64: %q", s)
		}
		n = n*10 + int64(c-'0')
	}
	if negative {
		n = -n
	}
	return n
}

// ─── quorum_session_open vector ────────────────────────────────────────────

func TestQuorumSessionOpenChallengeMatchesFixture(t *testing.T) {
	vec := loadClearSigningVector(t, "quorum_session_open")
	dwallet := solana.PublicKeyFromBytes(mustHexBytes(t, vec.Inputs.Dwallet))
	in := &QuorumSessionOpenChallengeInput{
		DWallet:             dwallet,
		MessageDigest:       mustHex32T(t, vec.Inputs.MessageDigest),
		MetadataDigest:      mustHex32T(t, vec.Inputs.MetadataDigest),
		UserPubkey:          mustHex32T(t, vec.Inputs.UserPubkey),
		SignatureScheme:     uint16(vec.Inputs.SignatureScheme),
		MessageApprovalBump: uint8(vec.Inputs.MessageApprovalBump),
		Amount:              mustU64Str(t, vec.Inputs.Amount),
		Destination:         mustHex32T(t, vec.Inputs.Destination),
		ExpiresAt:           mustI64Str(t, vec.Inputs.ExpiresAt),
		SessionNonce:        mustU64Str(t, vec.Inputs.SessionNonce),
		PrimarySlot:         mustHexSlot(t, vec.Inputs.PrimarySlot),
	}
	human := HumanMessageQuorumSessionOpen(
		dwallet, in.Amount, in.Destination, in.MessageDigest, in.MetadataDigest,
		in.SignatureScheme, in.ExpiresAt,
	)
	if string(human) != vec.HumanMessage {
		t.Fatalf("human drift\n got: %q\nwant: %q", string(human), vec.HumanMessage)
	}
	hash, err := in.Hash()
	if err != nil {
		t.Fatalf("Hash: %v", err)
	}
	if got := hex.EncodeToString(hash[:]); got != vec.HashHex {
		t.Fatalf("hash drift\n got: %s\nwant: %s", got, vec.HashHex)
	}
}

// ─── quorum_contribute vector ──────────────────────────────────────────────

func TestQuorumContributeChallengeMatchesFixture(t *testing.T) {
	vec := loadClearSigningVector(t, "quorum_contribute")
	session := solana.PublicKeyFromBytes(mustHexBytes(t, vec.Inputs.Session))
	dwallet := solana.PublicKeyFromBytes(mustHexBytes(t, vec.Inputs.Dwallet))
	memberSlot := mustHexSlot(t, vec.Inputs.MemberSlot)
	in := &QuorumContributeChallengeInput{
		Session:             session,
		MemberSlot:          memberSlot,
		DWallet:             dwallet,
		Amount:              mustU64Str(t, vec.Inputs.Amount),
		Destination:         mustHex32T(t, vec.Inputs.Destination),
		MessageDigest:       mustHex32T(t, vec.Inputs.MessageDigest),
		MetadataDigest:      mustHex32T(t, vec.Inputs.MetadataDigest),
		UserPubkey:          mustHex32T(t, vec.Inputs.UserPubkey),
		SignatureScheme:     uint16(vec.Inputs.SignatureScheme),
		MessageApprovalBump: uint8(vec.Inputs.MessageApprovalBump),
		ExpiresAt:           mustI64Str(t, vec.Inputs.ExpiresAt),
	}
	human, err := HumanMessageQuorumContribute(
		session, memberSlot, dwallet, in.Amount,
		in.Destination, in.MessageDigest, in.MetadataDigest, in.UserPubkey,
		in.SignatureScheme, in.ExpiresAt,
	)
	if err != nil {
		t.Fatalf("HumanMessageQuorumContribute: %v", err)
	}
	if string(human) != vec.HumanMessage {
		t.Fatalf("human drift\n got: %q\nwant: %q", string(human), vec.HumanMessage)
	}
	hash, err := in.Hash()
	if err != nil {
		t.Fatalf("Hash: %v", err)
	}
	if got := hex.EncodeToString(hash[:]); got != vec.HashHex {
		t.Fatalf("hash drift\n got: %s\nwant: %s", got, vec.HashHex)
	}
}

// ─── passkey_session_open + passkey_primary_use vectors ────────────────────

type passkeyFixture struct {
	Domain        string `json:"domain"`
	OpSessionOpen string `json:"op_session_open"`
	OpPrimaryUse  string `json:"op_primary_use"`
	Inputs        struct {
		Dwallet            string `json:"dwallet"`
		PrimarySlot        string `json:"primary_slot"`
		EphPk              string `json:"eph_pk"`
		NotAfterUnixTs     string `json:"not_after_unix_ts"`
		CredentialIDHash   string `json:"credential_id_hash"`
		SessionNonce       string `json:"session_nonce"`
		UseNonce           string `json:"use_nonce"`
		SignatureScheme    int    `json:"signature_scheme"`
		MessageApprovalBump int   `json:"message_approval_bump"`
		MessageApproval    string `json:"message_approval"`
		MessageDigest      string `json:"message_digest"`
		MetadataDigest     string `json:"metadata_digest"`
		UserPubkey         string `json:"user_pubkey"`
	} `json:"inputs"`
	Pdas struct {
		Session struct {
			Hex string `json:"hex"`
		} `json:"session"`
	} `json:"pdas"`
	Challenges struct {
		Open struct {
			HumanMessage string `json:"human_message"`
			ChallengeHex string `json:"challenge_hex"`
		} `json:"open"`
		Use struct {
			HumanMessage string `json:"human_message"`
			ChallengeHex string `json:"challenge_hex"`
		} `json:"use"`
	} `json:"challenges"`
}

func loadPasskeyFixture(t *testing.T) passkeyFixture {
	t.Helper()
	root := repoRootForMarker(t, "fixtures/passkey_prf/v1/challenge_vectors.json")
	if root == "" {
		t.Skip("fixtures/passkey_prf/v1/challenge_vectors.json not found — skipping passkey drift check")
	}
	raw, err := os.ReadFile(filepath.Join(root, "fixtures", "passkey_prf", "v1", "challenge_vectors.json"))
	if err != nil {
		t.Fatalf("read passkey fixture: %v", err)
	}
	var fx passkeyFixture
	if err := json.Unmarshal(raw, &fx); err != nil {
		t.Fatalf("parse passkey fixture: %v", err)
	}
	return fx
}

func TestPasskeySessionOpenChallengeMatchesFixture(t *testing.T) {
	fx := loadPasskeyFixture(t)
	if fx.Domain != "andromeda::rules-policy::v2" {
		t.Fatalf("domain drift: %q", fx.Domain)
	}
	if fx.OpSessionOpen != "passkey-session-open" {
		t.Fatalf("op_session_open drift: %q", fx.OpSessionOpen)
	}
	dwallet := solana.PublicKeyFromBytes(mustHexBytes(t, fx.Inputs.Dwallet))
	in := &PasskeySessionOpenChallengeInput{
		DWallet:          dwallet,
		PrimarySlot:      mustHexSlot(t, fx.Inputs.PrimarySlot),
		EphPk:            mustHex32T(t, fx.Inputs.EphPk),
		NotAfterUnixTs:   mustU64Str(t, fx.Inputs.NotAfterUnixTs),
		CredentialIDHash: mustHex32T(t, fx.Inputs.CredentialIDHash),
		SessionNonce:     mustU64Str(t, fx.Inputs.SessionNonce),
	}
	human := HumanMessagePasskeySessionOpen(dwallet, in.NotAfterUnixTs, in.EphPk)
	if string(human) != fx.Challenges.Open.HumanMessage {
		t.Fatalf("human drift\n got: %q\nwant: %q", string(human), fx.Challenges.Open.HumanMessage)
	}
	hash, err := in.Hash()
	if err != nil {
		t.Fatalf("Hash: %v", err)
	}
	if got := hex.EncodeToString(hash[:]); got != fx.Challenges.Open.ChallengeHex {
		t.Fatalf("hash drift\n got: %s\nwant: %s", got, fx.Challenges.Open.ChallengeHex)
	}
}

func TestPasskeyPrimaryUseChallengeMatchesFixture(t *testing.T) {
	fx := loadPasskeyFixture(t)
	if fx.OpPrimaryUse != "passkey-primary-use" {
		t.Fatalf("op_primary_use drift: %q", fx.OpPrimaryUse)
	}
	session := solana.PublicKeyFromBytes(mustHexBytes(t, fx.Pdas.Session.Hex))
	dwallet := solana.PublicKeyFromBytes(mustHexBytes(t, fx.Inputs.Dwallet))
	msgApproval := solana.PublicKeyFromBytes(mustHexBytes(t, fx.Inputs.MessageApproval))
	in := &PasskeyPrimaryUseChallengeInput{
		Session:             session,
		DWallet:             dwallet,
		MessageApproval:     msgApproval,
		MessageDigest:       mustHex32T(t, fx.Inputs.MessageDigest),
		MetadataDigest:      mustHex32T(t, fx.Inputs.MetadataDigest),
		UserPubkey:          mustHex32T(t, fx.Inputs.UserPubkey),
		SignatureScheme:     uint16(fx.Inputs.SignatureScheme),
		MessageApprovalBump: uint8(fx.Inputs.MessageApprovalBump),
		UseNonce:            mustU64Str(t, fx.Inputs.UseNonce),
		PrimarySlot:         mustHexSlot(t, fx.Inputs.PrimarySlot),
	}
	human := HumanMessagePasskeyPrimaryUse(
		session, dwallet, in.MessageDigest, in.MetadataDigest, in.UserPubkey, in.SignatureScheme,
	)
	if string(human) != fx.Challenges.Use.HumanMessage {
		t.Fatalf("human drift\n got: %q\nwant: %q", string(human), fx.Challenges.Use.HumanMessage)
	}
	hash, err := in.Hash()
	if err != nil {
		t.Fatalf("Hash: %v", err)
	}
	if got := hex.EncodeToString(hash[:]); got != fx.Challenges.Use.ChallengeHex {
		t.Fatalf("hash drift\n got: %s\nwant: %s", got, fx.Challenges.Use.ChallengeHex)
	}
}
