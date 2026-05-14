package auth

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/gagliardetto/solana-go"
)

// fixtureVector mirrors `Vector` in
// `contracts/auth/examples/gen_challenge_vectors.rs`.
type fixtureVector struct {
	Inputs              map[string]any `json:"inputs"`
	HumanMessage        *string        `json:"human_message,omitempty"`
	HumanLenLEHex       *string        `json:"human_len_le_hex,omitempty"`
	HashHex             string         `json:"hash_hex"`
	ClearSigningVersion *string        `json:"clear_signing_version,omitempty"`
}

type fixtureFile struct {
	Version     int                      `json:"version"`
	WireVersion string                   `json:"wire_version"`
	Vectors     map[string]fixtureVector `json:"vectors"`
}

func loadFixture(t *testing.T) fixtureFile {
	t.Helper()
	// gateway/internal/auth/ → repo root → fixtures
	path := filepath.Join("..", "..", "..", "fixtures", "clear_signing_vectors.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	var f fixtureFile
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatalf("unmarshal fixture: %v", err)
	}
	if f.Version < 2 {
		t.Fatalf("fixture version %d < 2 — regenerate with cargo run --features host-test --example gen_challenge_vectors", f.Version)
	}
	return f
}

func unhex(t *testing.T, s string, want int) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("unhex %q: %v", s, err)
	}
	if want > 0 && len(b) != want {
		t.Fatalf("unhex %q: got %d bytes, want %d", s, len(b), want)
	}
	return b
}

func unhex32(t *testing.T, s string) [32]byte {
	var out [32]byte
	copy(out[:], unhex(t, s, 32))
	return out
}

func unhexSlot(t *testing.T, s string) [MemberSlotLen]byte {
	var out [MemberSlotLen]byte
	copy(out[:], unhex(t, s, MemberSlotLen))
	return out
}

func unhexPubkey(t *testing.T, s string) solana.PublicKey {
	b := unhex(t, s, 32)
	var out solana.PublicKey
	copy(out[:], b)
	return out
}

func bigU64(t *testing.T, m map[string]any, key string) uint64 {
	t.Helper()
	v, ok := m[key].(string)
	if !ok {
		t.Fatalf("field %q: not a string", key)
	}
	n, err := strconv.ParseUint(v, 10, 64)
	if err != nil {
		t.Fatalf("field %q: %v", key, err)
	}
	return n
}

func bigI64(t *testing.T, m map[string]any, key string) int64 {
	t.Helper()
	v, ok := m[key].(string)
	if !ok {
		t.Fatalf("field %q: not a string", key)
	}
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil {
		t.Fatalf("field %q: %v", key, err)
	}
	return n
}

func numU8(t *testing.T, m map[string]any, key string) uint8 {
	t.Helper()
	v, ok := m[key].(float64)
	if !ok {
		t.Fatalf("field %q: not a number", key)
	}
	return uint8(v)
}

func numU16(t *testing.T, m map[string]any, key string) uint16 {
	t.Helper()
	v, ok := m[key].(float64)
	if !ok {
		t.Fatalf("field %q: not a number", key)
	}
	return uint16(v)
}

func numU32(t *testing.T, m map[string]any, key string) uint32 {
	t.Helper()
	v, ok := m[key].(float64)
	if !ok {
		t.Fatalf("field %q: not a number", key)
	}
	return uint32(v)
}

func hexField(t *testing.T, m map[string]any, key string) string {
	t.Helper()
	v, ok := m[key].(string)
	if !ok {
		t.Fatalf("field %q: not a string", key)
	}
	return v
}

// assertVector recomputes the challenge from the fixture inputs and
// asserts hash + humanMessage match the frozen values.
func assertVector(t *testing.T, name string, fx fixtureVector, gotHash [32]byte, gotHuman string) {
	t.Helper()
	wantHash := unhex32(t, fx.HashHex)
	if gotHash != wantHash {
		t.Errorf("%s: hash mismatch\n got %s\nwant %s", name, hex.EncodeToString(gotHash[:]), fx.HashHex)
	}
	if fx.HumanMessage != nil && gotHuman != *fx.HumanMessage {
		t.Errorf("%s: humanMessage mismatch\n got %q\nwant %q", name, gotHuman, *fx.HumanMessage)
	}
}

func TestClearSigning_FrozenGoldenVectors(t *testing.T) {
	fx := loadFixture(t)
	V := fx.Vectors

	// allowlist-destinations (4)
	t.Run("allowlist_add_destination", func(t *testing.T) {
		v := V["allowlist_add_destination"]
		in := v.Inputs
		hash, human, _, err := AllowlistAddDestinationChallenge(
			unhexPubkey(t, hexField(t, in, "dwallet")),
			unhexPubkey(t, hexField(t, in, "policy")),
			unhex32(t, hexField(t, in, "destination")),
			bigU64(t, in, "nonce"),
			unhexSlot(t, hexField(t, in, "ownerSlot")),
		)
		if err != nil {
			t.Fatal(err)
		}
		assertVector(t, "allowlist_add_destination", v, hash, human)
	})

	t.Run("allowlist_remove_destination", func(t *testing.T) {
		v := V["allowlist_remove_destination"]
		in := v.Inputs
		hash, human, _, err := AllowlistRemoveDestinationChallenge(
			unhexPubkey(t, hexField(t, in, "dwallet")),
			unhexPubkey(t, hexField(t, in, "policy")),
			unhex32(t, hexField(t, in, "destination")),
			bigU64(t, in, "nonce"),
			unhexSlot(t, hexField(t, in, "ownerSlot")),
		)
		if err != nil {
			t.Fatal(err)
		}
		assertVector(t, "allowlist_remove_destination", v, hash, human)
	})

	t.Run("allowlist_pause", func(t *testing.T) {
		v := V["allowlist_pause"]
		in := v.Inputs
		hash, human, _, err := AllowlistPauseChallenge(
			unhexPubkey(t, hexField(t, in, "dwallet")),
			unhexPubkey(t, hexField(t, in, "policy")),
			bigU64(t, in, "nonce"),
			unhexSlot(t, hexField(t, in, "ownerSlot")),
		)
		if err != nil {
			t.Fatal(err)
		}
		assertVector(t, "allowlist_pause", v, hash, human)
	})

	t.Run("allowlist_resume", func(t *testing.T) {
		v := V["allowlist_resume"]
		in := v.Inputs
		hash, human, _, err := AllowlistResumeChallenge(
			unhexPubkey(t, hexField(t, in, "dwallet")),
			unhexPubkey(t, hexField(t, in, "policy")),
			bigU64(t, in, "nonce"),
			unhexSlot(t, hexField(t, in, "ownerSlot")),
		)
		if err != nil {
			t.Fatal(err)
		}
		assertVector(t, "allowlist_resume", v, hash, human)
	})

	// velocity-guard (3)
	t.Run("velocity_update_window", func(t *testing.T) {
		v := V["velocity_update_window"]
		in := v.Inputs
		hash, human, _, err := VelocityUpdateWindowChallenge(
			unhexPubkey(t, hexField(t, in, "dwallet")),
			unhexPubkey(t, hexField(t, in, "policy")),
			numU32(t, in, "maxSigsPerWindow"),
			bigU64(t, in, "windowSlots"),
			bigU64(t, in, "nonce"),
			unhexSlot(t, hexField(t, in, "ownerSlot")),
		)
		if err != nil {
			t.Fatal(err)
		}
		assertVector(t, "velocity_update_window", v, hash, human)
	})

	t.Run("velocity_pause", func(t *testing.T) {
		v := V["velocity_pause"]
		in := v.Inputs
		hash, human, _, err := VelocityPauseChallenge(
			unhexPubkey(t, hexField(t, in, "dwallet")),
			unhexPubkey(t, hexField(t, in, "policy")),
			bigU64(t, in, "nonce"),
			unhexSlot(t, hexField(t, in, "ownerSlot")),
		)
		if err != nil {
			t.Fatal(err)
		}
		assertVector(t, "velocity_pause", v, hash, human)
	})

	t.Run("velocity_resume", func(t *testing.T) {
		v := V["velocity_resume"]
		in := v.Inputs
		hash, human, _, err := VelocityResumeChallenge(
			unhexPubkey(t, hexField(t, in, "dwallet")),
			unhexPubkey(t, hexField(t, in, "policy")),
			bigU64(t, in, "nonce"),
			unhexSlot(t, hexField(t, in, "ownerSlot")),
		)
		if err != nil {
			t.Fatal(err)
		}
		assertVector(t, "velocity_resume", v, hash, human)
	})

	// time-lock (3)
	t.Run("time_lock_update_window", func(t *testing.T) {
		v := V["time_lock_update_window"]
		in := v.Inputs
		hash, human, _, err := TimeLockUpdateWindowChallenge(
			unhexPubkey(t, hexField(t, in, "dwallet")),
			unhexPubkey(t, hexField(t, in, "policy")),
			numU8(t, in, "mode"),
			bigU64(t, in, "startSlot"),
			bigU64(t, in, "endSlot"),
			bigU64(t, in, "recurringPeriodSlots"),
			bigU64(t, in, "nonce"),
			unhexSlot(t, hexField(t, in, "ownerSlot")),
		)
		if err != nil {
			t.Fatal(err)
		}
		assertVector(t, "time_lock_update_window", v, hash, human)
	})

	t.Run("time_lock_pause", func(t *testing.T) {
		v := V["time_lock_pause"]
		in := v.Inputs
		hash, human, _, err := TimeLockPauseChallenge(
			unhexPubkey(t, hexField(t, in, "dwallet")),
			unhexPubkey(t, hexField(t, in, "policy")),
			bigU64(t, in, "nonce"),
			unhexSlot(t, hexField(t, in, "ownerSlot")),
		)
		if err != nil {
			t.Fatal(err)
		}
		assertVector(t, "time_lock_pause", v, hash, human)
	})

	t.Run("time_lock_resume", func(t *testing.T) {
		v := V["time_lock_resume"]
		in := v.Inputs
		hash, human, _, err := TimeLockResumeChallenge(
			unhexPubkey(t, hexField(t, in, "dwallet")),
			unhexPubkey(t, hexField(t, in, "policy")),
			bigU64(t, in, "nonce"),
			unhexSlot(t, hexField(t, in, "ownerSlot")),
		)
		if err != nil {
			t.Fatal(err)
		}
		assertVector(t, "time_lock_resume", v, hash, human)
	})

	// oracle-conditional (3)
	t.Run("oracle_update_bounds", func(t *testing.T) {
		v := V["oracle_update_bounds"]
		in := v.Inputs
		hash, human, _, err := OracleUpdateBoundsChallenge(
			unhexPubkey(t, hexField(t, in, "dwallet")),
			unhexPubkey(t, hexField(t, in, "policy")),
			bigI64(t, in, "minPrice"),
			bigI64(t, in, "maxPrice"),
			bigU64(t, in, "maxAgeSlots"),
			numU16(t, in, "maxConfidenceBps"),
			bigU64(t, in, "nonce"),
			unhexSlot(t, hexField(t, in, "ownerSlot")),
		)
		if err != nil {
			t.Fatal(err)
		}
		assertVector(t, "oracle_update_bounds", v, hash, human)
	})

	t.Run("oracle_pause", func(t *testing.T) {
		v := V["oracle_pause"]
		in := v.Inputs
		hash, human, _, err := OraclePauseChallenge(
			unhexPubkey(t, hexField(t, in, "dwallet")),
			unhexPubkey(t, hexField(t, in, "policy")),
			bigU64(t, in, "nonce"),
			unhexSlot(t, hexField(t, in, "ownerSlot")),
		)
		if err != nil {
			t.Fatal(err)
		}
		assertVector(t, "oracle_pause", v, hash, human)
	})

	t.Run("oracle_resume", func(t *testing.T) {
		v := V["oracle_resume"]
		in := v.Inputs
		hash, human, _, err := OracleResumeChallenge(
			unhexPubkey(t, hexField(t, in, "dwallet")),
			unhexPubkey(t, hexField(t, in, "policy")),
			bigU64(t, in, "nonce"),
			unhexSlot(t, hexField(t, in, "ownerSlot")),
		)
		if err != nil {
			t.Fatal(err)
		}
		assertVector(t, "oracle_resume", v, hash, human)
	})

	// passkey-step-up (3)
	t.Run("passkey_update_policy", func(t *testing.T) {
		v := V["passkey_update_policy"]
		in := v.Inputs
		pkBytes := unhex(t, hexField(t, in, "passkeyPubkey"), 33)
		var pk [33]byte
		copy(pk[:], pkBytes)
		hash, human, _, err := PasskeyUpdatePolicyChallenge(
			unhexPubkey(t, hexField(t, in, "dwallet")),
			unhexPubkey(t, hexField(t, in, "policy")),
			bigU64(t, in, "thresholdAmount"),
			pk,
			bigU64(t, in, "nonce"),
			unhexSlot(t, hexField(t, in, "ownerSlot")),
		)
		if err != nil {
			t.Fatal(err)
		}
		assertVector(t, "passkey_update_policy", v, hash, human)
	})

	t.Run("passkey_pause", func(t *testing.T) {
		v := V["passkey_pause"]
		in := v.Inputs
		hash, human, _, err := PasskeyPauseChallenge(
			unhexPubkey(t, hexField(t, in, "dwallet")),
			unhexPubkey(t, hexField(t, in, "policy")),
			bigU64(t, in, "nonce"),
			unhexSlot(t, hexField(t, in, "ownerSlot")),
		)
		if err != nil {
			t.Fatal(err)
		}
		assertVector(t, "passkey_pause", v, hash, human)
	})

	t.Run("passkey_resume", func(t *testing.T) {
		v := V["passkey_resume"]
		in := v.Inputs
		hash, human, _, err := PasskeyResumeChallenge(
			unhexPubkey(t, hexField(t, in, "dwallet")),
			unhexPubkey(t, hexField(t, in, "policy")),
			bigU64(t, in, "nonce"),
			unhexSlot(t, hexField(t, in, "ownerSlot")),
		)
		if err != nil {
			t.Fatal(err)
		}
		assertVector(t, "passkey_resume", v, hash, human)
	})

	// session-keys (4)
	t.Run("session_keys_revoke_session", func(t *testing.T) {
		v := V["session_keys_revoke_session"]
		in := v.Inputs
		hash, human, _, err := SessionKeysRevokeChallenge(
			unhexPubkey(t, hexField(t, in, "dwallet")),
			unhexPubkey(t, hexField(t, in, "policy")),
			bigU64(t, in, "nonce"),
			unhexSlot(t, hexField(t, in, "ownerSlot")),
		)
		if err != nil {
			t.Fatal(err)
		}
		assertVector(t, "session_keys_revoke_session", v, hash, human)
	})

	t.Run("session_keys_add_allowed_program", func(t *testing.T) {
		v := V["session_keys_add_allowed_program"]
		in := v.Inputs
		hash, human, _, err := SessionKeysAddAllowedProgramChallenge(
			unhexPubkey(t, hexField(t, in, "dwallet")),
			unhexPubkey(t, hexField(t, in, "policy")),
			unhexPubkey(t, hexField(t, in, "programId")),
			bigU64(t, in, "nonce"),
			unhexSlot(t, hexField(t, in, "ownerSlot")),
		)
		if err != nil {
			t.Fatal(err)
		}
		assertVector(t, "session_keys_add_allowed_program", v, hash, human)
	})

	t.Run("session_keys_remove_allowed_program", func(t *testing.T) {
		v := V["session_keys_remove_allowed_program"]
		in := v.Inputs
		hash, human, _, err := SessionKeysRemoveAllowedProgramChallenge(
			unhexPubkey(t, hexField(t, in, "dwallet")),
			unhexPubkey(t, hexField(t, in, "policy")),
			unhexPubkey(t, hexField(t, in, "programId")),
			bigU64(t, in, "nonce"),
			unhexSlot(t, hexField(t, in, "ownerSlot")),
		)
		if err != nil {
			t.Fatal(err)
		}
		assertVector(t, "session_keys_remove_allowed_program", v, hash, human)
	})

	t.Run("session_keys_close_session", func(t *testing.T) {
		v := V["session_keys_close_session"]
		in := v.Inputs
		hash, human, _, err := SessionKeysCloseSessionChallenge(
			unhexPubkey(t, hexField(t, in, "dwallet")),
			unhexPubkey(t, hexField(t, in, "policy")),
			unhexPubkey(t, hexField(t, in, "recipient")),
			bigU64(t, in, "nonce"),
			unhexSlot(t, hexField(t, in, "ownerSlot")),
		)
		if err != nil {
			t.Fatal(err)
		}
		assertVector(t, "session_keys_close_session", v, hash, human)
	})

	// fhe-gated (3)
	t.Run("fhe_rotate_authority", func(t *testing.T) {
		v := V["fhe_rotate_authority"]
		in := v.Inputs
		hash, human, _, err := FHEGatedRotateAuthorityChallenge(
			unhexPubkey(t, hexField(t, in, "dwallet")),
			unhexPubkey(t, hexField(t, in, "policy")),
			unhexPubkey(t, hexField(t, in, "newFheAuthority")),
			bigU64(t, in, "nonce"),
			unhexSlot(t, hexField(t, in, "ownerSlot")),
		)
		if err != nil {
			t.Fatal(err)
		}
		assertVector(t, "fhe_rotate_authority", v, hash, human)
	})

	t.Run("fhe_pause", func(t *testing.T) {
		v := V["fhe_pause"]
		in := v.Inputs
		hash, human, _, err := FHEGatedPauseChallenge(
			unhexPubkey(t, hexField(t, in, "dwallet")),
			unhexPubkey(t, hexField(t, in, "policy")),
			bigU64(t, in, "nonce"),
			unhexSlot(t, hexField(t, in, "ownerSlot")),
		)
		if err != nil {
			t.Fatal(err)
		}
		assertVector(t, "fhe_pause", v, hash, human)
	})

	t.Run("fhe_resume", func(t *testing.T) {
		v := V["fhe_resume"]
		in := v.Inputs
		hash, human, _, err := FHEGatedResumeChallenge(
			unhexPubkey(t, hexField(t, in, "dwallet")),
			unhexPubkey(t, hexField(t, in, "policy")),
			bigU64(t, in, "nonce"),
			unhexSlot(t, hexField(t, in, "ownerSlot")),
		)
		if err != nil {
			t.Fatal(err)
		}
		assertVector(t, "fhe_resume", v, hash, human)
	})
}

func TestClearSigning_FixtureCoversAllPolicyOps(t *testing.T) {
	fx := loadFixture(t)
	want := []string{
		"allowlist_add_destination",
		"allowlist_remove_destination",
		"allowlist_pause",
		"allowlist_resume",
		"velocity_update_window",
		"velocity_pause",
		"velocity_resume",
		"time_lock_update_window",
		"time_lock_pause",
		"time_lock_resume",
		"oracle_update_bounds",
		"oracle_pause",
		"oracle_resume",
		"passkey_update_policy",
		"passkey_pause",
		"passkey_resume",
		"session_keys_revoke_session",
		"session_keys_add_allowed_program",
		"session_keys_remove_allowed_program",
		"session_keys_close_session",
		"fhe_rotate_authority",
		"fhe_pause",
		"fhe_resume",
	}
	for _, name := range want {
		if _, ok := fx.Vectors[name]; !ok {
			t.Errorf("missing fixture entry: %s", name)
		}
	}
}
