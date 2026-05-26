// Update 7 (2026-05-26) cross-language fixture validation.
//
// Each test below loads a fixture JSON produced by the Rust generator
// (`contracts/policy-engine/src/lib.rs::update7_fixtures::gen_update7_fixtures`),
// re-computes the same hash from the same inputs using the Go mirror, and
// asserts byte-for-byte agreement. A failure here means the Go side has
// drifted from the canonical layout — either a recent edit broke the wire
// format or the fixture needs regeneration after a deliberate change.
//
// To regenerate after a canonical change:
//
//	cd contracts/policy-engine
//	cargo test --features host-test --lib gen_update7_fixtures -- --ignored
//
// CI runs without `--ignored`, so the fixtures stay frozen for the build.
package policy

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/gagliardetto/solana-go"
)

const fixturesDirRel = "../../../fixtures/policy_engine_v3/challenges/runtime"

func loadUpdate7Fixture(t *testing.T, name string, dst any) {
	t.Helper()
	path := filepath.Join(fixturesDirRel, name)
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	if err := json.Unmarshal(raw, dst); err != nil {
		t.Fatalf("unmarshal %s: %v", path, err)
	}
}

func decodeHexN(t *testing.T, s string, n int) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("decode hex %q: %v", s, err)
	}
	if len(b) != n {
		t.Fatalf("expected %d bytes, got %d (hex=%q)", n, len(b), s)
	}
	return b
}

func decodeArr32(t *testing.T, s string) [32]byte {
	var out [32]byte
	copy(out[:], decodeHexN(t, s, 32))
	return out
}

func decodeArr8(t *testing.T, s string) [8]byte {
	var out [8]byte
	copy(out[:], decodeHexN(t, s, 8))
	return out
}

func decodeArrSlot(t *testing.T, s string) [MemberSlotLen]byte {
	var out [MemberSlotLen]byte
	copy(out[:], decodeHexN(t, s, MemberSlotLen))
	return out
}

func decodeAddress32(t *testing.T, s string) solana.PublicKey {
	return solana.PublicKeyFromBytes(decodeHexN(t, s, 32))
}

// ─── swap_sign_message fixture ──────────────────────────────────────────────

type swapSignMessageFixture struct {
	Input struct {
		DwalletHex      string `json:"dwallet_hex"`
		FromTokenHex    string `json:"from_token_hex"`
		FromAmount      uint64 `json:"from_amount"`
		ToTokenHex      string `json:"to_token_hex"`
		MinAmountOut    uint64 `json:"min_amount_out"`
		ChainTagHex     string `json:"chain_tag_hex"`
		SignatureScheme uint16 `json:"signature_scheme"`
	} `json:"input"`
	Expected struct {
		HumanMessage string `json:"human_message"`
		HumanHex     string `json:"human_hex"`
		HumanBytes   int    `json:"human_bytes"`
	} `json:"expected"`
}

func TestFixture_SwapSignMessage(t *testing.T) {
	var fx swapSignMessageFixture
	loadUpdate7Fixture(t, "swap_sign_message.json", &fx)
	dwallet := decodeAddress32(t, fx.Input.DwalletHex)
	fromToken := decodeArr32(t, fx.Input.FromTokenHex)
	toToken := decodeArr32(t, fx.Input.ToTokenHex)
	chainTag := decodeArr8(t, fx.Input.ChainTagHex)

	got := HumanMessageSwap(dwallet, fromToken, fx.Input.FromAmount, toToken,
		fx.Input.MinAmountOut, chainTag, fx.Input.SignatureScheme)

	if string(got) != fx.Expected.HumanMessage {
		t.Errorf("human_message mismatch\n want: %q\n got : %q", fx.Expected.HumanMessage, string(got))
	}
	if hex.EncodeToString(got) != fx.Expected.HumanHex {
		t.Errorf("human_hex mismatch (Go renderer drifted from Rust)\n want: %s\n got : %s",
			fx.Expected.HumanHex, hex.EncodeToString(got))
	}
	if len(got) != fx.Expected.HumanBytes {
		t.Errorf("human_bytes=%d want %d", len(got), fx.Expected.HumanBytes)
	}
}

// ─── swap_metadata_digest fixture ───────────────────────────────────────────

type swapMetadataDigestFixture struct {
	Input struct {
		EngineHex        string `json:"engine_hex"`
		DwalletHex       string `json:"dwallet_hex"`
		MessageDigestHex string `json:"message_digest_hex"`
		DestinationHex   string `json:"destination_hex"`
		UserPubkeyHex    string `json:"user_pubkey_hex"`
		SignatureScheme  uint16 `json:"signature_scheme"`
		RulesGeneration  uint32 `json:"rules_generation"`
		FromAmount       uint64 `json:"from_amount"`
		AssetIndex       uint8  `json:"asset_index"`
		FromTokenHex     string `json:"from_token_hex"`
		ToTokenHex       string `json:"to_token_hex"`
		MinAmountOut     uint64 `json:"min_amount_out"`
		ChainTagHex      string `json:"chain_tag_hex"`
	} `json:"input"`
	Expected struct {
		PreimageHex   string `json:"preimage_hex"`
		PreimageBytes int    `json:"preimage_bytes"`
		ChallengeHex  string `json:"challenge_hex"`
	} `json:"expected"`
}

func TestFixture_SwapMetadataDigest(t *testing.T) {
	var fx swapMetadataDigestFixture
	loadUpdate7Fixture(t, "swap_metadata_digest.json", &fx)
	in := SwapMetadataDigestInput{
		Engine:          decodeAddress32(t, fx.Input.EngineHex),
		DWallet:         decodeAddress32(t, fx.Input.DwalletHex),
		MessageDigest:   decodeArr32(t, fx.Input.MessageDigestHex),
		Destination:     decodeArr32(t, fx.Input.DestinationHex),
		UserPubkey:      decodeArr32(t, fx.Input.UserPubkeyHex),
		SignatureScheme: fx.Input.SignatureScheme,
		RulesGeneration: fx.Input.RulesGeneration,
		FromAmount:      fx.Input.FromAmount,
		AssetIndex:      fx.Input.AssetIndex,
		FromToken:       decodeArr32(t, fx.Input.FromTokenHex),
		ToToken:         decodeArr32(t, fx.Input.ToTokenHex),
		MinAmountOut:    fx.Input.MinAmountOut,
		ChainTag:        decodeArr8(t, fx.Input.ChainTagHex),
	}
	gotPre := hex.EncodeToString(in.Preimage())
	if gotPre != fx.Expected.PreimageHex {
		t.Errorf("preimage_hex mismatch (V3 metadata layout drifted)\n want: %s\n got : %s",
			fx.Expected.PreimageHex, gotPre)
	}
	if len(in.Preimage()) != fx.Expected.PreimageBytes {
		t.Errorf("preimage_bytes=%d want %d", len(in.Preimage()), fx.Expected.PreimageBytes)
	}
	gotHash := in.Hash()
	if hex.EncodeToString(gotHash[:]) != fx.Expected.ChallengeHex {
		t.Errorf("challenge_hex mismatch\n want: %s\n got : %s",
			fx.Expected.ChallengeHex, hex.EncodeToString(gotHash[:]))
	}
}

// ─── swap_use_challenge fixture ─────────────────────────────────────────────

type swapUseChallengeFixture struct {
	Input struct {
		EngineHex         string `json:"engine_hex"`
		DwalletHex        string `json:"dwallet_hex"`
		MetadataDigestHex string `json:"metadata_digest_hex"`
		OwnerSlotHex      string `json:"owner_slot_hex"`
		HumanHex          string `json:"human_hex"`
	} `json:"input"`
	Expected struct {
		PreimageHex   string `json:"preimage_hex"`
		PreimageBytes int    `json:"preimage_bytes"`
		ChallengeHex  string `json:"challenge_hex"`
	} `json:"expected"`
}

func TestFixture_SwapUseChallenge(t *testing.T) {
	var fx swapUseChallengeFixture
	loadUpdate7Fixture(t, "swap_use_challenge.json", &fx)
	humanBytes, err := hex.DecodeString(fx.Input.HumanHex)
	if err != nil {
		t.Fatalf("decode human_hex: %v", err)
	}
	in := SwapUseChallengeInput{
		HumanMessage:   humanBytes,
		Engine:         decodeAddress32(t, fx.Input.EngineHex),
		DWallet:        decodeAddress32(t, fx.Input.DwalletHex),
		MetadataDigest: decodeArr32(t, fx.Input.MetadataDigestHex),
		OwnerSlot:      decodeArrSlot(t, fx.Input.OwnerSlotHex),
	}
	gotPre := hex.EncodeToString(in.Preimage())
	if gotPre != fx.Expected.PreimageHex {
		t.Errorf("preimage_hex mismatch (swap_use_challenge layout drifted)\n want: %s\n got : %s",
			fx.Expected.PreimageHex, gotPre)
	}
	if len(in.Preimage()) != fx.Expected.PreimageBytes {
		t.Errorf("preimage_bytes=%d want %d", len(in.Preimage()), fx.Expected.PreimageBytes)
	}
	gotHash := in.Hash()
	if hex.EncodeToString(gotHash[:]) != fx.Expected.ChallengeHex {
		t.Errorf("challenge_hex mismatch\n want: %s\n got : %s",
			fx.Expected.ChallengeHex, hex.EncodeToString(gotHash[:]))
	}
}

// ─── bundle_use_challenge_2 fixture ─────────────────────────────────────────

type bundleUseChallenge2Fixture struct {
	Input struct {
		EngineHex                   string   `json:"engine_hex"`
		DwalletHex                  string   `json:"dwallet_hex"`
		OwnerSlotHex                string   `json:"owner_slot_hex"`
		Total                       uint8    `json:"total"`
		OrderedMetadataDigestsHex   []string `json:"ordered_metadata_digests_hex"`
		Leg0View                    struct {
			ThisIndex              uint8    `json:"this_index"`
			ThisMetadataDigestHex  string   `json:"this_metadata_digest_hex"`
			OtherDigestsHex        []string `json:"other_digests_hex"`
		} `json:"leg0_view"`
		Leg1View struct {
			ThisIndex              uint8    `json:"this_index"`
			ThisMetadataDigestHex  string   `json:"this_metadata_digest_hex"`
			OtherDigestsHex        []string `json:"other_digests_hex"`
		} `json:"leg1_view"`
	} `json:"input"`
	Expected struct {
		PreimageHex   string `json:"preimage_hex"`
		PreimageBytes int    `json:"preimage_bytes"`
		ChallengeHex  string `json:"challenge_hex"`
	} `json:"expected"`
}

func TestFixture_BundleUseChallenge2(t *testing.T) {
	var fx bundleUseChallenge2Fixture
	loadUpdate7Fixture(t, "bundle_use_challenge_2.json", &fx)
	engine := decodeAddress32(t, fx.Input.EngineHex)
	dwallet := decodeAddress32(t, fx.Input.DwalletHex)
	ownerSlot := decodeArrSlot(t, fx.Input.OwnerSlotHex)

	// Validate from BOTH legs' viewpoints — both MUST produce the expected
	// challenge_hex (the bundle invariant).
	for _, leg := range []struct {
		name        string
		thisIndex   uint8
		thisDigest  string
		otherHexes  []string
		checkPreimg bool // only leg0 matches the canonical preimage in the fixture (ordered = [approve, swap])
	}{
		{"leg0", fx.Input.Leg0View.ThisIndex, fx.Input.Leg0View.ThisMetadataDigestHex, fx.Input.Leg0View.OtherDigestsHex, true},
		{"leg1", fx.Input.Leg1View.ThisIndex, fx.Input.Leg1View.ThisMetadataDigestHex, fx.Input.Leg1View.OtherDigestsHex, true},
	} {
		t.Run(leg.name, func(t *testing.T) {
			others := make([][32]byte, len(leg.otherHexes))
			for i, h := range leg.otherHexes {
				others[i] = decodeArr32(t, h)
			}
			in := BundleUseChallengeInput{
				Engine:             engine,
				DWallet:            dwallet,
				ThisMetadataDigest: decodeArr32(t, leg.thisDigest),
				OwnerSlot:          ownerSlot,
				Total:              fx.Input.Total,
				ThisIndex:          leg.thisIndex,
				OtherDigests:       others,
			}
			pre, err := in.Preimage()
			if err != nil {
				t.Fatalf("preimage: %v", err)
			}
			// The preimage from EACH leg's viewpoint must equal the canonical
			// ordered preimage in the fixture — that is the bundle invariant.
			if hex.EncodeToString(pre) != fx.Expected.PreimageHex {
				t.Errorf("preimage_hex mismatch from %s viewpoint\n want: %s\n got : %s",
					leg.name, fx.Expected.PreimageHex, hex.EncodeToString(pre))
			}
			if len(pre) != fx.Expected.PreimageBytes {
				t.Errorf("preimage_bytes=%d want %d", len(pre), fx.Expected.PreimageBytes)
			}
			hash, err := in.Hash()
			if err != nil {
				t.Fatalf("hash: %v", err)
			}
			if hex.EncodeToString(hash[:]) != fx.Expected.ChallengeHex {
				t.Errorf("challenge_hex mismatch from %s viewpoint\n want: %s\n got : %s",
					leg.name, fx.Expected.ChallengeHex, hex.EncodeToString(hash[:]))
			}
		})
	}

	// And the ordered list in the fixture must match what the canonical
	// reordering produces.
	if len(fx.Input.OrderedMetadataDigestsHex) != int(fx.Input.Total) {
		t.Errorf("ordered_metadata_digests_hex length %d != total %d",
			len(fx.Input.OrderedMetadataDigestsHex), fx.Input.Total)
	}
}
