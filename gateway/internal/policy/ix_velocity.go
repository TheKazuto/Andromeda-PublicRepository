package policy

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"

	"github.com/gagliardetto/solana-go"
)

// Disc 11.
const DiscAddRuleVelocity uint8 = 11

// MaxVelocityWindows mirrors `MAX_VELOCITY_WINDOWS` in lib.rs.
const MaxVelocityWindows = 4

// VelocityWindow describes a single rate-limit window. F3 supports count-based
// limits (cap = N requests per window); sum-based limits are F3b.
type VelocityWindow struct {
	WindowSeconds uint64
	Cap           uint64
}

// AddRuleVelocityParams carries the typed inputs for `add_rule_velocity`
// (disc 11). Up to 4 windows; runtime counters initialized to zero on-chain.
type AddRuleVelocityParams struct {
	ProgramID         solana.PublicKey
	Engine            solana.PublicKey
	DWallet           solana.PublicKey
	Payer             solana.PublicKey
	InitAuthorityHash [32]byte
	ExpectedNonce     uint64
	RuleIndex         uint8
	AppliesTo         uint8
	Windows           []VelocityWindow // 1..4 windows
}

func AddRuleVelocity(p AddRuleVelocityParams) (solana.Instruction, error) {
	if len(p.Windows) < 1 || len(p.Windows) > MaxVelocityWindows {
		return nil, fmt.Errorf(
			"policy: velocity windows count must be 1..%d (got %d)", MaxVelocityWindows, len(p.Windows),
		)
	}
	rulePDA, _, err := RulePDA(p.ProgramID, p.Engine, KindVelocity, p.RuleIndex)
	if err != nil {
		return nil, fmt.Errorf("derive rule pda: %w", err)
	}
	eventAuth, _, err := EventAuthorityPDA(p.ProgramID)
	if err != nil {
		return nil, fmt.Errorf("derive event authority: %w", err)
	}

	// windows_config layout: 4 × {window_seconds u64 || cap u64} = 64 bytes.
	var windowsCfg [4 * 16]byte
	for i, w := range p.Windows {
		if w.WindowSeconds == 0 || w.Cap == 0 {
			return nil, fmt.Errorf("velocity window[%d]: window_seconds and cap must be > 0", i)
		}
		base := i * 16
		binary.LittleEndian.PutUint64(windowsCfg[base:base+8], w.WindowSeconds)
		binary.LittleEndian.PutUint64(windowsCfg[base+8:base+16], w.Cap)
	}

	data := make([]byte, 0, 1+32+8+1+1+1+64)
	data = append(data, DiscAddRuleVelocity)
	data = append(data, p.InitAuthorityHash[:]...)
	var nonce [8]byte
	binary.LittleEndian.PutUint64(nonce[:], p.ExpectedNonce)
	data = append(data, nonce[:]...)
	data = append(data, p.RuleIndex)
	data = append(data, p.AppliesTo)
	data = append(data, uint8(len(p.Windows)))
	data = append(data, windowsCfg[:]...)

	accounts := solana.AccountMetaSlice{
		{PublicKey: p.DWallet, IsSigner: false, IsWritable: false},
		{PublicKey: p.Engine, IsSigner: false, IsWritable: true},
		{PublicKey: rulePDA, IsSigner: false, IsWritable: true},
		{PublicKey: p.Payer, IsSigner: true, IsWritable: true},
		{PublicKey: SysvarInstructions, IsSigner: false, IsWritable: false},
		{PublicKey: SysvarClock, IsSigner: false, IsWritable: false},
		{PublicKey: SysvarRent, IsSigner: false, IsWritable: false},
		{PublicKey: SystemProgramID, IsSigner: false, IsWritable: false},
		{PublicKey: eventAuth, IsSigner: false, IsWritable: false},
		{PublicKey: p.ProgramID, IsSigner: false, IsWritable: false},
	}
	return solana.NewInstruction(p.ProgramID, accounts, data), nil
}

// VelocityConfigHash computes the canonical `config_hash` stored in
// `RuleEntry.config_hash` and `RuleHeader.config_hash` for Velocity rules.
// Mirrors `hashv(&[b"velocity-config-v1", &applies, &count, &windows_flat])`.
//
// `windowsFlat` must be exactly 4 × 48 = 192 bytes (full padded layout
// including runtime counters set to zero at creation).
func VelocityConfigHash(appliesTo uint8, windowsCount uint8, windowsFlat []byte) ([32]byte, error) {
	if len(windowsFlat) != MaxVelocityWindows*48 {
		return [32]byte{}, fmt.Errorf("velocity windows_flat must be %d bytes (got %d)",
			MaxVelocityWindows*48, len(windowsFlat))
	}
	h := sha256.New()
	h.Write([]byte("velocity-config-v1"))
	h.Write([]byte{appliesTo, windowsCount})
	h.Write(windowsFlat)
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out, nil
}
