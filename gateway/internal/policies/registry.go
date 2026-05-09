package policies

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/gagliardetto/solana-go"
)

const (
	TemplateAllowlist         = "allowlist-destinations"
	TemplateVelocityGuard     = "velocity-guard"
	TemplateTimeLock          = "time-lock"
	TemplateSessionKeys       = "session-keys"
	TemplateOracleConditional = "oracle-conditional"
	TemplatePasskeyStepUp     = "passkey-step-up"
	TemplateFHEGated          = "fhe-gated"
)

// AllTemplates is the catalogue surfaced to clients via /v1/policies/templates.
//
// Seeds reflect the audit C2 / Opção 4 design: every template's PDA includes
// init_authority_hash so squat by an attacker on one (dwallet, init_authority)
// pair cannot block the legitimate user. session-keys also includes
// session_index for multi-session support (Audit H6).
var AllTemplates = []TemplateMetadata{
	{
		Name:        TemplateAllowlist,
		DisplayName: "Allowlist Destinations",
		Description: "Approve signing only when the destination matches the whitelist.",
		Mutable:     []string{"destinations", "active"},
		Seeds:       "[b\"allowlist\", dwallet, init_authority_hash]",
	},
	{
		Name:        TemplateVelocityGuard,
		DisplayName: "Velocity Guard",
		Description: "Cap signature throughput in a sliding slot window. Defends against compromised-key bursts.",
		Mutable:     []string{"max_sigs_per_window", "window_slots", "active"},
		Seeds:       "[b\"velocity\", dwallet, init_authority_hash]",
	},
	{
		Name:        TemplateTimeLock,
		DisplayName: "Time Lock",
		Description: "Allow signing only inside an absolute or recurring slot window.",
		Mutable:     []string{"mode", "start_slot", "end_slot", "recurring_period_slots", "active"},
		Seeds:       "[b\"timelock\", dwallet, init_authority_hash]",
	},
	{
		Name:        TemplateSessionKeys,
		DisplayName: "Session Keys",
		Description: "Delegate signing authority to a temporary keypair under hard limits: expires_at_slot, max_uses, max_amount_per_tx, allowed program list. Supports multiple simultaneous sessions per dwallet.",
		Mutable:     []string{"allowed_programs", "active"},
		Seeds:       "[b\"session_key\", dwallet, init_authority_hash, session_index]",
	},
	{
		Name:        TemplateOracleConditional,
		DisplayName: "Oracle Conditional",
		Description: "Approve signing only when an oracle price feed (Pyth Pull V2) is within bounds and fresh (max_age_slots).",
		Mutable:     []string{"min_price", "max_price", "max_age_slots", "active"},
		Seeds:       "[b\"oracle\", dwallet, init_authority_hash]",
	},
	{
		Name:        TemplatePasskeyStepUp,
		DisplayName: "Passkey Step-Up",
		Description: "Above threshold_amount, require a verified WebAuthn passkey assertion (validated end-to-end on-chain via Secp256r1 precompile).",
		Mutable:     []string{"threshold_amount", "passkey_pubkey_hash", "active"},
		Seeds:       "[b\"passkey\", dwallet, init_authority_hash]",
	},
	{
		Name:        TemplateFHEGated,
		DisplayName: "FHE-gated",
		Description: "Approve signing only when an EncryptedDecision signed by an allowed fhe_authority is supplied. Powers Confidential Workflows.",
		Mutable:     []string{"fhe_authority", "decision_max_age_slots", "active"},
		Seeds:       "[b\"fhe_gated\", dwallet, init_authority_hash]",
	},
}

// TemplateMetadata is the public surface exposed via /v1/policies/templates.
type TemplateMetadata struct {
	Name        string   `json:"name"`
	DisplayName string   `json:"display_name"`
	Description string   `json:"description"`
	Mutable     []string `json:"mutable_fields"`
	Seeds       string   `json:"seeds"`
}

// Registry maps template name → deployed Solana program id.
type Registry struct {
	IkaProgramID    solana.PublicKey
	IkaCoordinator  solana.PublicKey
	ProgramIDs      map[string]solana.PublicKey
}

// NewRegistry parses ANDROMEDA_TEMPLATE_PROGRAM_IDS_JSON, IKA_PROGRAM_ID and
// IKA_COORDINATOR_ADDRESS. The JSON shape is `{"allowlist-destinations": "...", ...}`.
//
// Templates without a configured program id are still listed by
// /v1/policies/templates but reject deploy/request-signature with 503.
func NewRegistry(programIDsJSON, ikaProgramID, ikaCoordinator string) (*Registry, error) {
	if ikaProgramID == "" {
		return nil, errors.New("IKA_PROGRAM_ID is required for the policies feature")
	}
	if ikaCoordinator == "" {
		return nil, errors.New("IKA_COORDINATOR_ADDRESS is required for the policies feature")
	}
	ika, err := solana.PublicKeyFromBase58(ikaProgramID)
	if err != nil {
		return nil, fmt.Errorf("parse IKA_PROGRAM_ID: %w", err)
	}
	coord, err := solana.PublicKeyFromBase58(ikaCoordinator)
	if err != nil {
		return nil, fmt.Errorf("parse IKA_COORDINATOR_ADDRESS: %w", err)
	}

	pids := map[string]solana.PublicKey{}
	if programIDsJSON != "" {
		raw := map[string]string{}
		if err := json.Unmarshal([]byte(programIDsJSON), &raw); err != nil {
			return nil, fmt.Errorf("parse ANDROMEDA_TEMPLATE_PROGRAM_IDS_JSON: %w", err)
		}
		for k, v := range raw {
			pk, err := solana.PublicKeyFromBase58(v)
			if err != nil {
				return nil, fmt.Errorf("invalid program id for %s: %w", k, err)
			}
			pids[k] = pk
		}
	}
	return &Registry{
		IkaProgramID:   ika,
		IkaCoordinator: coord,
		ProgramIDs:     pids,
	}, nil
}

// ProgramID returns the program id for a template, or an error if not configured.
func (r *Registry) ProgramID(template string) (solana.PublicKey, error) {
	pk, ok := r.ProgramIDs[template]
	if !ok {
		return solana.PublicKey{}, fmt.Errorf("template %s has no program id configured", template)
	}
	return pk, nil
}
