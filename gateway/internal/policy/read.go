package policy

import (
	"context"
	"encoding/hex"
	"net/http"

	"github.com/gagliardetto/solana-go"
	"github.com/gagliardetto/solana-go/rpc"
	"github.com/go-chi/chi/v5"

	"github.com/shinkalabs/andromeda-gateway/internal/httpx"
)

// ─── GET /v1/policy/{dwallet} ───────────────────────────────────────────────
//
// Returns the full PolicyEngine state for a given dWallet: header + every
// active RuleEntry + each rule's sub-PDA decoded (Allowlist only in F2.7;
// other kinds will be decoded as F3..F9 land).
//
// Query params:
//   ?init_authority_hash_hex=<hex>  — required to derive the engine PDA.

type ruleStateJSON struct {
	Kind          uint8  `json:"kind"`
	Bump          uint8  `json:"bump"`
	Version       uint8  `json:"version"`
	Enabled       bool   `json:"enabled"`
	Generation    uint32 `json:"generation"`
	RulePDA       string `json:"rule_pda"`
	ConfigHashHex string `json:"config_hash_hex"`
	Detail        any    `json:"detail,omitempty"`
}

type allowlistDetailJSON struct {
	AppliesTo         uint8    `json:"applies_to"`
	DestinationsCount uint8    `json:"destinations_count"`
	DestinationsHex   []string `json:"destinations_hex"`
}

type readPolicyResponse struct {
	ProgramID                string          `json:"program_id"`
	EngineAddress            string          `json:"engine_address"`
	DwalletAddress           string          `json:"dwallet_address"`
	Version                  uint8           `json:"version"`
	Paused                   bool            `json:"paused"`
	RulesCount               uint8           `json:"rules_count"`
	RulesGeneration          uint32          `json:"rules_generation"`
	NextAdminNonce           uint64          `json:"next_admin_nonce"`
	NextPrimaryRecoverNonce  uint64          `json:"next_primary_recover_nonce"`
	NextOidcSessionNonce     uint64          `json:"next_oidc_session_nonce"`
	NextPasskeySessionNonce  uint64          `json:"next_passkey_session_nonce"`
	NextQuorumSessionNonce   uint64          `json:"next_quorum_session_nonce"`
	InitAuthoritySlotHex     string          `json:"init_authority_slot_hex"`
	OwnerSlotHex             string          `json:"owner_slot_hex"`
	Rules                    []ruleStateJSON `json:"rules"`
}

func (s *Service) readPolicy(w http.ResponseWriter, r *http.Request) {
	if s.RPCClient == nil {
		httpx.WriteError(w, http.StatusServiceUnavailable, "no_rpc",
			"SOLANA_RPC_URL is not configured")
		return
	}
	dwalletStr := chi.URLParam(r, "dwallet")
	dwallet, err := solana.PublicKeyFromBase58(dwalletStr)
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid_dwallet", "dwallet must be base58")
		return
	}
	hashHex := r.URL.Query().Get("init_authority_hash_hex")
	if hashHex == "" {
		httpx.WriteError(w, http.StatusBadRequest, "missing_init_authority_hash",
			"query parameter `init_authority_hash_hex` is required")
		return
	}
	hashBytes, err := hex.DecodeString(hashHex)
	if err != nil || len(hashBytes) != 32 {
		httpx.WriteError(w, http.StatusBadRequest, "invalid_init_authority_hash",
			"must be 32-byte hex")
		return
	}
	var initHash [32]byte
	copy(initHash[:], hashBytes)
	engine, _, err := EnginePDA(s.ProgramID, dwallet, initHash)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "pda_derivation_failed", err.Error())
		return
	}

	ctx := r.Context()
	engineAcct, err := s.RPCClient.GetAccountInfoWithOpts(ctx, engine, &rpc.GetAccountInfoOpts{
		Commitment: rpc.CommitmentConfirmed,
	})
	if err != nil {
		httpx.WriteError(w, http.StatusBadGateway, "rpc_failed", err.Error())
		return
	}
	if engineAcct == nil || engineAcct.Value == nil {
		httpx.WriteError(w, http.StatusNotFound, "engine_not_found",
			"PolicyEngine PDA does not exist on-chain")
		return
	}
	engineBytes := engineAcct.Value.Data.GetBinary()
	state, err := DecodePolicyEngine(engineBytes)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "decode_failed", err.Error())
		return
	}

	resp := readPolicyResponse{
		ProgramID:               s.ProgramID.String(),
		EngineAddress:           engine.String(),
		DwalletAddress:          dwallet.String(),
		Version:                 state.Version,
		Paused:                  state.Paused == 1,
		RulesCount:              state.RulesCount,
		RulesGeneration:         state.RulesGeneration,
		NextAdminNonce:          state.NextAdminNonce,
		NextPrimaryRecoverNonce: state.NextPrimaryRecoverNonce,
		NextOidcSessionNonce:    state.NextOidcSessionNonce,
		NextPasskeySessionNonce: state.NextPasskeySessionNonce,
		NextQuorumSessionNonce:  state.NextQuorumSessionNonce,
		InitAuthoritySlotHex:    hex.EncodeToString(state.InitAuthoritySlot[:]),
		OwnerSlotHex:            hex.EncodeToString(state.OwnerSlot[:]),
		Rules:                   make([]ruleStateJSON, 0, state.RulesCount),
	}

	// Best-effort: for each active rule, fetch and decode its sub-PDA.
	for i := 0; i < MaxRules; i++ {
		entry := state.Rules[i]
		if entry.Kind == KindEmpty {
			continue
		}
		ruleJSON := ruleStateJSON{
			Kind:          uint8(entry.Kind),
			Bump:          entry.Bump,
			Version:       entry.Version,
			Enabled:       entry.Enabled,
			Generation:    entry.Generation,
			RulePDA:       entry.RulePDA.String(),
			ConfigHashHex: hex.EncodeToString(entry.ConfigHash[:]),
		}
		if entry.Kind == KindAllowlist {
			if detail, err := fetchAllowlistDetail(ctx, s.RPCClient, entry.RulePDA); err == nil && detail != nil {
				ruleJSON.Detail = detail
			}
		}
		// F3..F9: decoders for other kinds land alongside their handlers.
		resp.Rules = append(resp.Rules, ruleJSON)
	}

	httpx.WriteJSON(w, http.StatusOK, resp)
}

func fetchAllowlistDetail(ctx context.Context, c *rpc.Client, pda solana.PublicKey) (*allowlistDetailJSON, error) {
	acct, err := c.GetAccountInfoWithOpts(ctx, pda, &rpc.GetAccountInfoOpts{
		Commitment: rpc.CommitmentConfirmed,
	})
	if err != nil || acct == nil || acct.Value == nil {
		return nil, err
	}
	state, err := DecodeAllowlistRule(acct.Value.Data.GetBinary())
	if err != nil {
		return nil, err
	}
	dests := make([]string, len(state.Destinations))
	for i, d := range state.Destinations {
		dests[i] = hex.EncodeToString(d[:])
	}
	return &allowlistDetailJSON{
		AppliesTo:         state.AppliesTo,
		DestinationsCount: state.DestinationsCount,
		DestinationsHex:   dests,
	}, nil
}
