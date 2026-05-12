package policies

import (
	"encoding/base64"
	"errors"
	"fmt"

	"github.com/gagliardetto/solana-go"

	"github.com/shinkalabs/andromeda-gateway/internal/auth"
)

// This file holds the two big template×action dispatch tables behind the
// policy admin endpoints — extracted from routes.go to keep that file
// focused on HTTP wiring. computeAdminChallenge builds the off-chain
// challenge a policy owner signs; dispatchAdminSubmit assembles the
// on-chain instruction(s) for a signed admin action. Both touch the
// authority of deployed dWallet policies, so changes here are a contract
// review item (see contracts/ and CLAUDE.md §3).

func computeAdminChallenge(template string, req adminChallengeRequest, dwallet solana.PublicKey, ownerSlot [auth.MemberSlotLen]byte) ([32]byte, error) {
	var zero [32]byte
	switch template {
	case TemplateAllowlist:
		switch req.Action {
		case "add_destination", "remove_destination":
			dest, derr := decodeBase58OrBase64Bytes32(req.DestinationBase64)
			if derr != nil {
				return zero, fmt.Errorf("destination: %w", derr)
			}
			if req.Action == "add_destination" {
				return auth.AllowlistAddDestinationChallenge(dwallet, dest, req.ExpectedNonce, ownerSlot), nil
			}
			return auth.AllowlistRemoveDestinationChallenge(dwallet, dest, req.ExpectedNonce, ownerSlot), nil
		case "pause":
			return auth.AllowlistPauseChallenge(dwallet, req.ExpectedNonce, ownerSlot), nil
		case "resume":
			return auth.AllowlistResumeChallenge(dwallet, req.ExpectedNonce, ownerSlot), nil
		}
	case TemplateVelocityGuard:
		switch req.Action {
		case "update_window":
			if req.MaxSigsPerWindow == nil || req.WindowSlots == nil {
				return zero, errors.New("max_sigs_per_window and window_slots required")
			}
			return auth.VelocityUpdateWindowChallenge(dwallet, *req.MaxSigsPerWindow, *req.WindowSlots, req.ExpectedNonce, ownerSlot), nil
		case "pause":
			return auth.VelocityPauseChallenge(dwallet, req.ExpectedNonce, ownerSlot), nil
		case "resume":
			return auth.VelocityResumeChallenge(dwallet, req.ExpectedNonce, ownerSlot), nil
		}
	case TemplateTimeLock:
		switch req.Action {
		case "update_window":
			if req.Mode == nil || req.StartSlot == nil || req.EndSlot == nil || req.RecurringPeriodSlots == nil {
				return zero, errors.New("mode, start_slot, end_slot, recurring_period_slots required")
			}
			return auth.TimeLockUpdateWindowChallenge(dwallet, *req.Mode, *req.StartSlot, *req.EndSlot, *req.RecurringPeriodSlots, req.ExpectedNonce, ownerSlot), nil
		case "pause":
			return auth.TimeLockPauseChallenge(dwallet, req.ExpectedNonce, ownerSlot), nil
		case "resume":
			return auth.TimeLockResumeChallenge(dwallet, req.ExpectedNonce, ownerSlot), nil
		}
	case TemplateOracleConditional:
		switch req.Action {
		case "update_bounds":
			if req.MinPrice == nil || req.MaxPrice == nil || req.MaxAgeSlots == nil {
				return zero, errors.New("min_price, max_price, max_age_slots required")
			}
			var maxConfBps uint16
			if req.MaxConfidenceBps != nil {
				maxConfBps = *req.MaxConfidenceBps
			}
			return auth.OracleUpdateBoundsChallenge(dwallet, *req.MinPrice, *req.MaxPrice, *req.MaxAgeSlots, maxConfBps, req.ExpectedNonce, ownerSlot), nil
		case "pause":
			return auth.OraclePauseChallenge(dwallet, req.ExpectedNonce, ownerSlot), nil
		case "resume":
			return auth.OracleResumeChallenge(dwallet, req.ExpectedNonce, ownerSlot), nil
		}
	case TemplatePasskeyStepUp:
		switch req.Action {
		case "update_policy":
			if req.ThresholdAmount == nil || req.PasskeyPubkeyB64 == "" {
				return zero, errors.New("threshold_amount and passkey_pubkey_base64 required")
			}
			pkb, derr := base64.StdEncoding.DecodeString(req.PasskeyPubkeyB64)
			if derr != nil || len(pkb) != 33 {
				return zero, errors.New("passkey_pubkey_base64 must decode to 33 bytes")
			}
			var pk [33]byte
			copy(pk[:], pkb)
			return auth.PasskeyUpdatePolicyChallenge(dwallet, *req.ThresholdAmount, pk, req.ExpectedNonce, ownerSlot), nil
		case "pause":
			return auth.PasskeyPauseChallenge(dwallet, req.ExpectedNonce, ownerSlot), nil
		case "resume":
			return auth.PasskeyResumeChallenge(dwallet, req.ExpectedNonce, ownerSlot), nil
		}
	case TemplateFHEGated:
		switch req.Action {
		case "rotate_authority":
			if req.NewFHEAuthority == "" {
				return zero, errors.New("new_fhe_authority required")
			}
			fa, ferr := solana.PublicKeyFromBase58(req.NewFHEAuthority)
			if ferr != nil {
				return zero, fmt.Errorf("new_fhe_authority: %w", ferr)
			}
			return auth.FHEGatedRotateAuthorityChallenge(dwallet, fa, req.ExpectedNonce, ownerSlot), nil
		case "pause":
			return auth.FHEGatedPauseChallenge(dwallet, req.ExpectedNonce, ownerSlot), nil
		case "resume":
			return auth.FHEGatedResumeChallenge(dwallet, req.ExpectedNonce, ownerSlot), nil
		}
	case TemplateSessionKeys:
		// Audit C2 (Opção 4): create_session is now an init_policy flow,
		// not an admin action — use POST /v1/policies/session-keys/init.
		switch req.Action {
		case "revoke":
			return auth.SessionKeysRevokeChallenge(dwallet, req.ExpectedNonce, ownerSlot), nil
		case "add_allowed_program", "remove_allowed_program":
			if req.AllowedProgram == "" {
				return zero, errors.New("allowed_program required")
			}
			pid, perr := solana.PublicKeyFromBase58(req.AllowedProgram)
			if perr != nil {
				return zero, fmt.Errorf("allowed_program: %w", perr)
			}
			if req.Action == "add_allowed_program" {
				return auth.SessionKeysAddAllowedProgramChallenge(dwallet, pid, req.ExpectedNonce, ownerSlot), nil
			}
			return auth.SessionKeysRemoveAllowedProgramChallenge(dwallet, pid, req.ExpectedNonce, ownerSlot), nil
		case "close_session":
			if req.Recipient == "" {
				return zero, errors.New("recipient required")
			}
			rcpt, rerr := solana.PublicKeyFromBase58(req.Recipient)
			if rerr != nil {
				return zero, fmt.Errorf("recipient: %w", rerr)
			}
			return auth.SessionKeysCloseSessionChallenge(dwallet, rcpt, req.ExpectedNonce, ownerSlot), nil
		case "create_session":
			return zero, errors.New("create_session is now an init flow — POST /v1/policies/session-keys/init (Audit C2)")
		}
	}
	return zero, fmt.Errorf("unknown template/action: %s/%s", template, req.Action)
}

// dispatchAdminSubmit routes admin actions to the right builder. After
// Audit C1: no `now`/`current_ts` is needed (Clock sysvar handles it).
// After Audit C2: AdminContext carries InitAuthorityHash for PDA derivation.
// After Audit H6: session-keys admin actions also need session_index.
func dispatchAdminSubmit(reg *Registry, template string, req adminSubmitRequest, ctx AdminContext, sig AdminSignature) ([]solana.Instruction, error) {
	switch template {
	case TemplateAllowlist:
		switch req.Action {
		case "add_destination", "remove_destination":
			dest, derr := decodeBase58OrBase64Bytes32(req.DestinationBase64)
			if derr != nil {
				return nil, fmt.Errorf("destination: %w", derr)
			}
			action := AllowlistAddDestination
			if req.Action == "remove_destination" {
				action = AllowlistRemoveDestination
			}
			return BuildAllowlistAdmin(reg, AllowlistAdminInput{
				AdminContext: ctx, Action: action, Destination: dest,
				ExpectedNonce: req.ExpectedNonce, OwnerSig: sig,
			})
		case "pause":
			return BuildAllowlistAdmin(reg, AllowlistAdminInput{
				AdminContext: ctx, Action: AllowlistPauseAction,
				ExpectedNonce: req.ExpectedNonce, OwnerSig: sig,
			})
		case "resume":
			return BuildAllowlistAdmin(reg, AllowlistAdminInput{
				AdminContext: ctx, Action: AllowlistResumeAction,
				ExpectedNonce: req.ExpectedNonce, OwnerSig: sig,
			})
		}
	case TemplateVelocityGuard:
		switch req.Action {
		case "update_window":
			if req.MaxSigsPerWindow == nil || req.WindowSlots == nil {
				return nil, errors.New("max_sigs_per_window and window_slots required")
			}
			return BuildVelocityAdmin(reg, VelocityAdminInput{
				AdminContext:     ctx,
				Action:           VelocityUpdateWindow,
				MaxSigsPerWindow: *req.MaxSigsPerWindow,
				WindowSlots:      *req.WindowSlots,
				ExpectedNonce:    req.ExpectedNonce, OwnerSig: sig,
			})
		case "pause":
			return BuildVelocityAdmin(reg, VelocityAdminInput{
				AdminContext: ctx, Action: VelocityPauseAction,
				ExpectedNonce: req.ExpectedNonce, OwnerSig: sig,
			})
		case "resume":
			return BuildVelocityAdmin(reg, VelocityAdminInput{
				AdminContext: ctx, Action: VelocityResumeAction,
				ExpectedNonce: req.ExpectedNonce, OwnerSig: sig,
			})
		}
	case TemplateTimeLock:
		switch req.Action {
		case "update_window":
			if req.Mode == nil || req.StartSlot == nil || req.EndSlot == nil || req.RecurringPeriodSlots == nil {
				return nil, errors.New("mode, start_slot, end_slot, recurring_period_slots required")
			}
			return BuildTimeLockAdmin(reg, TimeLockAdminInput{
				AdminContext:         ctx,
				Action:               TimeLockUpdateWindow,
				Mode:                 *req.Mode,
				StartSlot:            *req.StartSlot,
				EndSlot:              *req.EndSlot,
				RecurringPeriodSlots: *req.RecurringPeriodSlots,
				ExpectedNonce:        req.ExpectedNonce, OwnerSig: sig,
			})
		case "pause":
			return BuildTimeLockAdmin(reg, TimeLockAdminInput{
				AdminContext: ctx, Action: TimeLockPauseAction,
				ExpectedNonce: req.ExpectedNonce, OwnerSig: sig,
			})
		case "resume":
			return BuildTimeLockAdmin(reg, TimeLockAdminInput{
				AdminContext: ctx, Action: TimeLockResumeAction,
				ExpectedNonce: req.ExpectedNonce, OwnerSig: sig,
			})
		}
	case TemplateOracleConditional:
		switch req.Action {
		case "update_bounds":
			if req.MinPrice == nil || req.MaxPrice == nil || req.MaxAgeSlots == nil {
				return nil, errors.New("min_price, max_price, max_age_slots required")
			}
			var maxConfBps uint16
			if req.MaxConfidenceBps != nil {
				maxConfBps = *req.MaxConfidenceBps
			}
			return BuildOracleAdmin(reg, OracleAdminInput{
				AdminContext: ctx, Action: OracleUpdateBounds,
				MinPrice: *req.MinPrice, MaxPrice: *req.MaxPrice, MaxAgeSlots: *req.MaxAgeSlots,
				MaxConfidenceBps: maxConfBps,
				ExpectedNonce:    req.ExpectedNonce, OwnerSig: sig,
			})
		case "pause":
			return BuildOracleAdmin(reg, OracleAdminInput{
				AdminContext: ctx, Action: OraclePauseAction,
				ExpectedNonce: req.ExpectedNonce, OwnerSig: sig,
			})
		case "resume":
			return BuildOracleAdmin(reg, OracleAdminInput{
				AdminContext: ctx, Action: OracleResumeAction,
				ExpectedNonce: req.ExpectedNonce, OwnerSig: sig,
			})
		}
	case TemplatePasskeyStepUp:
		switch req.Action {
		case "update_policy":
			if req.ThresholdAmount == nil || req.PasskeyPubkeyB64 == "" {
				return nil, errors.New("threshold_amount and passkey_pubkey_base64 required")
			}
			pkb, derr := base64.StdEncoding.DecodeString(req.PasskeyPubkeyB64)
			if derr != nil || len(pkb) != 33 {
				return nil, errors.New("passkey_pubkey_base64 must decode to 33 bytes")
			}
			var pk [33]byte
			copy(pk[:], pkb)
			return BuildPasskeyAdmin(reg, PasskeyAdminInput{
				AdminContext: ctx, Action: PasskeyUpdatePolicy,
				ThresholdAmount: *req.ThresholdAmount, PasskeyPubkey: pk,
				ExpectedNonce: req.ExpectedNonce, OwnerSig: sig,
			})
		case "pause":
			return BuildPasskeyAdmin(reg, PasskeyAdminInput{
				AdminContext: ctx, Action: PasskeyPauseAction,
				ExpectedNonce: req.ExpectedNonce, OwnerSig: sig,
			})
		case "resume":
			return BuildPasskeyAdmin(reg, PasskeyAdminInput{
				AdminContext: ctx, Action: PasskeyResumeAction,
				ExpectedNonce: req.ExpectedNonce, OwnerSig: sig,
			})
		}
	case TemplateFHEGated:
		switch req.Action {
		case "rotate_authority":
			if req.NewFHEAuthority == "" {
				return nil, errors.New("new_fhe_authority required")
			}
			fa, ferr := solana.PublicKeyFromBase58(req.NewFHEAuthority)
			if ferr != nil {
				return nil, fmt.Errorf("new_fhe_authority: %w", ferr)
			}
			return BuildFHEGatedAdmin(reg, FHEGatedAdminInput{
				AdminContext: ctx, Action: FHEGatedRotateAuthority, NewFHEAuthority: fa,
				ExpectedNonce: req.ExpectedNonce, OwnerSig: sig,
			})
		case "pause":
			return BuildFHEGatedAdmin(reg, FHEGatedAdminInput{
				AdminContext: ctx, Action: FHEGatedPauseAction,
				ExpectedNonce: req.ExpectedNonce, OwnerSig: sig,
			})
		case "resume":
			return BuildFHEGatedAdmin(reg, FHEGatedAdminInput{
				AdminContext: ctx, Action: FHEGatedResumeAction,
				ExpectedNonce: req.ExpectedNonce, OwnerSig: sig,
			})
		}
	case TemplateSessionKeys:
		// Audit H6: session_index required to identify which session.
		if req.SessionIndex == nil {
			return nil, errors.New("session_index required for session-keys admin actions (Audit H6)")
		}
		switch req.Action {
		case "create_session":
			return nil, errors.New("create_session moved to /v1/policies/session-keys/init (Audit C2)")
		case "revoke":
			return BuildSessionKeysAdmin(reg, SessionKeysAdminInput{
				AdminContext: ctx, SessionIndex: *req.SessionIndex,
				Action:        SessionKeysRevoke,
				ExpectedNonce: req.ExpectedNonce, OwnerSig: sig,
			})
		case "add_allowed_program", "remove_allowed_program":
			if req.AllowedProgram == "" {
				return nil, errors.New("allowed_program required")
			}
			pid, perr := solana.PublicKeyFromBase58(req.AllowedProgram)
			if perr != nil {
				return nil, fmt.Errorf("allowed_program: %w", perr)
			}
			action := SessionKeysAddAllowedProgram
			if req.Action == "remove_allowed_program" {
				action = SessionKeysRemoveAllowedProgram
			}
			return BuildSessionKeysAdmin(reg, SessionKeysAdminInput{
				AdminContext: ctx, SessionIndex: *req.SessionIndex,
				Action: action, ProgramID: pid,
				ExpectedNonce: req.ExpectedNonce, OwnerSig: sig,
			})
		case "close_session":
			if req.Recipient == "" {
				return nil, errors.New("recipient required")
			}
			rcpt, rerr := solana.PublicKeyFromBase58(req.Recipient)
			if rerr != nil {
				return nil, fmt.Errorf("recipient: %w", rerr)
			}
			return BuildSessionKeysClose(reg, SessionKeysCloseInput{
				AdminContext: ctx, SessionIndex: *req.SessionIndex,
				Recipient:     rcpt,
				ExpectedNonce: req.ExpectedNonce, OwnerSig: sig,
			})
		}
	}
	return nil, fmt.Errorf("unknown template/action: %s/%s", template, req.Action)
}
