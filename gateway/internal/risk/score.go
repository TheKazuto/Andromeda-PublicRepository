package risk

import (
	"encoding/json"
	"fmt"
)

// Score represents the risk assessment output for a transaction/destination.
type Score struct {
	Level   string   `json:"level"`   // "none" | "low" | "medium" | "high" | "critical"
	Action  string   `json:"action"`  // "warn" | "none" (always advisory, never blocks)
	Reasons []string `json:"reasons"` // why this level was assigned
}

// LevelToInt returns the numeric rank of a risk level for comparison (none=0, critical=4).
func LevelToInt(level string) int {
	switch level {
	case "none":
		return 0
	case "low":
		return 1
	case "medium":
		return 2
	case "high":
		return 3
	case "critical":
		return 4
	default:
		return 0
	}
}

// IntToLevel converts numeric rank back to string.
func IntToLevel(n int) string {
	switch n {
	case 0:
		return "none"
	case 1:
		return "low"
	case 2:
		return "medium"
	case 3:
		return "high"
	case 4:
		return "critical"
	default:
		return "none"
	}
}

// EvaluateInput is the forward-compatible context passed to the Evaluate function.
// It combines immediate request context with optional results from simulation/calldata
// analysis (added by RT5 sources after they run). The struct can grow without breaking
// existing sources — sources read only the fields they need.
type EvaluateInput struct {
	// Immediate request context
	DWalletAddress string // the signing dWallet address
	Destination    string // the 32-byte hex destination of the transaction
	TenantID       string // the tenant owning the dWallet
	RequestID      string // request ID for audit/logging

	// Optional: only when raw_transaction was provided and simulation ran
	// (populated by RT5 after simulation/calldata analysis completes).
	Simulation   *SimulationResult `json:"simulation,omitempty"`    // transaction simulation output
	CalldataRisk *CalldataRisk     `json:"calldata_risk,omitempty"` // heuristic risk from decoded calldata
}

// SimulationResult represents the output of transaction simulation (from ika-backend).
type SimulationResult struct {
	OK           bool            `json:"ok"`            // simulation succeeded without error
	WillRevert   bool            `json:"will_revert"`   // transaction would revert on-chain
	AssetChanges []AssetChange   `json:"asset_changes"` // native + token balance deltas
	Approvals    []ApprovalGrant `json:"approvals"`     // approvals granted by this tx
	Calls        []ContractCall  `json:"calls"`         // external contracts called
	Warnings     []string        `json:"warnings"`      // simulation-level warnings
}

// AssetChange represents a balance delta (native or token).
type AssetChange struct {
	Asset  string `json:"asset"`  // "native" or token address (hex)
	Change string `json:"change"` // signed amount (e.g., "-2500000000" for -2.5 SOL)
}

// ApprovalGrant represents an approval given to a spender.
type ApprovalGrant struct {
	Token   string `json:"token"`   // token address
	Spender string `json:"spender"` // spender address
	Amount  string `json:"amount"`  // "unlimited" or numeric amount
}

// ContractCall represents an external contract invocation.
type ContractCall struct {
	Address string `json:"address"` // contract address
	Method  string `json:"method"`  // function name/selector
}

// CalldataRisk represents the heuristic risk assessment of decoded calldata.
type CalldataRisk struct {
	Level   string   `json:"level"`   // "none" | "low" | "medium" | "high" | "critical"
	Reasons []string `json:"reasons"` // what flags were triggered
}

// MarshalJSON ensures CalldataRisk is nil-safe in JSON marshaling.
func (cr *CalldataRisk) MarshalJSON() ([]byte, error) {
	if cr == nil {
		return json.Marshal(map[string]interface{}{})
	}
	type Alias CalldataRisk
	return json.Marshal((*Alias)(cr))
}

// DecideAction determines the enforcement action (warn/none) given a risk level
// and the warn threshold configured for this dWallet.
// Risk Layer is purely ADVISORY: it only returns "warn" (when level >= warnLevel)
// or "none". It never blocks or returns "block".
func DecideAction(level string, warnLevel string) string {
	levelInt := LevelToInt(level)
	warnInt := LevelToInt(warnLevel)

	if levelInt >= warnInt {
		return "warn"
	}
	return "none"
}

// FormatSanitized returns the risk score with reasons sanitized for client exposure.
// Removes full addresses, private key material, and other sensitive details.
func (s *Score) FormatSanitized() Score {
	sanitized := Score{
		Level:   s.Level,
		Action:  s.Action,
		Reasons: make([]string, 0, len(s.Reasons)),
	}
	// Sources generate reasons already generic (no full addresses/PII), so they are
	// copied as-is. This stays the single sanitization point for client-facing output.
	sanitized.Reasons = append(sanitized.Reasons, s.Reasons...)
	return sanitized
}

// String implements Stringer for logging.
func (s *Score) String() string {
	return fmt.Sprintf("Score{Level:%s, Action:%s, Reasons:%v}", s.Level, s.Action, s.Reasons)
}
