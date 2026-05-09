package policies

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/gagliardetto/solana-go/rpc"
)

func TestSummarizeSimulation_Succeeded(t *testing.T) {
	policyID := "POLICYprogID11111111111111111111111111111111"
	ikaID := "IKAprogID111111111111111111111111111111111111"
	sim := &rpc.SimulateTransactionResponse{
		Value: &rpc.SimulateTransactionResult{
			Err: nil,
			Logs: []string{
				fmt.Sprintf("Program %s invoke [1]", policyID),
				fmt.Sprintf("Program %s invoke [2]", ikaID),
				fmt.Sprintf("Program %s consumed 233 of 197442 compute units", ikaID),
				fmt.Sprintf("Program %s consumed 1806 of 200000 compute units", policyID),
				fmt.Sprintf("Program %s success", policyID),
			},
		},
	}
	res := summarizeSimulation(sim, policyID, ikaID)
	if !res.WouldSucceed {
		t.Errorf("would_succeed = false, want true")
	}
	if res.Boundary != "succeeded" {
		t.Errorf("boundary = %q, want succeeded", res.Boundary)
	}
	if res.EstimatedCU != 1806 {
		t.Errorf("estimated_cu = %d, want 1806", res.EstimatedCU)
	}
}

func TestSummarizeSimulation_PolicyRejected(t *testing.T) {
	policyID := "POLICYprogID11111111111111111111111111111111"
	ikaID := "IKAprogID111111111111111111111111111111111111"
	errVal := json.RawMessage(`{"InstructionError":[0,{"Custom":6002}]}`)
	sim := &rpc.SimulateTransactionResponse{
		Value: &rpc.SimulateTransactionResult{
			Err: errVal,
			Logs: []string{
				fmt.Sprintf("Program %s invoke [1]", policyID),
				fmt.Sprintf("Program %s consumed 312 of 200000 compute units", policyID),
				fmt.Sprintf("Program %s failed: custom program error: 0x1772", policyID),
			},
		},
	}
	res := summarizeSimulation(sim, policyID, ikaID)
	if res.WouldSucceed {
		t.Errorf("would_succeed = true, want false")
	}
	if res.Boundary != "policy" {
		t.Errorf("boundary = %q, want policy", res.Boundary)
	}
	if res.EstimatedCU != 312 {
		t.Errorf("estimated_cu = %d, want 312", res.EstimatedCU)
	}
}

func TestSummarizeSimulation_IkaCpiBoundary(t *testing.T) {
	policyID := "POLICYprogID11111111111111111111111111111111"
	ikaID := "IKAprogID111111111111111111111111111111111111"
	errVal := json.RawMessage(`{"InstructionError":[0,"InvalidAccountOwner"]}`)
	sim := &rpc.SimulateTransactionResponse{
		Value: &rpc.SimulateTransactionResult{
			Err: errVal,
			Logs: []string{
				fmt.Sprintf("Program %s invoke [1]", policyID),
				fmt.Sprintf("Program %s invoke [2]", ikaID),
				fmt.Sprintf("Program %s failed: Invalid account owner", ikaID),
			},
		},
	}
	res := summarizeSimulation(sim, policyID, ikaID)
	if res.Boundary != "ika_cpi" {
		t.Errorf("boundary = %q, want ika_cpi", res.Boundary)
	}
}
