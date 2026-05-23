package store

import (
	"fmt"
	"strings"
)

// validateInput checks that a required field is non-empty.
func validateInput(value, fieldName string) error {
	if strings.TrimSpace(value) == "" {
		return fmt.Errorf("%s is required", fieldName)
	}
	return nil
}

// NormalizeAddress normalizes an address for storage and lookup.
// For hex addresses (matching 0x?[0-9a-fA-F]+): strips 0x/0X prefix, lowercases.
// For base58 addresses (Solana): trims whitespace only, case-sensitive.
// Returns error if the address is empty, only "0x", or (for hex) has invalid length/charset.
func NormalizeAddress(addr string) (string, error) {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		return "", fmt.Errorf("address cannot be empty")
	}
	if addr == "0x" || addr == "0X" {
		return "", fmt.Errorf("address cannot be 0x only")
	}

	// Check if it looks like a hex address (0x prefix or all hex chars)
	isHex := strings.HasPrefix(addr, "0x") || strings.HasPrefix(addr, "0X")
	if !isHex && len(addr) > 0 {
		// Could be base58 (Solana) or hex without prefix; try hex-like pattern first
		testAddr := addr
		if strings.HasPrefix(testAddr, "0x") || strings.HasPrefix(testAddr, "0X") {
			testAddr = testAddr[2:]
		}
		// If all characters are hex, treat as hex; otherwise treat as base58
		allHex := true
		for _, c := range testAddr {
			if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
				allHex = false
				break
			}
		}
		isHex = allHex && len(testAddr) > 0
	}

	if isHex {
		// Hex address: remove prefix, lowercase, validate length and charset
		if strings.HasPrefix(addr, "0x") || strings.HasPrefix(addr, "0X") {
			addr = addr[2:]
		}
		addr = strings.ToLower(addr)
		// Basic validation: hex string should have even length and valid chars
		if len(addr)%2 != 0 {
			return "", fmt.Errorf("hex address has odd length: %s", addr)
		}
		for _, c := range addr {
			if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
				return "", fmt.Errorf("hex address contains invalid character: %c", c)
			}
		}
		return addr, nil
	}

	// Base58 (Solana): trim whitespace but preserve case
	return addr, nil
}

// validateRiskLevel ensures the risk level is one of the valid values.
func validateRiskLevel(level RiskLevel) error {
	switch level {
	case RiskLevelNone, RiskLevelLow, RiskLevelMedium, RiskLevelHigh, RiskLevelCritical:
		return nil
	default:
		return fmt.Errorf("invalid risk level: %s", level)
	}
}

// validateFailMode ensures the fail mode is valid.
func validateFailMode(mode FailMode) error {
	switch mode {
	case FailModeOpen, FailModeClosed:
		return nil
	default:
		return fmt.Errorf("invalid fail mode: %s", mode)
	}
}
