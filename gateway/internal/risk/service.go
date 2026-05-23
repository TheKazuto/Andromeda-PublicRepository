package risk

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
)

// Service is the main risk-scoring orchestrator. It holds the registry of sources,
// the config store, and the decision logic (Evaluate).
// Risk Layer is purely ADVISORY: it never blocks, only generates warnings.
// Always enabled when configured; the opt-in is per-request (raw_transaction presence).
type Service struct {
	sources *Registry   // pluggable risk sources
	store   ConfigStore // for per-dWallet and per-tenant defaults
	logger  *slog.Logger
}

// ConfigStore is the interface for reading risk policy configuration.
type ConfigStore interface {
	GetRiskConfig(ctx context.Context, dwalletAddress string) (*RiskConfig, error)
	GetRiskTenantDefaults(ctx context.Context, tenantID string) (*RiskTenantDefaults, error)
}

// RiskConfig is the per-dWallet risk policy (read from store).
type RiskConfig struct {
	DWalletAddress    string
	TenantID          string
	WarnLevel         string
	SimulationEnabled bool
}

// RiskTenantDefaults is the per-tenant default risk policy (fallback for dWallet config).
type RiskTenantDefaults struct {
	TenantID  string
	WarnLevel string
}

// NewService creates a risk scoring service.
func NewService(store ConfigStore, logger *slog.Logger) *Service {
	if logger == nil {
		logger = slog.Default()
	}
	return &Service{
		sources: NewRegistry(),
		store:   store,
		logger:  logger,
	}
}

// RegisterSource registers a pluggable risk source.
func (s *Service) RegisterSource(src Source) {
	s.sources.Register(src)
}

// Evaluate runs the risk assessment pipeline for a transaction.
// It queries all registered sources in parallel, aggregates their results,
// and incorporates optional simulation/calldata risk data if provided.
// Returns the final advisory score (warn or none) — never blocks.
func (s *Service) Evaluate(ctx context.Context, input *EvaluateInput) (*Score, error) {
	// Resolve the dWallet's risk policy (per-dWallet, with tenant default fallback).
	config, err := s.resolveConfig(ctx, input)
	if err != nil {
		// Best-effort: on config resolution error, still evaluate what we can.
		s.logger.Warn("config resolution error", "dwallet", redactAddress(input.DWalletAddress), "err", err)
		// Use safe default warn level.
		config = &RiskConfig{WarnLevel: "medium"}
	}

	// Aggregate all source scores in parallel.
	aggregated, sourceErrors := s.aggregateSources(ctx, input)

	// Incorporate optional simulation and calldata risk if provided.
	aggregated = s.incorporateAdditionalRisks(aggregated, input)

	// If a source failed, append advisory reason but don't block.
	if len(sourceErrors) > 0 {
		aggregated.Reasons = append(aggregated.Reasons,
			"risk evaluation encountered transient errors (some checks unavailable)")
	}

	// Decide action: only "warn" (when level >= warnLevel) or "none".
	action := DecideAction(aggregated.Level, config.WarnLevel)
	aggregated.Action = action

	// Log the result (sanitized for production).
	s.logEvaluation(input, aggregated, sourceErrors)

	return aggregated, nil
}

// resolveConfig retrieves the dWallet's risk config with tenant default fallback.
func (s *Service) resolveConfig(ctx context.Context, input *EvaluateInput) (*RiskConfig, error) {
	// Try per-dWallet config first.
	if input.DWalletAddress != "" {
		cfg, err := s.store.GetRiskConfig(ctx, input.DWalletAddress)
		if err == nil && cfg != nil {
			return cfg, nil
		}
		if err != nil {
			s.logger.Warn("failed to get dWallet config", "dwallet", redactAddress(input.DWalletAddress), "err", err)
		}
	}

	// Fall back to tenant default.
	if input.TenantID == "" {
		// No config found; use safe defaults.
		return &RiskConfig{
			WarnLevel: "medium",
		}, nil
	}

	defaults, err := s.store.GetRiskTenantDefaults(ctx, input.TenantID)
	if err != nil {
		s.logger.Warn("failed to get tenant defaults", "tenant", input.TenantID, "err", err)
		// Return safe defaults on error.
		return &RiskConfig{
			WarnLevel: "medium",
		}, nil
	}

	if defaults == nil {
		// No tenant config; use safe defaults.
		return &RiskConfig{
			WarnLevel: "medium",
		}, nil
	}

	return &RiskConfig{
		WarnLevel: defaults.WarnLevel,
	}, nil
}

// aggregateSources runs all registered sources in parallel and merges their scores.
// Returns the highest-severity level found, all reasons concatenated, and any errors.
func (s *Service) aggregateSources(ctx context.Context, input *EvaluateInput) (*Score, map[string]error) {
	sources := s.sources.All()
	if len(sources) == 0 {
		return &Score{Level: "none"}, nil
	}

	type result struct {
		score *Score
		err   error
	}

	results := make([]result, len(sources))
	var wg sync.WaitGroup
	wg.Add(len(sources))

	for i, src := range sources {
		go func(idx int, source Source) {
			defer wg.Done()
			score, err := source.Evaluate(ctx, input)
			results[idx] = result{score: score, err: err}
		}(i, src)
	}

	wg.Wait()

	// Merge results.
	maxLevel := 0
	allReasons := make([]string, 0)
	sourceErrors := make(map[string]error)

	for i, src := range sources {
		res := results[i]
		if res.err != nil {
			sourceErrors[src.Name()] = res.err
			continue
		}
		if res.score == nil {
			continue
		}
		levelInt := LevelToInt(res.score.Level)
		if levelInt > maxLevel {
			maxLevel = levelInt
		}
		allReasons = append(allReasons, res.score.Reasons...)
	}

	return &Score{
		Level:   IntToLevel(maxLevel),
		Reasons: allReasons,
	}, sourceErrors
}

// incorporateAdditionalRisks merges optional simulation and calldata risk into
// the aggregated source risk. Never blocks; just elevates the level and adds reasons.
func (s *Service) incorporateAdditionalRisks(aggregated *Score, input *EvaluateInput) *Score {
	// Incorporate CallDataRisk if present.
	if input.CalldataRisk != nil {
		calldataLevelInt := LevelToInt(input.CalldataRisk.Level)
		aggregatedLevelInt := LevelToInt(aggregated.Level)
		if calldataLevelInt > aggregatedLevelInt {
			aggregated.Level = input.CalldataRisk.Level
		}
		aggregated.Reasons = append(aggregated.Reasons, input.CalldataRisk.Reasons...)
	}

	// Incorporate simulation-based risk if present.
	if input.Simulation != nil {
		simReasons := s.deriveSimulationRisk(input.Simulation)
		if len(simReasons) > 0 {
			aggregated.Reasons = append(aggregated.Reasons, simReasons...)
		}
	}

	return aggregated
}

// deriveSimulationRisk extracts honest risk signals from simulation output.
// Returns reasons when detecting concerns (unlimited approvals, reverts, etc).
// On uncertainty, returns empty — never invents risk.
func (s *Service) deriveSimulationRisk(sim *SimulationResult) []string {
	var reasons []string

	// Will revert: critical user error.
	if sim.WillRevert {
		reasons = append(reasons, "transaction would revert on-chain")
	}

	// Unlimited approval: flagged as high-risk concern.
	for _, approval := range sim.Approvals {
		if approval.Amount == "unlimited" {
			reasons = append(reasons, "unlimited approval granted to spender (escalated risk)")
			break
		}
	}

	// Asset outflows: informational, not necessarily risky.
	for _, change := range sim.AssetChanges {
		if change.Change[0] == '-' {
			reasons = append(reasons, fmt.Sprintf("outflow of %s detected", change.Asset[:min(len(change.Asset), 8)]))
			break // one example is enough.
		}
	}

	return reasons
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// logEvaluation logs the risk evaluation result (sanitized).
func (s *Service) logEvaluation(input *EvaluateInput, score *Score, sourceErrors map[string]error) {
	logLevel := slog.LevelInfo
	if LevelToInt(score.Level) >= LevelToInt("high") {
		logLevel = slog.LevelWarn
	}

	attrs := []slog.Attr{
		slog.String("dwallet", redactAddress(input.DWalletAddress)),
		slog.String("level", score.Level),
		slog.String("action", score.Action),
		slog.Int("reason_count", len(score.Reasons)),
	}

	if len(sourceErrors) > 0 {
		errStrs := make([]string, 0, len(sourceErrors))
		for name, err := range sourceErrors {
			errStrs = append(errStrs, fmt.Sprintf("%s:%v", name, err))
		}
		attrs = append(attrs, slog.Any("source_errors", errStrs))
	}

	s.logger.LogAttrs(context.Background(), logLevel, "risk evaluation", attrs...)
}

// redactAddress returns a redacted version of an address for logging (first 6 + last 4 chars).
func redactAddress(addr string) string {
	if len(addr) <= 10 {
		return "***"
	}
	return addr[:6] + "..." + addr[len(addr)-4:]
}
