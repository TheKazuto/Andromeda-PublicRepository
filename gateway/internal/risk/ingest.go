package risk

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/shinkalabs/andromeda-gateway/internal/netsafety"
	"github.com/shinkalabs/andromeda-gateway/internal/store"
	"github.com/sony/gobreaker/v2"
)

// FeedSource represents a blocklist feed configuration.
type FeedSource struct {
	URL      string
	Source   string
	Category string
	License  string
}

// IngestorOptions configures the blocklist ingestor.
type IngestorOptions struct {
	Store        store.RiskBlocklistStore
	FeedRuns     store.RiskFeedRunStore
	Logger       *slog.Logger
	URLGuard     *netsafety.Validator
	Feeds        []FeedSource
	TickInterval time.Duration
	HTTPTimeout  time.Duration
	// VariationThresholdPercent: if content_hash differs and entry count changes
	// by more than this percentage, skip the update to guard against feed poisoning.
	VariationThresholdPercent float64
	// Metrics is a optional Prometheus metrics sink (nil-safe). If nil, metrics are not emitted.
	Metrics IngestorMetrics
}

// IngestorMetrics defines the minimal Prometheus surface the ingestor emits (nil-safe).
// Implemented by *metrics.Metrics or a mock in tests.
type IngestorMetrics interface {
	RecordRiskFeedDownloadFailure(source string)    // counter: risk_feed_download_failures_total
	RecordRiskFeedVariationSkip(source string)      // counter: risk_feed_variation_skips_total
	RecordRiskFeedEntriesUpserted(source string)    // counter: risk_feed_entries_upserted
	RecordRiskFeedLastSuccessSeconds(source string) // gauge: risk_feed_last_success_seconds (unix ts)
}

// Ingestor manages periodic blocklist feed ingestion with leader election.
type Ingestor struct {
	opts    IngestorOptions
	http    *http.Client
	breaker *gobreaker.CircuitBreaker[*http.Response]
}

// NewIngestor creates a new blocklist ingestor.
func NewIngestor(opts IngestorOptions) *Ingestor {
	if opts.Logger == nil {
		opts.Logger = slog.Default()
	}
	if opts.HTTPTimeout == 0 {
		opts.HTTPTimeout = 30 * time.Second
	}
	if opts.TickInterval == 0 {
		opts.TickInterval = 3600 * time.Second
	}
	if opts.VariationThresholdPercent == 0 {
		opts.VariationThresholdPercent = 30
	}
	if opts.URLGuard == nil {
		opts.URLGuard = netsafety.New(netsafety.ModeProduction)
	}

	breaker := gobreaker.NewCircuitBreaker[*http.Response](gobreaker.Settings{
		Name:        "risk-feed-download",
		MaxRequests: 3,
		Interval:    30 * time.Second,
		Timeout:     60 * time.Second,
		ReadyToTrip: func(c gobreaker.Counts) bool {
			failureRatio := float64(c.TotalFailures) / float64(c.Requests)
			return c.Requests >= 3 && failureRatio >= 0.6
		},
		OnStateChange: func(s string, from, to gobreaker.State) {
			if to == gobreaker.StateOpen {
				opts.Logger.Warn("risk feed circuit breaker opened", "name", s)
			}
		},
	})

	return &Ingestor{
		opts:    opts,
		breaker: breaker,
		http: &http.Client{
			Timeout: opts.HTTPTimeout,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}
}

// Start runs the ingestor loop until ctx is cancelled.
// It spawns a goroutine that ticks at TickInterval, claims due feeds
// with SELECT...FOR UPDATE SKIP LOCKED, and ingests them.
func (in *Ingestor) Start(ctx context.Context) {
	go in.run(ctx)
}

func (in *Ingestor) run(ctx context.Context) {
	ticker := time.NewTicker(in.opts.TickInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			in.tick(ctx)
		}
	}
}

func (in *Ingestor) tick(ctx context.Context) {
	now := time.Now().UTC()

	// Claim due feeds with 2x tick interval as lease duration
	// to allow time for download + processing without concurrent runs.
	leaseDuration := in.opts.TickInterval * 2
	leases, err := in.opts.FeedRuns.ClaimDueFeedRuns(ctx, now, leaseDuration, len(in.opts.Feeds))
	if err != nil {
		in.opts.Logger.Warn("claim due feed runs failed", "err", err)
		return
	}

	// Build a map of claimed feed URLs for quick lookup
	claimedFeeds := make(map[string]bool)
	for _, lease := range leases {
		claimedFeeds[lease.FeedURL] = true
	}

	// Ingest each claimed feed
	for _, lease := range leases {
		in.ingestFeed(ctx, lease.FeedURL, now)
	}
}

func (in *Ingestor) ingestFeed(ctx context.Context, feedURL string, now time.Time) {
	// Find the feed source configuration
	var feedCfg *FeedSource
	for i := range in.opts.Feeds {
		if in.opts.Feeds[i].URL == feedURL {
			feedCfg = &in.opts.Feeds[i]
			break
		}
	}
	if feedCfg == nil {
		in.opts.Logger.Warn("feed not configured", "feed_url", feedURL)
		return
	}

	// Download the feed
	content, contentHash, err := in.downloadFeed(ctx, feedURL)
	if err != nil {
		in.opts.Logger.Warn("download feed failed",
			"feed_url", feedURL,
			"source", feedCfg.Source,
			"err", err)
		// Record the error in the feed run state
		if in.opts.Metrics != nil {
			in.opts.Metrics.RecordRiskFeedDownloadFailure(feedCfg.Source)
		}
		state := &store.RiskFeedRunState{
			FeedURL:      feedURL,
			LastErrorAt:  &now,
			LastErrorMsg: err.Error(),
		}
		if errUpd := in.opts.FeedRuns.UpsertFeedRunState(ctx, state); errUpd != nil {
			in.opts.Logger.Error("update feed run error state failed",
				"feed_url", feedURL,
				"err", errUpd)
		}
		return
	}

	// Check for variation (feed poisoning guard)
	oldState, err := in.opts.FeedRuns.GetFeedRunState(ctx, feedURL)
	if err != nil {
		in.opts.Logger.Warn("get old feed run state failed",
			"feed_url", feedURL,
			"err", err)
		return
	}

	// Check for variation (feed poisoning guard) only if content changed
	if oldState != nil && oldState.ContentHash != "" && oldState.ContentHash != contentHash {
		// Parse new content to get actual entry count, not raw line count (M1)
		newEntries, err := in.parseFeed(feedCfg, content)
		if err != nil {
			in.opts.Logger.Warn("parse feed for variation check failed",
				"feed_url", feedURL,
				"source", feedCfg.Source,
				"err", err)
			return
		}
		newCount := len(newEntries)

		// M2: Protect against division by zero
		oldCount := oldState.EntriesUpserted
		if oldCount == 0 {
			oldCount = 1 // Avoid division by zero; treat first run as baseline
		}

		variation := float64(newCount) / float64(oldCount)
		if variation < 1 {
			variation = 1 / variation
		}
		variationPercent := (variation - 1) * 100

		if variationPercent > in.opts.VariationThresholdPercent {
			in.opts.Logger.Warn("feed variation exceeded threshold, skipping update",
				"feed_url", feedURL,
				"source", feedCfg.Source,
				"old_count", oldCount,
				"new_count", newCount,
				"variation_percent", variationPercent)
			// Record the variation in the feed run state
			if in.opts.Metrics != nil {
				in.opts.Metrics.RecordRiskFeedVariationSkip(feedCfg.Source)
			}
			state := &store.RiskFeedRunState{
				FeedURL:      feedURL,
				LastErrorAt:  &now,
				LastErrorMsg: fmt.Sprintf("variation exceeded threshold: %.1f%%", variationPercent),
			}
			if errUpd := in.opts.FeedRuns.UpsertFeedRunState(ctx, state); errUpd != nil {
				in.opts.Logger.Error("update feed run variation state failed",
					"feed_url", feedURL,
					"err", errUpd)
			}
			return
		}
	}

	// Parse and normalize addresses from the feed
	entries, err := in.parseFeed(feedCfg, content)
	if err != nil {
		in.opts.Logger.Warn("parse feed failed",
			"feed_url", feedURL,
			"source", feedCfg.Source,
			"err", err)
		state := &store.RiskFeedRunState{
			FeedURL:      feedURL,
			LastErrorAt:  &now,
			LastErrorMsg: err.Error(),
		}
		if errUpd := in.opts.FeedRuns.UpsertFeedRunState(ctx, state); errUpd != nil {
			in.opts.Logger.Error("update feed run parse error state failed",
				"feed_url", feedURL,
				"err", errUpd)
		}
		return
	}

	// Upsert all entries in the blocklist
	successCount := 0
	for _, addr := range entries {
		entry := &store.RiskBlocklistEntry{
			Destination: addr,
			Source:      feedCfg.Source,
			Category:    feedCfg.Category,
			License:     feedCfg.License,
			FetchedAt:   now,
			ContentHash: contentHash,
		}
		if err := in.opts.Store.UpsertBlocklistEntry(ctx, entry); err != nil {
			in.opts.Logger.Warn("upsert blocklist entry failed",
				"destination", addr,
				"feed_url", feedURL,
				"err", err)
			continue
		}
		successCount++
	}

	// Update the feed run state with success
	now = time.Now().UTC() // Refresh to avoid skew
	state := &store.RiskFeedRunState{
		FeedURL:         feedURL,
		LastSuccessAt:   &now,
		LastErrorAt:     nil,
		LastErrorMsg:    "",
		EntriesUpserted: successCount,
		ContentHash:     contentHash,
	}
	if err := in.opts.FeedRuns.UpsertFeedRunState(ctx, state); err != nil {
		in.opts.Logger.Error("update feed run success state failed",
			"feed_url", feedURL,
			"source", feedCfg.Source,
			"entries_upserted", successCount,
			"err", err)
		return
	}

	// Record metrics for successful ingest
	if in.opts.Metrics != nil {
		in.opts.Metrics.RecordRiskFeedEntriesUpserted(feedCfg.Source)
		in.opts.Metrics.RecordRiskFeedLastSuccessSeconds(feedCfg.Source)
	}

	in.opts.Logger.Info("feed ingested successfully",
		"feed_url", feedURL,
		"source", feedCfg.Source,
		"entries_upserted", successCount)
}

// downloadFeed fetches the content of a feed and returns the content and its SHA256 hash.
// Uses circuit breaker to protect against cascading failures.
func (in *Ingestor) downloadFeed(ctx context.Context, feedURL string) (string, string, error) {
	// Validate URL against SSRF
	if err := in.opts.URLGuard.ValidateRegister(ctx, feedURL); err != nil {
		return "", "", fmt.Errorf("SSRF validation failed: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, feedURL, nil)
	if err != nil {
		return "", "", fmt.Errorf("create request failed: %w", err)
	}

	// Execute through circuit breaker
	resp, err := in.breaker.Execute(func() (*http.Response, error) {
		return in.http.Do(req)
	})
	if err != nil {
		return "", "", fmt.Errorf("http request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", "", fmt.Errorf("http status %d", resp.StatusCode)
	}

	// Read with a size limit to prevent DoS (25 MB for MVP, conservative)
	const maxSize = 25 * 1024 * 1024
	limitedReader := io.LimitReader(resp.Body, maxSize)
	content, err := io.ReadAll(limitedReader)
	if err != nil {
		return "", "", fmt.Errorf("read body failed: %w", err)
	}

	// Validate content-type if present
	contentType := resp.Header.Get("Content-Type")
	if contentType != "" && !strings.Contains(contentType, "application/json") &&
		!strings.Contains(contentType, "text/plain") {
		return "", "", fmt.Errorf("unexpected content-type: %s", contentType)
	}

	// Compute SHA256 hash
	hash := sha256.Sum256(content)
	hashHex := hex.EncodeToString(hash[:])

	return string(content), hashHex, nil
}

// parseFeed parses a blocklist feed and returns normalized addresses.
// Supports both line-based format and JSON (MetaMask-style).
func (in *Ingestor) parseFeed(feedCfg *FeedSource, content string) ([]string, error) {
	content = strings.TrimSpace(content)

	// Try JSON format first (for MetaMask eth-phishing-detect)
	if strings.HasPrefix(content, "{") || strings.HasPrefix(content, "[") {
		return in.parseJSONFeed(feedCfg, content)
	}

	// Fall back to line-based format
	return in.parseLineFeed(content)
}

// parseJSONFeed extracts addresses from JSON format.
// For MetaMask eth-phishing-detect, extracts the "blacklist" array.
func (in *Ingestor) parseJSONFeed(feedCfg *FeedSource, content string) ([]string, error) {
	// MetaMask format: { "blacklist": [...], "whitelist": [...], ... }
	if feedCfg.Source == "metamask-phishing" {
		var cfg struct {
			Blacklist []string `json:"blacklist"`
		}
		if err := json.Unmarshal([]byte(content), &cfg); err != nil {
			return nil, fmt.Errorf("failed to parse MetaMask JSON: %w", err)
		}
		var addresses []string
		for _, addr := range cfg.Blacklist {
			normalized, err := store.NormalizeAddress(addr)
			if err == nil {
				addresses = append(addresses, normalized)
			}
		}
		return addresses, nil
	}

	// Generic JSON array format
	var addrs []string
	if err := json.Unmarshal([]byte(content), &addrs); err != nil {
		return nil, fmt.Errorf("failed to parse JSON array: %w", err)
	}
	var normalized []string
	for _, addr := range addrs {
		n, err := store.NormalizeAddress(addr)
		if err == nil {
			normalized = append(normalized, n)
		}
	}
	return normalized, nil
}

// parseLineFeed parses line-based format (one address per line).
func (in *Ingestor) parseLineFeed(content string) ([]string, error) {
	var addresses []string
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		addr, err := store.NormalizeAddress(line)
		if err != nil {
			continue
		}
		addresses = append(addresses, addr)
	}
	return addresses, nil
}
