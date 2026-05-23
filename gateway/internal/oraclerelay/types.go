package oraclerelay

import "time"

// Feed is a registered oracle feed row (`oracle_feeds`).
type Feed struct {
	ID              string
	Label           string
	Cluster         string
	PythFeedIDHex   string // 32-byte feed id, hex (no 0x)
	FeedCachePDA    string // base58 — derived [b"feed_cache", feed_id]
	PythAccount     string // base58 — the PriceUpdateV2 source account
	PythAccountKind string // 'price_feed' | 'price_update_v2'
	RefreshInterval int    // seconds
	Paused          bool
	LastPublishTime *time.Time
	LastTxSignature *string
	LastError       *string
}

// Metrics is the minimal Prometheus surface the relay emits (nil-safe: a nil
// Metrics disables emission). Implemented by *metrics.Metrics. Kept as an
// interface so this package needs no direct prometheus dependency.
type Metrics interface {
	RecordOracleFeedRefresh(result string)     // result: success|skipped|stale|error
	RecordOracleRefreshRejected(reason string) // F3 reason: deviation|lag
}

// FeedSeed is the JSON shape accepted in PYTH_ADAPTER_FEEDS for bootstrap.
type FeedSeed struct {
	Label           string `json:"label"`
	PythFeedIDHex   string `json:"feedIdHex"`
	PythAccount     string `json:"pythAccount"`
	PythAccountKind string `json:"pythAccountKind,omitempty"`
	RefreshInterval int    `json:"refreshIntervalSeconds,omitempty"`
}

// RefreshOutcome is the result of one refresh attempt, persisted to
// `oracle_feed_refresh_log`.
type RefreshOutcome struct {
	Result      string // 'success' | 'skipped' | 'stale' | 'error'
	TxSignature string
	PublishTime *time.Time
	PriceCanon  *int64
	ConfCanon   *int64
	Err         string // sanitised
}

const (
	resultSuccess = "success"
	resultSkipped = "skipped"
	resultStale   = "stale"
	resultError   = "error"

	kindPriceFeed     = "price_feed"
	kindPriceUpdateV2 = "price_update_v2"
)
