package oraclerelay

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/gagliardetto/solana-go"
	"github.com/gagliardetto/solana-go/rpc"
)

// pythReceiverID owns every PriceUpdateV2 account (mainnet + devnet).
var pythReceiverID = solana.MustPublicKeyFromBase58("rec5EKMGg6MxZYaMdyBfgwp4d5rB9T1VQH5pJv5LtFJ")

// Submitter is the subset of gasponsor.Signer the crank needs (the adapter
// authority key signs + pays for refresh / init txs).
type Submitter interface {
	SignAndSend(ctx context.Context, ixs []solana.Instruction) (solana.Signature, error)
	WaitForConfirmation(ctx context.Context, sig solana.Signature, c rpc.CommitmentType, timeout time.Duration) error
	PublicKey() solana.PublicKey
}

// Options configures the crank Service.
type Options struct {
	ProgramID solana.PublicKey
	Cluster   string
	Tick      time.Duration
	Seeds     []FeedSeed
	RPC       *rpc.Client
	Signer    Submitter
	Store     *Store
	HermesURL string // Pyth Hermes endpoint (catalog/discovery); defaults to DefaultHermesURL
	Logger    *slog.Logger
	Metrics   Metrics // optional (nil disables emission)
	// CrankEnabled turns the periodic refresh loop on. Default OFF (F7.5): the
	// continuous crank was retired in favour of refresh-on-sign + the managed
	// price-trigger monitor, which keep the FeedCache fresh at the exact signing
	// moment, so gas is only spent on a real signature instead of on a fixed
	// tick. When OFF the Service still runs the one-shot bootstrap (creates the
	// FeedCache PDAs) and the admin routes (register / force-refresh / pause)
	// still work; only the periodic loop is skipped. Re-enable for a feed read
	// outside a signing tx (rare).
	CrankEnabled bool

	// F3 off-chain guards (defensive; on-chain remains authoritative). 0 = off.
	//   - MaxDeviationBPS: skip a refresh whose new canonical price deviates
	//     more than this (basis points) from the last pushed value.
	//   - MaxPublishLagSeconds: skip a refresh whose publish_time is older than
	//     this budget (don't push a stale price).
	MaxDeviationBPS      int
	MaxPublishLagSeconds int
}

// Service runs the leader-elected oracle-feed bootstrap and, when enabled, the
// periodic refresh crank.
type Service struct {
	programID    solana.PublicKey
	configPDA    solana.PublicKey
	cluster      string
	tick         time.Duration
	seeds        []FeedSeed
	rpc          *rpc.Client
	signer       Submitter
	store        *Store
	hermesURL    string
	httpClient   *http.Client
	logger       *slog.Logger
	crankEnabled bool
	metrics      Metrics

	// F3 guards + the in-memory last-canonical-price baseline for the deviation
	// check (the crank is leader-elected, so a single instance owns this).
	maxDeviationBPS      int
	maxPublishLagSeconds int
	lastCanonMu          sync.Mutex
	lastCanon            map[string]int64 // feedID → last accepted canonical price
	rejectStreak         map[string]int   // feedID → consecutive deviation rejects
}

// maxDeviationRejectStreak caps how many consecutive ticks the deviation guard
// rejects a feed before accepting the new price as a real (sustained) move. This
// stops a legitimate large move from freezing a feed forever; a transient spike
// (1-2 ticks) is still dropped.
const maxDeviationRejectStreak = 3

const confirmTimeout = 30 * time.Second

// NewService validates options and returns a Service.
func NewService(o Options) (*Service, error) {
	if o.RPC == nil || o.Signer == nil || o.Store == nil {
		return nil, errors.New("oraclerelay: RPC, Signer and Store are required")
	}
	cfgPDA, _, err := AdapterConfigPDA(o.ProgramID)
	if err != nil {
		return nil, fmt.Errorf("derive adapter config pda: %w", err)
	}
	if o.Tick <= 0 {
		o.Tick = 30 * time.Second
	}
	if o.Cluster == "" {
		o.Cluster = "devnet"
	}
	if o.Logger == nil {
		o.Logger = slog.Default()
	}
	if o.HermesURL == "" {
		o.HermesURL = DefaultHermesURL
	}
	return &Service{
		programID:            o.ProgramID,
		configPDA:            cfgPDA,
		cluster:              o.Cluster,
		tick:                 o.Tick,
		seeds:                o.Seeds,
		rpc:                  o.RPC,
		signer:               o.Signer,
		store:                o.Store,
		hermesURL:            strings.TrimRight(o.HermesURL, "/"),
		httpClient:           &http.Client{Timeout: 15 * time.Second},
		logger:               o.Logger,
		crankEnabled:         o.CrankEnabled,
		metrics:              o.Metrics,
		maxDeviationBPS:      o.MaxDeviationBPS,
		maxPublishLagSeconds: o.MaxPublishLagSeconds,
		lastCanon:            make(map[string]int64),
		rejectStreak:         make(map[string]int),
	}, nil
}

// Start runs the one-shot bootstrap (ensures every configured feed has an
// on-chain FeedCache PDA + DB row), then — only when the periodic crank is
// enabled — runs the refresh loop until ctx is cancelled. Intended to be wrapped
// by a leader.Runner so exactly one replica drives it (otherwise replicas would
// duplicate the bootstrap inits and, if enabled, refresh txs + gas).
//
// F7.5: the continuous crank is retired by default. refresh-on-sign + the
// managed price-trigger monitor keep feeds fresh at signing time, so the
// bootstrap is all that normally runs here.
func (svc *Service) Start(ctx context.Context) {
	svc.seedFeeds(ctx)
	if !svc.crankEnabled {
		svc.logger.Info("oracle relay crank disabled (bootstrap-only) — refresh-on-sign + price-trigger monitor keep feeds fresh; set PYTH_ADAPTER_CRANK_ENABLED=true to re-enable periodic refresh")
		<-ctx.Done()
		return
	}
	svc.logger.Info("oracle relay periodic crank enabled", "tick", svc.tick)
	ticker := time.NewTicker(svc.tick)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			svc.tickAll(ctx)
		}
	}
}

// seedFeeds ensures each configured feed has an on-chain FeedCache PDA and a DB
// row. Failures are logged and skipped — a single bad feed must not stop the
// others (and the AdapterConfig must already exist, created at deploy time).
func (svc *Service) seedFeeds(ctx context.Context) {
	for _, seed := range svc.seeds {
		if _, err := svc.ensureFeed(ctx, seed); err != nil {
			svc.logger.Warn("oracle feed seed failed", "label", seed.Label, "err", err)
		}
	}
}

// ensureFeed validates the source, creates the on-chain FeedCache PDA if
// missing, and upserts the DB row. Returns the resulting feed. The
// `AdapterConfig` must already exist (created at deploy via init_adapter).
func (svc *Service) ensureFeed(ctx context.Context, seed FeedSeed) (*Feed, error) {
	feedIDHex := strings.ToLower(strings.TrimPrefix(strings.TrimSpace(seed.PythFeedIDHex), "0x"))
	feedID, err := decodeFeedID(feedIDHex)
	if err != nil {
		return nil, err
	}
	pythAccount, err := solana.PublicKeyFromBase58(seed.PythAccount)
	if err != nil {
		return nil, fmt.Errorf("invalid pythAccount: %w", err)
	}
	kind := seed.PythAccountKind
	if kind == "" {
		kind = kindPriceFeed
	}
	if kind != kindPriceFeed && kind != kindPriceUpdateV2 {
		return nil, fmt.Errorf("invalid pythAccountKind %q", kind)
	}

	// Validate the source for sponsored feeds: it must exist, be owned by the
	// Pyth receiver, be Full-verified, and carry the configured feed_id.
	if kind == kindPriceFeed {
		data, owner, rerr := svc.readAccount(ctx, pythAccount)
		if rerr != nil {
			return nil, fmt.Errorf("read pyth account: %w", rerr)
		}
		if !owner.Equals(pythReceiverID) {
			return nil, errors.New("pyth account not owned by the Pyth receiver program")
		}
		pu, perr := ParsePriceUpdateV2(data)
		if perr != nil {
			return nil, perr
		}
		if got := hex.EncodeToString(pu.FeedID[:]); got != feedIDHex {
			return nil, fmt.Errorf("feed_id mismatch: account=%s configured=%s", got, feedIDHex)
		}
	}

	cachePDA, bump, err := FeedCachePDA(svc.programID, feedID)
	if err != nil {
		return nil, fmt.Errorf("derive feed cache pda: %w", err)
	}

	// Create the cache on-chain if it does not exist yet.
	exists, err := svc.accountExists(ctx, cachePDA)
	if err != nil {
		return nil, fmt.Errorf("probe feed cache: %w", err)
	}
	if !exists {
		ix := InitFeedCacheIx(svc.programID, svc.configPDA, cachePDA, svc.signer.PublicKey(), feedID, bump)
		sig, serr := svc.signer.SignAndSend(ctx, []solana.Instruction{ix})
		if serr != nil {
			return nil, fmt.Errorf("init_feed_cache send: %w", serr)
		}
		if cerr := svc.signer.WaitForConfirmation(ctx, sig, rpc.CommitmentConfirmed, confirmTimeout); cerr != nil {
			return nil, fmt.Errorf("init_feed_cache confirm: %w", cerr)
		}
		svc.logger.Info("oracle feed cache created", "label", seed.Label, "pda", cachePDA.String(), "tx", sig.String())
	}

	interval := seed.RefreshInterval
	if interval <= 0 {
		interval = 30
	}
	id, err := svc.store.Upsert(ctx, Feed{
		Label:           seed.Label,
		Cluster:         svc.cluster,
		PythFeedIDHex:   feedIDHex,
		FeedCachePDA:    cachePDA.String(),
		PythAccount:     pythAccount.String(),
		PythAccountKind: kind,
		RefreshInterval: interval,
	})
	if err != nil {
		return nil, err
	}
	return svc.store.GetByID(ctx, id)
}

func (svc *Service) tickAll(ctx context.Context) {
	feeds, err := svc.store.ListActive(ctx, svc.cluster)
	if err != nil {
		svc.logger.Warn("list active oracle feeds failed", "err", err)
		return
	}
	for i := range feeds {
		if ctx.Err() != nil {
			return
		}
		svc.record(ctx, feeds[i].ID, svc.refreshFeed(ctx, feeds[i]))
	}
}

// refreshFeed runs one refresh attempt and returns its outcome WITHOUT
// persisting it (callers decide when to record). Used by both the crank tick
// and the admin force-refresh endpoint.
func (svc *Service) refreshFeed(ctx context.Context, f Feed) RefreshOutcome {
	if f.PythAccountKind == kindPriceUpdateV2 {
		// Pull/post_update (ephemeral VAA) is Fase 7. Surface it, never silently.
		return RefreshOutcome{Result: resultError,
			Err: "pull (post_update) mode not enabled in MVP — use a sponsored price_feed account"}
	}
	pythAccount, err := solana.PublicKeyFromBase58(f.PythAccount)
	if err != nil {
		return errOutcome(err)
	}
	data, owner, err := svc.readAccount(ctx, pythAccount)
	if err != nil {
		return errOutcome(err)
	}
	if !owner.Equals(pythReceiverID) {
		return errOutcome(errors.New("pyth account not owned by receiver program"))
	}
	pu, err := ParsePriceUpdateV2(data)
	if err != nil {
		return errOutcome(err)
	}
	if got := hex.EncodeToString(pu.FeedID[:]); got != f.PythFeedIDHex {
		return errOutcome(fmt.Errorf("feed_id mismatch: account=%s configured=%s", got, f.PythFeedIDHex))
	}

	// F3 lag guard: don't push a price older than the budget. The on-chain
	// adapter also enforces OracleStale, but this avoids a wasted tx and an
	// alertable signal. 0 = disabled.
	if svc.maxPublishLagSeconds > 0 {
		if age := time.Now().Unix() - pu.PublishTime; age > int64(svc.maxPublishLagSeconds) {
			svc.recordRejected("lag")
			svc.logger.Warn("oracle refresh rejected: publish_time too old",
				"feed", f.ID, "age_seconds", age, "budget_seconds", svc.maxPublishLagSeconds)
			return RefreshOutcome{Result: resultStale}
		}
	}

	// Freshness gate: skip when publish_time has not advanced (no wasted tx,
	// and avoids the on-chain PublishTimeRegression revert).
	if f.LastPublishTime != nil && pu.PublishTime <= f.LastPublishTime.Unix() {
		return RefreshOutcome{Result: resultSkipped}
	}

	// Canonical price mirror (same logic as on-chain). Used for the F3 deviation
	// guard below and for the success log. A mirror error (pathological
	// exponent) is non-fatal: skip the deviation check and let on-chain decide.
	newCanon, canErr := ToCanonicalI64(pu.Price, pu.Exponent)

	// F3 deviation guard: refuse an absurd jump vs the last accepted value.
	// 0 = disabled. Defensive — a too-tight band can freeze a legitimate move,
	// so it is opt-in, auto-recovers after a sustained move (streak cap), and
	// the on-chain price stays authoritative.
	if svc.maxDeviationBPS > 0 && canErr == nil {
		if last, ok := svc.lastCanonFor(f.ID); ok && deviatesBeyondBPS(last, newCanon, svc.maxDeviationBPS) {
			if streak := svc.bumpRejectStreak(f.ID); streak < maxDeviationRejectStreak {
				svc.recordRejected("deviation")
				svc.logger.Warn("oracle refresh rejected: price deviation out of band",
					"feed", f.ID, "last", last, "new", newCanon, "max_bps", svc.maxDeviationBPS, "streak", streak)
				return RefreshOutcome{Result: resultSkipped}
			}
			// Sustained out-of-band move — accept it as real and fall through.
			svc.logger.Warn("oracle deviation: accepting sustained out-of-band move after repeated rejects",
				"feed", f.ID, "last", last, "new", newCanon)
		}
	}
	// Price deemed valid (in-band, or accepted sustained move). Advance the
	// baseline now — BEFORE the tx — so a later send/confirm failure can't
	// freeze the feed against a stale baseline, and reset the reject streak.
	if canErr == nil {
		svc.setLastCanon(f.ID, newCanon)
		svc.resetRejectStreak(f.ID)
	}

	cachePDA, _, err := FeedCachePDA(svc.programID, pu.FeedID)
	if err != nil {
		return errOutcome(err)
	}
	ix := RefreshFeedIx(svc.programID, svc.configPDA, cachePDA, pythAccount)
	sig, err := svc.signer.SignAndSend(ctx, []solana.Instruction{ix})
	if err != nil {
		return errOutcome(fmt.Errorf("refresh_feed send: %w", err))
	}
	if err := svc.signer.WaitForConfirmation(ctx, sig, rpc.CommitmentConfirmed, confirmTimeout); err != nil {
		return errOutcome(fmt.Errorf("refresh_feed confirm: %w", err))
	}

	pubT := time.Unix(pu.PublishTime, 0).UTC()
	out := RefreshOutcome{
		Result:      resultSuccess,
		TxSignature: sig.String(),
		PublishTime: &pubT,
	}
	// The on-chain refresh already normalised with identical logic and landed,
	// so these mirrors should not error; if they ever do (Go/Rust drift on a
	// pathological exponent), record success without a misleading price rather
	// than logging a 0. The authoritative price is on-chain. newCanon was
	// computed above for the deviation guard.
	cc, cerr := ToCanonicalU64(pu.Conf, pu.Exponent)
	if canErr != nil || cerr != nil {
		svc.logger.Warn("canonical mirror diverged from on-chain (price omitted from log)",
			"feed", f.ID, "price_err", canErr, "conf_err", cerr)
		return out
	}
	ccI := int64(cc)
	out.PriceCanon = &newCanon
	out.ConfCanon = &ccI
	// F3 baseline already advanced before the send (see the deviation guard).
	return out
}

func (svc *Service) readAccount(ctx context.Context, pk solana.PublicKey) ([]byte, solana.PublicKey, error) {
	res, err := svc.rpc.GetAccountInfoWithOpts(ctx, pk, &rpc.GetAccountInfoOpts{
		Commitment: rpc.CommitmentConfirmed,
		Encoding:   solana.EncodingBase64,
	})
	if err != nil {
		return nil, solana.PublicKey{}, err
	}
	if res == nil || res.Value == nil {
		return nil, solana.PublicKey{}, errors.New("account not found")
	}
	return res.Value.Data.GetBinary(), res.Value.Owner, nil
}

func (svc *Service) accountExists(ctx context.Context, pk solana.PublicKey) (bool, error) {
	res, err := svc.rpc.GetAccountInfoWithOpts(ctx, pk, &rpc.GetAccountInfoOpts{
		Commitment: rpc.CommitmentConfirmed,
		Encoding:   solana.EncodingBase64,
	})
	if err != nil {
		// solana-go returns a sentinel for missing accounts.
		if errors.Is(err, rpc.ErrNotFound) {
			return false, nil
		}
		return false, err
	}
	return res != nil && res.Value != nil, nil
}

func (svc *Service) record(ctx context.Context, feedID string, o RefreshOutcome) {
	o.Err = sanitize(o.Err)
	if svc.metrics != nil && o.Result != "" {
		svc.metrics.RecordOracleFeedRefresh(o.Result)
	}
	if err := svc.store.RecordRefresh(ctx, feedID, o); err != nil {
		svc.logger.Warn("record oracle refresh failed", "err", err, "feed", feedID, "result", o.Result)
	}
}

func errOutcome(err error) RefreshOutcome {
	return RefreshOutcome{Result: resultError, Err: err.Error()}
}

// recordRejected emits the F3 rejection metric (nil-safe).
func (svc *Service) recordRejected(reason string) {
	if svc.metrics != nil {
		svc.metrics.RecordOracleRefreshRejected(reason)
	}
}

func (svc *Service) lastCanonFor(feedID string) (int64, bool) {
	svc.lastCanonMu.Lock()
	defer svc.lastCanonMu.Unlock()
	v, ok := svc.lastCanon[feedID]
	return v, ok
}

func (svc *Service) setLastCanon(feedID string, canon int64) {
	svc.lastCanonMu.Lock()
	svc.lastCanon[feedID] = canon
	svc.lastCanonMu.Unlock()
}

// bumpRejectStreak increments and returns the post-increment consecutive
// deviation-reject count for a feed.
func (svc *Service) bumpRejectStreak(feedID string) int {
	svc.lastCanonMu.Lock()
	defer svc.lastCanonMu.Unlock()
	svc.rejectStreak[feedID]++
	return svc.rejectStreak[feedID]
}

func (svc *Service) resetRejectStreak(feedID string) {
	svc.lastCanonMu.Lock()
	delete(svc.rejectStreak, feedID)
	svc.lastCanonMu.Unlock()
}

// deviatesBeyondBPS reports whether `now` differs from `last` by more than
// `maxBPS` basis points (1 bp = 0.01%). A zero/negative baseline can't be
// compared meaningfully → treated as no deviation. Uses big.Int so the
// cross-multiplication (`diff*10000 > maxBPS*last`) is exact and never overflows
// int64 on large canonical prices.
func deviatesBeyondBPS(last, now int64, maxBPS int) bool {
	if last <= 0 || maxBPS <= 0 {
		return false
	}
	diff := now - last
	if diff < 0 {
		diff = -diff
	}
	lhs := new(big.Int).Mul(big.NewInt(diff), big.NewInt(10000))
	rhs := new(big.Int).Mul(big.NewInt(int64(maxBPS)), big.NewInt(last))
	return lhs.Cmp(rhs) > 0
}

func decodeFeedID(hexStr string) ([32]byte, error) {
	var out [32]byte
	b, err := hex.DecodeString(strings.TrimPrefix(strings.ToLower(strings.TrimSpace(hexStr)), "0x"))
	if err != nil {
		return out, fmt.Errorf("invalid feedIdHex: %w", err)
	}
	if len(b) != 32 {
		return out, fmt.Errorf("feedIdHex must be 32 bytes, got %d", len(b))
	}
	copy(out[:], b)
	return out, nil
}

// sanitize trims internal noise and caps the length before persisting to the
// admin-only refresh log.
func sanitize(s string) string {
	s = strings.TrimSpace(s)
	if len(s) > 500 {
		s = s[:500]
	}
	return s
}
