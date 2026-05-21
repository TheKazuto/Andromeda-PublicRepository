package oraclerelay

import (
	"context"
	"fmt"

	"github.com/gagliardetto/solana-go"
	"github.com/gagliardetto/solana-go/rpc"
)

// Admin operations used by the HTTP routes (gateway/internal/oraclerelay/
// routes.go). They run on any replica (not only the leader): they are
// one-shot, idempotency-protected by the gateway middleware, and the on-chain
// program tolerates concurrent refreshes (publish_time regression is rejected).

// ListFeeds returns every feed registered for this relay's cluster.
func (svc *Service) ListFeeds(ctx context.Context) ([]Feed, error) {
	return svc.store.List(ctx, svc.cluster)
}

// GetFeed returns one feed by id.
func (svc *Service) GetFeed(ctx context.Context, id string) (*Feed, error) {
	return svc.store.GetByID(ctx, id)
}

// RegisterFeed validates the source, creates the FeedCache PDA if needed, and
// upserts the DB row. Returns the resulting feed.
func (svc *Service) RegisterFeed(ctx context.Context, seed FeedSeed) (*Feed, error) {
	return svc.ensureFeed(ctx, seed)
}

// ForceRefresh runs a refresh now and persists the outcome.
func (svc *Service) ForceRefresh(ctx context.Context, id string) (RefreshOutcome, error) {
	f, err := svc.store.GetByID(ctx, id)
	if err != nil {
		return RefreshOutcome{}, err
	}
	o := svc.refreshFeed(ctx, *f)
	svc.record(ctx, id, o)
	return o, nil
}

// PauseFeed engages the on-chain per-feed kill switch (which also force-stales
// the cache) and flips the DB flag so the crank stops touching it.
func (svc *Service) PauseFeed(ctx context.Context, id string) error {
	return svc.setPaused(ctx, id, true)
}

// ResumeFeed clears the on-chain pause flag and the DB flag.
func (svc *Service) ResumeFeed(ctx context.Context, id string) error {
	return svc.setPaused(ctx, id, false)
}

func (svc *Service) setPaused(ctx context.Context, id string, paused bool) error {
	f, err := svc.store.GetByID(ctx, id)
	if err != nil {
		return err
	}
	feedID, err := decodeFeedID(f.PythFeedIDHex)
	if err != nil {
		return err
	}
	cachePDA, _, err := FeedCachePDA(svc.programID, feedID)
	if err != nil {
		return fmt.Errorf("derive feed cache pda: %w", err)
	}
	ix := SetFeedPauseIx(svc.programID, svc.configPDA, cachePDA, svc.signer.PublicKey(), paused)
	sig, err := svc.signer.SignAndSend(ctx, []solana.Instruction{ix})
	if err != nil {
		return fmt.Errorf("set_feed_pause send: %w", err)
	}
	if err := svc.signer.WaitForConfirmation(ctx, sig, rpc.CommitmentConfirmed, confirmTimeout); err != nil {
		return fmt.Errorf("set_feed_pause confirm: %w", err)
	}
	return svc.store.SetPaused(ctx, id, paused)
}

// DeleteFeed removes the DB row. The on-chain FeedCache PDA is left intact
// (it can be re-adopted by re-registering the same feed_id).
func (svc *Service) DeleteFeed(ctx context.Context, id string) error {
	return svc.store.Delete(ctx, id)
}
