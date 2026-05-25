// Command server boots the intents-backend: a stateless private engine that
// turns LI.FI routes into signed, broadcast swaps over Ika dWallets. The
// gateway is its only caller (X-Internal-Key); all multi-tenant auth,
// rate-limit, quota and billing live there.
package main

import (
	"context"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/shinkalabs/andromeda-intents/internal/api"
	"github.com/shinkalabs/andromeda-intents/internal/chains"
	"github.com/shinkalabs/andromeda-intents/internal/config"
	"github.com/shinkalabs/andromeda-intents/internal/httpx"
	"github.com/shinkalabs/andromeda-intents/internal/lifi"
	"github.com/shinkalabs/andromeda-intents/internal/metrics"
	"github.com/shinkalabs/andromeda-intents/internal/swap"
)

func main() {
	cfg := config.Load()
	logger := newLogger(cfg)
	for _, warn := range cfg.Warnings {
		logger.Warn("config advisory", "msg", warn)
	}

	reg := prometheus.NewRegistry()
	m := metrics.New(reg)

	lifiClient := lifi.New(lifi.Options{
		BaseURL:    cfg.LifiBaseURL,
		APIKey:     cfg.LifiAPIKey,
		Integrator: cfg.LifiIntegrator,
		FeeBps:     cfg.LifiFeeBps,
		Timeout:    cfg.LifiTimeout,
		Metrics:    m,
		Logger:     logger,
	})

	solanaBroadcaster := chains.NewSolanaBroadcaster(m, logger)
	evmBroadcaster := chains.NewEVMBroadcaster(m, logger)
	swapSvc := swap.NewService(swap.Options{
		Lifi:              lifiClient,
		Solana:            solanaBroadcaster,
		EVM:               evmBroadcaster,
		SolanaRPCOverride: cfg.SolanaRPCURL,
		EVMOverrides:      cfg.EVMRPCOverrides(),
		Metrics:           m,
		Logger:            logger,
	})
	handlers := api.NewHandlers(lifiClient, swapSvc, m, logger, cfg.QuoteCacheTTL)

	readiness := func() (map[string]any, bool) {
		chainsLoaded := lifiClient.RPC().Loaded()
		breakerOpen := lifiClient.BreakerOpen()
		return map[string]any{
			"chainsCacheLoaded": chainsLoaded,
			"lifiBreakerOpen":   breakerOpen,
		}, chainsLoaded && !breakerOpen
	}

	router := httpx.NewRouter(httpx.RouterOptions{
		Logger:          logger,
		InternalAPIKey:  cfg.InternalAPIKey,
		Readiness:       readiness,
		MetricsRegistry: reg,
		Mount:           handlers.Mount,
	})

	rootCtx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Warm the /chains → RPC cache at boot and refresh it periodically. The
	// boot load is best-effort: readiness stays false until it succeeds.
	go refreshChainsLoop(rootCtx, lifiClient, logger)

	srv := &http.Server{
		Addr:              ":" + cfg.Port,
		Handler:           router,
		ReadHeaderTimeout: 10 * time.Second,
	}

	go func() {
		logger.Info("intents-backend listening", "port", cfg.Port, "env", cfg.Env)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Error("http server error", "err", err)
			os.Exit(1)
		}
	}()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh
	logger.Info("shutdown signal received")

	shutCtx, shutCancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer shutCancel()
	if err := srv.Shutdown(shutCtx); err != nil {
		logger.Error("graceful shutdown failed", "err", err)
	}
	cancel()
}

func refreshChainsLoop(ctx context.Context, c *lifi.Client, logger *slog.Logger) {
	refresh := func() {
		rctx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
		if err := c.RefreshChains(rctx); err != nil {
			logger.Warn("chains cache refresh failed", "err", err)
		}
	}
	refresh()
	ticker := time.NewTicker(10 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			refresh()
		}
	}
}

func newLogger(cfg *config.Config) *slog.Logger {
	level := slog.LevelInfo
	switch cfg.LogLevel {
	case "debug":
		level = slog.LevelDebug
	case "warn":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	}
	if cfg.IsProduction() {
		return slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: level}))
	}
	return slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: level}))
}
