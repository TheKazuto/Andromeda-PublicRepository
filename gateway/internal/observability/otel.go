// Package observability wires OpenTelemetry tracing for the gateway.
// The implementation is opt-in: when OTEL_EXPORTER_OTLP_ENDPOINT is
// empty, Init returns a no-op shutdown and every trace operation is a
// silent no-op. When the env var points to a collector, spans are
// exported via OTLP/HTTP.
//
// We deliberately don't ship a metrics SDK here — Prometheus is the
// canonical metric backend for this gateway (see internal/metrics).
// Tracing complements metrics by letting operators correlate slow
// requests across gateway → ika-backend → Solana RPC.
package observability

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"strconv"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.26.0"
)

// ServiceName is the OTel resource attribute service.name. Override
// via OTEL_SERVICE_NAME if multiple gateway instances need
// distinguishing.
const ServiceName = "andromeda-gateway"

// Shutdown is the function returned by Init. Call before process exit
// to flush in-flight spans. Always non-nil — when tracing was disabled
// it returns a noop.
type Shutdown func(context.Context) error

// Init configures the global TracerProvider and Propagator.
//
// When OTEL_EXPORTER_OTLP_ENDPOINT is empty, returns a no-op shutdown
// and the global tracer remains the default noop TracerProvider, so
// any otelhttp.NewHandler / otelhttp.NewTransport wrapping is a free
// pass-through.
//
// When set, Init dials the collector with insecure HTTP by default
// (production deployments should put the collector behind a private
// network or set OTEL_EXPORTER_OTLP_HEADERS for auth).
func Init(ctx context.Context, version string, logger *slog.Logger) (Shutdown, error) {
	endpoint := os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT")
	if endpoint == "" {
		logger.Info("otel tracing disabled — OTEL_EXPORTER_OTLP_ENDPOINT not set")
		return noopShutdown, nil
	}

	// Build the resource (service.name, service.version, env).
	res, err := resource.New(ctx,
		resource.WithAttributes(
			semconv.ServiceName(envOr("OTEL_SERVICE_NAME", ServiceName)),
			semconv.ServiceVersion(version),
			attribute.String("deployment.environment", envOr("ENV", "development")),
		),
	)
	if err != nil {
		return noopShutdown, err
	}

	// OTLP/HTTP exporter — minimal options, honours every standard
	// OTEL_* env var (endpoint, headers, certificate, etc).
	exporter, err := otlptracehttp.New(ctx)
	if err != nil {
		return noopShutdown, err
	}

	tp := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exporter, sdktrace.WithBatchTimeout(5*time.Second)),
		sdktrace.WithResource(res),
		sdktrace.WithSampler(sdktrace.ParentBased(sdktrace.TraceIDRatioBased(samplingRatio()))),
	)
	otel.SetTracerProvider(tp)
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{},
		propagation.Baggage{},
	))

	logger.Info("otel tracing enabled",
		"endpoint", endpoint,
		"service", envOr("OTEL_SERVICE_NAME", ServiceName),
		"sampling", samplingRatio())

	return func(c context.Context) error {
		flushCtx, cancel := context.WithTimeout(c, 10*time.Second)
		defer cancel()
		return errors.Join(tp.ForceFlush(flushCtx), tp.Shutdown(flushCtx))
	}, nil
}

func noopShutdown(context.Context) error { return nil }

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

// samplingRatio reads OTEL_TRACES_SAMPLER_ARG or defaults to 0.1 (10%).
// Override per-environment: 1.0 in staging, 0.05 in production.
func samplingRatio() float64 {
	const def = 0.1
	v := os.Getenv("OTEL_TRACES_SAMPLER_ARG")
	if v == "" {
		return def
	}
	f, err := strconv.ParseFloat(v, 64)
	if err != nil || f <= 0 || f > 1 {
		return def
	}
	return f
}
