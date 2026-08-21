// This file wires the resolved configuration into a running FIG daemon: the
// stream supervisor (producer), the worker pipeline (consumer), an offset
// store, the enabled backends, and an optional metrics/health HTTP server.
//
// It is the Go analog of fig/__main__.py, which constructed the queue, the
// StreamManagementThread, and the WorkerThreads and joined them. Here a single
// errgroup owns the goroutine lifetimes and a signal-cancellable context drives
// graceful shutdown.
package cli

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus/promhttp"
	"golang.org/x/sync/errgroup"

	// Blank-import each backend so its init() registers a Constructor with the
	// backend registry before backend.Build looks names up. Add a line here
	// when introducing a new backend package. The aws package is imported
	// non-blank because Run also calls its credential loader for the
	// credentials_store overlay.
	"github.com/crowdstrike/falcon-integration-gateway/internal/backend"
	awsbackend "github.com/crowdstrike/falcon-integration-gateway/internal/backend/aws"
	_ "github.com/crowdstrike/falcon-integration-gateway/internal/backend/azure"
	_ "github.com/crowdstrike/falcon-integration-gateway/internal/backend/gcp"
	_ "github.com/crowdstrike/falcon-integration-gateway/internal/backend/generic"
	_ "github.com/crowdstrike/falcon-integration-gateway/internal/backend/workspaceone"
	"github.com/crowdstrike/falcon-integration-gateway/internal/config"
	"github.com/crowdstrike/falcon-integration-gateway/internal/enrich"
	"github.com/crowdstrike/falcon-integration-gateway/internal/events"
	"github.com/crowdstrike/falcon-integration-gateway/internal/falcon/client"
	"github.com/crowdstrike/falcon-integration-gateway/internal/falcon/stream"
	"github.com/crowdstrike/falcon-integration-gateway/internal/logging"
	"github.com/crowdstrike/falcon-integration-gateway/internal/metrics"
	"github.com/crowdstrike/falcon-integration-gateway/internal/offset"
	"github.com/crowdstrike/falcon-integration-gateway/internal/pipeline"
	"github.com/crowdstrike/falcon-integration-gateway/internal/utils"
	"github.com/crowdstrike/falcon-integration-gateway/internal/version"
)

// defaultQueueDepthPerWorker is the per-worker multiplier for the bounded
// event channel when gateway.queue_depth is not set. A full channel blocks the
// stream reader, which is the pipeline's backpressure signal.
const defaultQueueDepthPerWorker = 64

// metricsShutdownTimeout bounds the graceful shutdown of the metrics/health
// HTTP server once the daemon's context is cancelled.
const metricsShutdownTimeout = 5 * time.Second

// Run builds every component from cfg and blocks until the daemon stops. It
// returns nil on a graceful shutdown (ctx cancelled, e.g. SIGINT/SIGTERM) and a
// non-nil error only on a fatal startup or runtime failure.
//
// Run installs its own signal-cancellable context derived from ctx: the first
// SIGINT/SIGTERM cancels it to trigger the graceful path — the supervisor stops
// and closes the event channel, the pipeline drains the buffered events and
// flushes the offset store, then Run returns. stop() then restores the runtime's
// default signal handling so a second signal hard-exits the process (130 for
// SIGINT, 143 for SIGTERM), the operator's escape hatch if a backend hangs.
func Run(ctx context.Context, cfg *config.Config) error {
	if cfg == nil {
		return errors.New("app: nil config")
	}

	ctx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()
	go func() {
		<-ctx.Done()
		stop()
	}()

	logger := logging.New(cfg.Logging.Level)
	logger.Info("starting Falcon Integration Gateway",
		"version", version.Version,
		"commit", version.Commit,
		"backends", cfg.Backends,
	)

	store, err := newOffsetStore(ctx, cfg)
	if err != nil {
		return err
	}

	backends, err := backend.Build(cfg.Backends, cfg, logger)
	if err != nil {
		return fmt.Errorf("app: build backends: %w", err)
	}

	if err := applyCredentialStore(ctx, cfg, logger); err != nil {
		return err
	}

	falconClient, err := client.NewClient(ctx, cfg, logger)
	if err != nil {
		return fmt.Errorf("app: build falcon client: %w", err)
	}

	enricher, err := enrich.New(enrich.Params{Config: cfg, Client: falconClient, Logger: logger})
	if err != nil {
		return fmt.Errorf("app: build enricher: %w", err)
	}

	supervisor, err := stream.NewSupervisor(stream.SupervisorConfig{
		Client:           falconClient,
		Store:            store,
		ApplicationID:    cfg.Falcon.ApplicationID,
		ReconnectRetries: cfg.Falcon.ReconnectRetryCount,
		ConfigOffset:     cfg.Events.Offset,
		StartFromNewest:  cfg.Events.StartFromNewest,
		EventTypes:       backend.UnionEventTypes(backends),
		Logger:           logger,
	})
	if err != nil {
		return fmt.Errorf("app: build stream supervisor: %w", err)
	}

	pipe, err := pipeline.New(pipeline.Params{
		Config:   cfg,
		Backends: backends,
		Enricher: enricher,
		Store:    store,
		Logger:   logger,
	})
	if err != nil {
		return fmt.Errorf("app: build pipeline: %w", err)
	}

	return run(ctx, runComponents{
		cfg:        cfg,
		logger:     logger,
		supervisor: supervisor,
		pipe:       pipe,
		backends:   backends,
	})
}

// runComponents bundles the constructed daemon components whose goroutine
// lifecycles run owns. It keeps the wiring in Run a linear, fail-fast sequence
// and the concurrency in run, in one place.
type runComponents struct {
	cfg        *config.Config
	logger     *slog.Logger
	supervisor *stream.Supervisor
	pipe       *pipeline.Pipeline
	backends   []backend.Backend
}

// run owns the goroutine lifecycles once every component is constructed. It is
// split from Run so the wiring above stays a linear, fail-fast sequence and the
// concurrency lives in one place.
func run(ctx context.Context, c runComponents) error {
	bufferSize := queueDepth(c.cfg)
	eventCh := make(chan *events.Event, bufferSize)
	c.logger.Info("event channel bounded", "queue_depth", bufferSize)

	// The pipeline drains on a context decoupled from the signal context so
	// that, on shutdown, buffered events are delivered to completion with a live
	// context rather than aborting mid-delivery (which would re-deliver them on
	// the next start). It terminates when the producer closes the channel; a
	// second signal is the operator's hard-exit path if a backend hangs here.
	drainCtx, drainCancel := context.WithCancel(context.Background())
	defer drainCancel()

	g, gctx := errgroup.WithContext(ctx)

	// Producer: the supervisor is the sole sender, so it closes the channel when
	// it returns. Graceful shutdown surfaces as a context error, which is not a
	// failure of the daemon.
	g.Go(func() error {
		defer close(eventCh)
		if err := c.supervisor.Run(gctx, eventCh); err != nil && !utils.IsCanceled(err) {
			return fmt.Errorf("app: stream supervisor: %w", err)
		}
		return nil
	})

	// Consumer: the pipeline owns closing the offset store when Run returns, so
	// this layer must not close it as well.
	g.Go(func() error {
		if err := c.pipe.Run(drainCtx, eventCh); err != nil {
			return fmt.Errorf("app: pipeline: %w", err)
		}
		return nil
	})

	if c.cfg.Gateway.MetricsAddr != "" {
		g.Go(func() error {
			return serveMetrics(gctx, c.cfg.Gateway.MetricsAddr, c.logger)
		})
	}

	err := g.Wait()

	closeBackends(c.logger, c.backends)

	if err != nil {
		return err
	}
	c.logger.Info("Falcon Integration Gateway stopped")
	return nil
}

// applyCredentialStore overlays Falcon API credentials from an external store
// onto cfg when credentials_store.store is set, so they take precedence over
// any file/env values before the Falcon client is built. An unset store is a
// no-op. Resolved credentials are secret and are never logged.
func applyCredentialStore(ctx context.Context, cfg *config.Config, logger *slog.Logger) error {
	store := cfg.Credentials.Store
	if store == "" {
		return nil
	}
	creds, err := awsbackend.LoadFalconCredentials(ctx, awsbackend.CredentialStoreConfig{
		Store:                 store,
		SSMRegion:             cfg.SSM.Region,
		SSMClientIDParam:      cfg.SSM.SSMClientID,
		SSMClientSecretParam:  cfg.SSM.SSMClientSecret,
		SecretsRegion:         cfg.SecretsManager.Region,
		SecretName:            cfg.SecretsManager.SecretsManagerSecretName,
		SecretClientIDKey:     cfg.SecretsManager.SecretsManagerClientIDKey,
		SecretClientSecretKey: cfg.SecretsManager.SecretsManagerClientSecretKey,
	})
	if err != nil {
		return fmt.Errorf("app: load credentials from %q store: %w", store, err)
	}
	cfg.Falcon.ClientID = creds.ClientID
	cfg.Falcon.ClientSecret = creds.ClientSecret
	logger.Info("loaded Falcon credentials from external store", "store", store)
	return nil
}

// newOffsetStore selects the offset store implementation from
// events.offset_store. "memory" is the ephemeral, test-oriented store; "ssm"
// persists the feed→offset map to an AWS Systems Manager parameter (for
// stateless containers with no durable disk); anything else (the default
// "file") is the durable JSON store at offset_store_path.
func newOffsetStore(ctx context.Context, cfg *config.Config) (offset.Store, error) {
	switch cfg.Events.OffsetStore {
	case "memory":
		return offset.NewMemory(), nil
	case "ssm":
		store, err := offset.NewSSM(ctx, cfg.Events.OffsetStoreRegion, cfg.Events.OffsetStorePath)
		if err != nil {
			return nil, fmt.Errorf("app: open offset store: %w", err)
		}
		return store, nil
	case "", "file":
		store, err := offset.NewFile(cfg.Events.OffsetStorePath)
		if err != nil {
			return nil, fmt.Errorf("app: open offset store: %w", err)
		}
		return store, nil
	default:
		return nil, fmt.Errorf("app: unknown offset_store %q (want file|memory|ssm)", cfg.Events.OffsetStore)
	}
}

// queueDepth resolves the bounded event channel capacity: the configured
// gateway.queue_depth when positive, else worker_threads * defaultQueueDepthPerWorker.
func queueDepth(cfg *config.Config) int {
	if cfg.Gateway.QueueDepth > 0 {
		return cfg.Gateway.QueueDepth
	}
	depth := cfg.Gateway.WorkerThreads * defaultQueueDepthPerWorker
	if depth < 1 {
		depth = defaultQueueDepthPerWorker
	}
	return depth
}

// closeBackends flushes any backend that implements backend.Closer. Errors are
// logged and swallowed: shutdown proceeds regardless, and there is nothing left
// to act on. A fresh, short-lived context is used because the daemon context is
// already cancelled by the time this runs.
func closeBackends(logger *slog.Logger, backends []backend.Backend) {
	ctx, cancel := context.WithTimeout(context.Background(), metricsShutdownTimeout)
	defer cancel()
	for _, b := range backends {
		closer, ok := b.(backend.Closer)
		if !ok {
			continue
		}
		if err := closer.Close(ctx); err != nil {
			logger.Error("backend close failed", "backend", b.Name(), "error", err)
		}
	}
}

// serveMetrics runs the /metrics, /healthz, and /readyz HTTP server until ctx is
// cancelled, then shuts it down gracefully. A ListenAndServe failure other than
// the expected http.ErrServerClosed is fatal (it cancels the errgroup).
func serveMetrics(ctx context.Context, addr string, logger *slog.Logger) error {
	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.HandlerFor(metrics.Registry(), promhttp.HandlerOpts{}))
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	mux.HandleFunc("/readyz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	srv := &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}

	serveErr := make(chan error, 1)
	go func() {
		logger.Info("metrics server listening", "addr", addr)
		serveErr <- srv.ListenAndServe()
	}()

	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), metricsShutdownTimeout)
		defer cancel()
		if err := srv.Shutdown(shutdownCtx); err != nil {
			return fmt.Errorf("app: metrics server shutdown: %w", err)
		}
		return nil
	case err := <-serveErr:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			return fmt.Errorf("app: metrics server: %w", err)
		}
		return nil
	}
}
