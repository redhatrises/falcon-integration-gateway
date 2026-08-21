package stream

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/cenkalti/backoff/v5"
	"golang.org/x/sync/errgroup"

	"github.com/crowdstrike/falcon-integration-gateway/internal/events"
	"github.com/crowdstrike/falcon-integration-gateway/internal/falcon/client"
	"github.com/crowdstrike/falcon-integration-gateway/internal/metrics"
	"github.com/crowdstrike/falcon-integration-gateway/internal/utils"
)

// noStreamsRetryInterval is how long listStreams waits between attempts when
// Falcon reports no available streams. Ported from fig/falcon/stream.py:53.
const noStreamsRetryInterval = 10 * time.Second

// healthyRunThreshold is the minimum session duration that counts as "healthy":
// after a session that ran at least this long, the reconnect backoff is reset so
// the next reconnect is prompt. A session that ends faster than this leaves the
// backoff growing, so a stream that dies immediately (e.g. an instant EOF loop)
// backs off to reconnectMaxInterval rather than hot-looping.
const healthyRunThreshold = 1 * time.Minute

// Reconnect backoff bounds, used when the SupervisorConfig leaves them unset.
// The max matches the Python management thread's 60s restart-poll cadence
// (fig/falcon/stream.py:30); the initial interval keeps a prompt reconnect after
// a healthy session without hammering on repeated failure.
const (
	defaultReconnectInitialInterval = 1 * time.Second
	defaultReconnectMaxInterval     = 60 * time.Second
)

// controlPlane is the subset of the Falcon client the supervisor needs to
// manage streaming sessions: list the application's streams and refresh a
// session by partition. Declared here, at the consumer, so the concrete
// *client.Client is injectable and the session loop is unit-testable without a
// live platform. *client.Client satisfies it.
type controlPlane interface {
	ListStreams(ctx context.Context, appID string) ([]client.Stream, error)
	Refresh(ctx context.Context, appID string, partition int64) error
}

// SupervisorConfig holds the immutable inputs to a Supervisor. The app layer
// extracts these primitives from the resolved config so this package does not
// depend on internal/config and stays unit-testable without a full Config.
type SupervisorConfig struct {
	// Client is the Falcon control-plane client used to list and refresh streams.
	Client controlPlane
	// Store supplies the durable resume offset per feed on each (re)connect and
	// receives the one-time watermark-floor seed on a feed's first connection.
	Store offsetStore
	// ApplicationID is the Falcon streaming application id (falcon.application_id).
	ApplicationID string
	// ReconnectRetries bounds the NoStreamsError retry inside listStreams
	// (falcon.reconnect_retry_count).
	ReconnectRetries int
	// ConfigOffset is the operator-pinned start offset (events.offset); 0 unless set.
	ConfigOffset uint64
	// StartFromNewest selects whence=2 on the initial connection (events.start_from_newest).
	StartFromNewest bool
	// EventTypes is the server-side eventType filter (nil = no filter).
	EventTypes []string
	// IdleTimeout bounds the per-connection read-idle watchdog; 0 uses the default.
	IdleTimeout time.Duration
	// ReconnectInitialInterval and ReconnectMaxInterval bound the exponential
	// backoff that spaces session rebuilds; 0 uses the package defaults.
	ReconnectInitialInterval time.Duration
	ReconnectMaxInterval     time.Duration
	// HTTPClient is the long-poll HTTP client; nil builds the streaming default.
	HTTPClient *http.Client
	// Logger is the scoped logger; nil uses slog.Default.
	Logger *slog.Logger
}

// offsetStore is the subset of offset.Store the supervisor needs: the read side
// to resolve a feed's resume offset on each (re)connect, and the write side to
// seed the watermark floor on a feed's first connection. It is declared here, at
// the consumer, so the streaming client depends on the minimum surface.
type offsetStore interface {
	Load(ctx context.Context, feedID string) (uint64, error)
	Commit(ctx context.Context, feedID string, offset uint64) error
}

// Supervisor is the producer's top-level manager. It lists the Falcon event
// streams for the configured application, opens one long-poll connection per
// stream partition, keeps each session refreshed, and rebuilds the whole session
// whenever any connection closes.
//
// It is a re-architecture of StreamManagementThread + StreamRefreshThread in
// fig/falcon/stream.py: the shared stop_event becomes a per-session
// context.WithCancel, and the sys.exit(1) on failure (marked TODO in Python)
// becomes a capped-exponential-backoff retry that runs forever.
type Supervisor struct {
	cfg        SupervisorConfig
	httpClient *http.Client

	// mu guards seeded, which records the feeds whose watermark floor has already
	// been seeded so the seed fires only on a feed's first connection.
	mu     sync.Mutex
	seeded map[string]bool
}

// NewSupervisor validates the required dependencies and returns a Supervisor.
func NewSupervisor(cfg SupervisorConfig) (*Supervisor, error) {
	if cfg.Client == nil {
		return nil, errors.New("stream: nil falcon client")
	}
	if cfg.Store == nil {
		return nil, errors.New("stream: nil offset store")
	}
	if cfg.ApplicationID == "" {
		return nil, errors.New("stream: empty application id")
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	httpClient := cfg.HTTPClient
	if httpClient == nil {
		httpClient = defaultHTTPClient()
	}
	return &Supervisor{cfg: cfg, httpClient: httpClient, seeded: make(map[string]bool)}, nil
}

// Run lists the streams and runs a session until it closes, then rebuilds —
// forever, until ctx is cancelled. It returns ctx.Err() on graceful shutdown and
// never returns on transient failure (each rebuild is spaced by a capped
// exponential backoff), replacing the Python supervisor's sys.exit(1).
//
// out is the producer's side of the pipeline channel; the caller owns closing it
// after Run returns.
func (s *Supervisor) Run(ctx context.Context, out chan<- *events.Event) error {
	bo := s.newReconnectBackOff()
	firstSession := true

	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		if !firstSession {
			metrics.StreamReconnects.Inc()
		}
		firstSession = false

		start := time.Now()
		err := s.runOnce(ctx, out)
		if ctxErr := ctx.Err(); ctxErr != nil {
			return ctxErr
		}

		// Reset the backoff only after a session that stayed up long enough to be
		// healthy, so a stream that closes immediately does not reconnect in a
		// tight loop.
		if time.Since(start) >= healthyRunThreshold {
			bo.Reset()
		}

		if err != nil {
			s.cfg.Logger.Error("stream session ended with error; rebuilding", "error", err)
		} else {
			s.cfg.Logger.Info("stream session closed; rebuilding")
		}

		if !utils.Sleep(ctx, bo.NextBackOff()) {
			return ctx.Err()
		}
	}
}

// runOnce lists the current streams, then runs one reader plus one refresher per
// stream under a shared per-session context. It returns when the session ends:
// any reader closing (clean EOF or error) cancels the session, tearing down the
// sibling readers and refreshers; any refresher error does the same via the
// errgroup. A nil return is a clean close; a non-nil return is the first error.
func (s *Supervisor) runOnce(ctx context.Context, out chan<- *events.Event) error {
	streams, err := s.listStreams(ctx)
	if err != nil {
		return err
	}

	sessCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	g, gctx := errgroup.WithContext(sessCtx)
	for _, st := range streams {
		g.Go(func() error {
			// A reader ending (for any reason) tears down the whole session so a
			// fresh set of session tokens is obtained on rebuild — faithful to the
			// Python shared stop_event.
			defer cancel()
			return s.readStream(gctx, st, out)
		})
		g.Go(func() error {
			return s.refreshStream(gctx, st)
		})
	}
	return g.Wait()
}

// listStreams lists the application's event streams, retrying a bounded number
// of times when Falcon reports none available. Port of get_streams
// (fig/falcon/stream.py:44-54): NoStreamsError is retried up to ReconnectRetries
// times with a 10s pause; any other error returns immediately for the outer Run
// loop to back off and retry.
func (s *Supervisor) listStreams(ctx context.Context) ([]client.Stream, error) {
	retries := max(s.cfg.ReconnectRetries, 1)

	var lastErr error
	for attempt := range retries {
		if err := ctx.Err(); err != nil {
			return nil, err
		}

		streams, err := s.cfg.Client.ListStreams(ctx, s.cfg.ApplicationID)
		if err == nil {
			return streams, nil
		}

		var noStreams *client.NoStreamsError
		if !errors.As(err, &noStreams) {
			return nil, err
		}
		lastErr = err
		if attempt == retries-1 {
			break
		}
		s.cfg.Logger.Info("Falcon returned no available streams; retrying",
			"retry_in", noStreamsRetryInterval, "attempt", attempt+1, "max_attempts", retries)
		if !utils.Sleep(ctx, noStreamsRetryInterval) {
			return nil, ctx.Err()
		}
	}
	return nil, lastErr
}

// readStream resolves the resume offset for the stream's feed and runs a single
// long-poll connection, emitting events onto out. It returns when the connection
// closes: nil on a clean server close, a wrapped error otherwise. The outer Run
// loop rebuilds the session (re-resolving the offset from the store) on return.
func (s *Supervisor) readStream(ctx context.Context, st client.Stream, out chan<- *events.Event) error {
	feedID, err := st.FeedID()
	if err != nil {
		return fmt.Errorf("stream: resolve feed id: %w", err)
	}

	queueOffset, err := s.cfg.Store.Load(ctx, feedID)
	if err != nil {
		return fmt.Errorf("stream: load offset for feed %s: %w", feedID, err)
	}

	off, useWhence := resolveOffset(s.cfg.ConfigOffset, queueOffset, s.cfg.StartFromNewest)

	conn := newConnection(connectionConfig{
		url:         st.URL(),
		token:       st.Token(),
		feedID:      feedID,
		offset:      off,
		useWhence:   useWhence,
		eventTypes:  s.cfg.EventTypes,
		seedFloor:   s.seedFloorFunc(feedID),
		httpClient:  s.httpClient,
		idleTimeout: s.cfg.IdleTimeout,
		logger:      s.cfg.Logger.With("feed_id", feedID),
	})
	return conn.run(ctx, out)
}

// seedFloorFunc returns the connection's first-event callback, which seeds the
// pipeline's commit-watermark floor for feedID exactly once per supervisor
// lifetime.
//
// The watermark advances only through a contiguous run of completed offsets, so
// it must start at firstOffset-1. On a cold start — or a resume where the
// persisted offset has aged out of Falcon's retention — the first delivered
// event carries an offset far above the persisted 0, so committed+1 would never
// arrive and nothing would ever be committed. Seeding the floor lets that first
// event advance the watermark.
//
// The seed is guarded to fire only on a feed's first connection: on a normal
// reconnect the persisted offset is already correct, and re-seeding could regress
// the store behind events still draining from the previous connection.
func (s *Supervisor) seedFloorFunc(feedID string) func(context.Context, uint64) error {
	return func(ctx context.Context, floor uint64) error {
		s.mu.Lock()
		already := s.seeded[feedID]
		s.mu.Unlock()
		if already {
			return nil
		}

		if err := s.cfg.Store.Commit(ctx, feedID, floor); err != nil {
			return fmt.Errorf("stream: seed watermark floor for feed %s: %w", feedID, err)
		}

		s.mu.Lock()
		s.seeded[feedID] = true
		s.mu.Unlock()

		// A pinned start offset (events.offset) asks Falcon to resume at that point,
		// so the first delivered event should land at configOffset+1 and the seeded
		// floor should equal configOffset. A floor above it means Falcon could not
		// honor the pin (the offset aged out of retention and the stream began
		// higher): the events between the pin and the first delivered offset are
		// gone and the operator's chosen resume point has been superseded. Warn so
		// this is not silent.
		if s.cfg.ConfigOffset > 0 && floor > s.cfg.ConfigOffset {
			s.cfg.Logger.Warn("configured events.offset superseded by stream resume point; earlier events are no longer retained",
				"feed_id", feedID, "config_offset", s.cfg.ConfigOffset, "floor", floor)
		}

		s.cfg.Logger.Info("seeded resume watermark floor", "feed_id", feedID, "floor", floor)
		return nil
	}
}

// refreshStream re-ups the stream's session on a ticker until ctx is cancelled.
// Port of StreamRefreshThread (fig/falcon/stream.py:57-80): the ticker fires at
// 90% of the stream's refresh interval (the ticker's fire-after-interval
// semantics match the Python sleep-then-refresh loop). A refresh error ends the
// session so the outer loop rebuilds; ctx cancellation is a clean stop (nil).
func (s *Supervisor) refreshStream(ctx context.Context, st client.Stream) error {
	partition, err := st.Partition()
	if err != nil {
		return fmt.Errorf("stream: resolve partition: %w", err)
	}

	interval := time.Duration(st.RefreshInterval()) * time.Second * 9 / 10
	if interval <= 0 {
		// A non-positive refresh interval would panic time.NewTicker; treat it as
		// "no refresh needed" and simply wait for shutdown.
		<-ctx.Done()
		return nil
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			if err := s.cfg.Client.Refresh(ctx, s.cfg.ApplicationID, partition); err != nil {
				if ctx.Err() != nil {
					return nil
				}
				return fmt.Errorf("stream: refresh session (partition %d): %w", partition, err)
			}
			s.cfg.Logger.Debug("refreshed streaming session", "partition", partition)
		}
	}
}

// newReconnectBackOff builds the capped exponential backoff used to space
// session rebuilds. NextBackOff never signals stop, so the supervisor retries
// forever (capped at the max interval). Unset config bounds fall back to the
// package defaults.
func (s *Supervisor) newReconnectBackOff() *backoff.ExponentialBackOff {
	initial := s.cfg.ReconnectInitialInterval
	if initial <= 0 {
		initial = defaultReconnectInitialInterval
	}
	maxInterval := s.cfg.ReconnectMaxInterval
	if maxInterval <= 0 {
		maxInterval = defaultReconnectMaxInterval
	}
	bo := backoff.NewExponentialBackOff()
	bo.InitialInterval = initial
	bo.MaxInterval = maxInterval
	bo.Reset()
	return bo
}
