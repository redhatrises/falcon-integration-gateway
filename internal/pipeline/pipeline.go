package pipeline

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"runtime/debug"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/crowdstrike/falcon-integration-gateway/internal/backend"
	"github.com/crowdstrike/falcon-integration-gateway/internal/config"
	"github.com/crowdstrike/falcon-integration-gateway/internal/events"
	"github.com/crowdstrike/falcon-integration-gateway/internal/metrics"
	"github.com/crowdstrike/falcon-integration-gateway/internal/offset"
)

// eppDetectionEventType is the event type gated by the cloud-detection filter
// (second dispatch gate). Port of fig/backends/__init__.py:39.
const eppDetectionEventType = "EppDetectionSummaryEvent"

// maxDeliveryAttempts is the total number of Process attempts per backend
// (initial try plus bounded retries) before applying the delivery-failure
// policy. Kept small.
const maxDeliveryAttempts = 3

// noOpWarnInterval bounds how often the pipeline checks whether the global
// severity/age filters dropped every event received in the window. A gateway
// that filters 100% of its traffic delivers nothing while its health endpoints
// stay green, so this makes an accidental no-op configuration visible.
const noOpWarnInterval = 15 * time.Minute

// Inter-attempt backoff bounds. A failed attempt waits retryBaseDelay times the
// attempt number, plus a small per-event skew, before retrying. The skew
// spreads concurrent workers' retries so they do not hammer a struggling
// backend in lockstep, and the cap bounds the worst-case wait.
const (
	retryBaseDelay = 250 * time.Millisecond
	retrySkewUnit  = 10 * time.Millisecond
	retrySkewMod   = 20
)

// deliveryPolicy selects what happens when a backend Process fails after the
// bounded retry: dead-letter (ack and move on) or block (stall the watermark).
type deliveryPolicy int

const (
	// policyDLQ dead-letters a failed event: it logs dead_letter=true, bumps
	// fig_events_dead_lettered_total, and treats the event as handled so the
	// resume watermark advances. Matches Python's move-on resilience while
	// adding visibility. This is the default.
	policyDLQ deliveryPolicy = iota
	// policyBlock does NOT mark a failed event done, so its offset never enters
	// the contiguous run and the resume watermark stalls indefinitely (strict /
	// compliance deployments).
	policyBlock
)

// Pipeline is the consumer side of FIG: a bounded worker pool that applies the
// three dispatch gates, submits to each passing backend, and advances a
// durable in-order resume watermark once delivery succeeds.
//
// It replaces fig/worker.py and the offset-advance logic in
// fig/queue/__init__.py.
type Pipeline struct {
	workers  int
	backends []backend.Backend
	// enricher resolves host details (cloud provider, platform, …) on demand for
	// the cloud-detection gate and, later, enrichment-consuming backends. Required
	// (non-nil): a gated detection event dereferences it.
	enricher events.Enricher
	// excludeClouds is the set form of cfg.DetectionsExcludeClouds, consulted by
	// the cloud-detection gate. An empty set disables the gate (and its
	// enrichment lookups) entirely.
	excludeClouds map[string]bool
	// sevThreshold drops events whose mapped severity is below it. Zero disables
	// the filter (MappedSeverity is always 1-5, never below 0).
	sevThreshold int
	// olderThanDays drops events created more than this many days ago. Zero
	// disables the age filter. The cutoff is recomputed per event from the
	// current time so it does not drift over a long-running process.
	olderThanDays int
	policy        deliveryPolicy
	tracker       *commitTracker
	store         offset.Store
	logger        *slog.Logger
	// retryBase is the per-attempt inter-retry delay multiplier. It defaults to
	// retryBaseDelay; tests set it to zero for deterministic, fast runs.
	retryBase time.Duration
	// noOpInterval is the no-op filter check cadence. It defaults to
	// noOpWarnInterval; tests set it lower to exercise the watcher quickly.
	noOpInterval time.Duration
	// winReceived and winFiltered count events received and filtered within the
	// current no-op check window; both are reset (swapped to zero) each tick.
	winReceived atomic.Uint64
	winFiltered atomic.Uint64
}

// New constructs a Pipeline from resolved config, the built backends, the
// enricher, an offset store, and a logger. It validates the worker count
// (defensively; config validation already constrains it to [1,127]) and
// resolves the delivery-failure policy (default DLQ).
func New(cfg *config.Config, backends []backend.Backend, enricher events.Enricher, store offset.Store, logger *slog.Logger) (*Pipeline, error) {
	if cfg == nil {
		return nil, fmt.Errorf("pipeline: nil config")
	}
	if enricher == nil {
		return nil, fmt.Errorf("pipeline: nil enricher")
	}
	if store == nil {
		return nil, fmt.Errorf("pipeline: nil offset store")
	}
	if logger == nil {
		return nil, fmt.Errorf("pipeline: nil logger")
	}

	workers := cfg.Gateway.WorkerThreads
	if workers < 1 {
		return nil, fmt.Errorf("pipeline: worker_threads must be >= 1, got %d", workers)
	}

	excludeClouds := make(map[string]bool, len(cfg.DetectionsExcludeClouds))
	for _, c := range cfg.DetectionsExcludeClouds {
		excludeClouds[c] = true
	}

	policy, err := parseDeliveryPolicy(cfg.Events.DeliveryFailure)
	if err != nil {
		return nil, err
	}

	return &Pipeline{
		workers:       workers,
		backends:      backends,
		enricher:      enricher,
		excludeClouds: excludeClouds,
		sevThreshold:  cfg.Events.SeverityThreshold,
		olderThanDays: cfg.Events.OlderThanDaysThreshold,
		policy:        policy,
		tracker:       newCommitTracker(store, logger),
		store:         store,
		logger:        logger,
		retryBase:     retryBaseDelay,
		noOpInterval:  noOpWarnInterval,
	}, nil
}

// parseDeliveryPolicy maps events.delivery_failure to a deliveryPolicy. An
// empty value defaults to DLQ (matching the config default).
func parseDeliveryPolicy(raw string) (deliveryPolicy, error) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "", "dlq":
		return policyDLQ, nil
	case "block":
		return policyBlock, nil
	default:
		return 0, fmt.Errorf("pipeline: invalid delivery_failure %q (want dlq|block)", raw)
	}
}

// Run spawns the worker pool and blocks until the input channel is closed and
// drained (the graceful-shutdown path: the producer stops on ctx cancel and
// closes in, workers finish the remaining events), then flushes the offset
// store. It returns the store-flush error, if any.
//
// The context is propagated into every backend Process call. Workers range
// over in rather than selecting on ctx.Done so that events already buffered in
// the bounded channel are drained on shutdown; a hard second-signal exit is the
// caller's concern.
func (p *Pipeline) Run(ctx context.Context, in <-chan *events.Event) error {
	p.logActiveFilters()

	// The no-op watcher runs alongside the workers and is torn down once they
	// drain, so it never outlives the pipeline.
	stop := make(chan struct{})
	var mon sync.WaitGroup
	mon.Go(func() {
		p.watchNoOp(ctx, stop)
	})

	var wg sync.WaitGroup
	for i := 0; i < p.workers; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			p.worker(ctx, id, in)
		}(i)
	}
	wg.Wait()

	close(stop)
	mon.Wait()

	// Flush any debounced offset writes on shutdown. Run owns flushing the
	// store on completion; the caller must not also Close it.
	if err := p.store.Close(ctx); err != nil {
		return fmt.Errorf("pipeline: flush offset store: %w", err)
	}
	return nil
}

// logActiveFilters records the global severity/age thresholds at startup when
// either is set. The filters silently drop events before any backend sees them,
// so surfacing the active thresholds once makes a subsequent "why are no events
// arriving" investigation answerable from the log.
func (p *Pipeline) logActiveFilters() {
	if p.sevThreshold <= 0 && p.olderThanDays <= 0 {
		return
	}
	p.logger.Info("global event filters active; events below these thresholds are dropped before delivery",
		"severity_threshold", p.sevThreshold,
		"older_than_days_threshold", p.olderThanDays,
	)
}

// watchNoOp periodically checks whether the global filters dropped every event
// received in the last window and warns if so, surfacing a gateway that is
// silently delivering nothing. It returns when the pipeline stops or the
// context is cancelled. When no global filter is configured there is nothing to
// warn about, so it returns immediately.
func (p *Pipeline) watchNoOp(ctx context.Context, stop <-chan struct{}) {
	if p.sevThreshold <= 0 && p.olderThanDays <= 0 {
		return
	}
	ticker := time.NewTicker(p.noOpInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-stop:
			return
		case <-ticker.C:
			received := p.winReceived.Swap(0)
			filtered := p.winFiltered.Swap(0)
			if shouldWarnNoOp(received, filtered) {
				p.logger.Warn("global filters dropped every event in the last window; gateway is delivering nothing",
					"received", received,
					"filtered", filtered,
					"severity_threshold", p.sevThreshold,
					"older_than_days_threshold", p.olderThanDays,
				)
			}
		}
	}
}

// shouldWarnNoOp reports whether a window that saw traffic filtered all of it.
// filtered can momentarily exceed received across a window boundary (received
// and filtered are incremented in sequence, so a concurrent dispatch may split
// across the swap), so the comparison is >= rather than ==.
func shouldWarnNoOp(received, filtered uint64) bool {
	return received > 0 && filtered >= received
}

// worker consumes events until in is closed. Each event is dispatched inside a
// panic-recovery boundary so one poison event never kills the worker — a
// faithful port of Python's blanket "except Exception" in WorkerThread.run.
func (p *Pipeline) worker(ctx context.Context, id int, in <-chan *events.Event) {
	logger := p.logger.With("component", "pipeline", "worker", id)
	for ev := range in {
		metrics.QueueDepth.Set(float64(len(in)))
		p.safeDispatch(ctx, logger, ev)
	}
}

// safeDispatch runs dispatch under a deferred recover so a panic in a backend
// or in event handling is logged and contained, never crashing the worker — a
// faithful port of Python's blanket "except Exception" in WorkerThread.run.
//
// A recovered panic is treated as a delivery failure subject to the configured
// policy: under DLQ (default) the event is dead-lettered and its watermark
// advances, so one poison event cannot wedge a feed's resume offset (and force
// unbounded duplicate re-delivery of every later event) forever; under block
// the watermark is held, matching a non-panicking block-policy failure.
func (p *Pipeline) safeDispatch(ctx context.Context, logger *slog.Logger, ev *events.Event) {
	defer func() {
		r := recover()
		if r == nil {
			return
		}
		metrics.EventsFailed.Inc()
		logger.Error("recovered from panic while processing event",
			"panic", r,
			"feed_id", ev.FeedID,
			"offset", ev.Offset(),
			"event_type", ev.EventType(),
			"stack", string(debug.Stack()),
		)
		if p.policy == policyBlock {
			logger.Error("panic under block policy; blocking watermark",
				"feed_id", ev.FeedID,
				"offset", ev.Offset(),
			)
			return
		}
		metrics.EventsDeadLettered.Inc()
		logger.Error("dead-lettering panicked event",
			"feed_id", ev.FeedID,
			"offset", ev.Offset(),
			"dead_letter", true,
		)
		p.markDone(ctx, logger, ev)
	}()
	p.dispatch(ctx, logger, ev)
}

// dispatch applies the three gates to select the backends for this event, then
// delivers to each. The event's offset is marked done (advancing the watermark)
// only after every dispatched-to backend succeeds or is dead-lettered. An event
// that passes zero backends is trivially handled.
//
// Three gates, in order (port of Backends.process, fig/backends/__init__.py):
//  1. event-type membership (RelevantEventTypes contains the type, or "*");
//  2. cloud-detection gate (EppDetectionSummaryEvent only) — drops events whose
//     enriched cloud provider is excluded;
//  3. IsRelevant.
//
// The event is wrapped once in an EnrichedEvent so host-detail lookups are
// memoized across the gates and every backend. A terminal enrichment failure at
// gate 2 is routed through the delivery-failure policy (dead-letter or block); a
// context cancellation holds the watermark for retry on the next run.
func (p *Pipeline) dispatch(ctx context.Context, logger *slog.Logger, ev *events.Event) {
	metrics.EventsReceived.Inc()
	p.winReceived.Add(1)

	// Global severity/age filter, applied before the per-backend gates. Port of
	// Event.irrelevant() (fig/falcon/eventss.py). Python dropped these events
	// before the queue so they never advanced the offset; here a filtered event
	// is marked done so the resume watermark advances past long spans of
	// sub-threshold or aged-out events rather than re-scanning them on restart.
	if p.isFilteredOut(ev) {
		metrics.EventsFiltered.Inc()
		p.winFiltered.Add(1)
		p.markDone(ctx, logger, ev)
		return
	}

	enriched := events.NewEnrichedEvent(ev, p.enricher)

	var dispatched []backend.Backend
	for _, b := range p.backends {
		if !eventTypeAccepted(b, ev) {
			continue
		}
		relevant, err := p.cloudDetectionRelevant(ctx, enriched)
		if err != nil {
			p.handleEnrichmentFailure(ctx, logger, ev, err)
			return
		}
		if !relevant {
			continue
		}
		if !b.IsRelevant(ctx, enriched) {
			continue
		}
		dispatched = append(dispatched, b)
	}

	if len(dispatched) == 0 {
		// No backend accepted the event: trivially handled, advance watermark.
		p.markDone(ctx, logger, ev)
		return
	}

	metrics.EventsDispatched.Inc()

	handled := true
	for _, b := range dispatched {
		bl := logger.With("backend", b.Name(), "feed_id", ev.FeedID, "offset", ev.Offset())
		if err := p.deliver(ctx, bl, b, enriched); err != nil {
			metrics.EventsFailed.Inc()
			if p.policy == policyBlock {
				bl.Error("backend delivery failed; blocking watermark", "error", err)
				handled = false
				continue
			}
			metrics.EventsDeadLettered.Inc()
			bl.Error("backend delivery failed; dead-lettering event",
				"error", err,
				"dead_letter", true,
			)
			continue
		}
		metrics.EventsDelivered.Inc()
	}

	if handled {
		p.markDone(ctx, logger, ev)
	}
}

// handleEnrichmentFailure applies the delivery-failure policy to an event whose
// gate-2 enrichment lookup terminally failed. A context cancellation/deadline is
// treated as shutdown: the watermark is held (not advanced, not dead-lettered)
// so the event is retried on the next run. Any other error bumps the enrichment
// failure counter and, under DLQ, dead-letters the event (advancing the
// watermark); under block, holds the watermark.
func (p *Pipeline) handleEnrichmentFailure(ctx context.Context, logger *slog.Logger, ev *events.Event, err error) {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		logger.Warn("enrichment aborted by context; holding watermark",
			"error", err,
			"feed_id", ev.FeedID,
			"offset", ev.Offset(),
			"event_type", ev.EventType(),
		)
		return
	}

	metrics.EventsEnrichmentFailed.Inc()
	if p.policy == policyBlock {
		logger.Error("enrichment failed; blocking watermark",
			"error", err,
			"feed_id", ev.FeedID,
			"offset", ev.Offset(),
		)
		return
	}
	metrics.EventsDeadLettered.Inc()
	logger.Error("enrichment failed; dead-lettering event",
		"error", err,
		"feed_id", ev.FeedID,
		"offset", ev.Offset(),
		"dead_letter", true,
	)
	p.markDone(ctx, logger, ev)
}

// deliver calls Process with a bounded number of attempts, returning the last
// error if all attempts fail. Between attempts it waits a linearly growing
// delay with a per-event skew (de-synchronizing concurrent workers' retries),
// aborting early if the context is cancelled.
func (p *Pipeline) deliver(ctx context.Context, logger *slog.Logger, b backend.Backend, ev *events.EnrichedEvent) error {
	var err error
	for attempt := 1; attempt <= maxDeliveryAttempts; attempt++ {
		if err = b.Process(ctx, ev); err == nil {
			return nil
		}
		if ctx.Err() != nil {
			return fmt.Errorf("delivery aborted: %w", ctx.Err())
		}
		if attempt < maxDeliveryAttempts {
			delay := p.retryDelay(attempt, ev.Offset())
			logger.Warn("backend delivery failed; retrying",
				"attempt", attempt, "retry_in", delay, "error", err)
			if !sleepCtx(ctx, delay) {
				return fmt.Errorf("delivery aborted: %w", ctx.Err())
			}
		}
	}
	return err
}

// retryDelay is the wait before the given attempt's retry: retryBase times the
// attempt number, plus a deterministic per-event skew derived from the offset
// so concurrent workers do not retry in lockstep against a struggling backend.
// A zero retryBase (tests) yields a zero delay.
func (p *Pipeline) retryDelay(attempt int, offset uint64) time.Duration {
	if p.retryBase <= 0 {
		return 0
	}
	skew := time.Duration(offset%retrySkewMod) * retrySkewUnit
	return time.Duration(attempt)*p.retryBase + skew
}

// sleepCtx waits for d or until ctx is cancelled. It returns true if the full
// duration elapsed (or d is non-positive) and false if ctx was cancelled first.
func sleepCtx(ctx context.Context, d time.Duration) bool {
	if d <= 0 {
		return ctx.Err() == nil
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

// markDone advances the in-order commit watermark for the event's feed. A
// commit/store error is logged and swallowed: the store is the source of truth
// on restart, so a lost commit costs at-least-once re-delivery of this event,
// never its loss. The next contiguous offset's Done persists a superseding
// watermark that covers this one.
func (p *Pipeline) markDone(ctx context.Context, logger *slog.Logger, ev *events.Event) {
	if err := p.tracker.Done(ctx, ev.FeedID, ev.Offset()); err != nil {
		logger.Error("failed to commit offset watermark",
			"error", err,
			"feed_id", ev.FeedID,
			"offset", ev.Offset(),
		)
	}
}

// isFilteredOut reports whether the global severity/age filter drops this
// event. The age cutoff is recomputed from the current time on each call
// (matching Python's cut_off_date) so a long-running process keeps aging events
// out correctly; a zero olderThanDays leaves the cutoff as the zero Time, which
// no real event predates, disabling the age check. A zero sevThreshold likewise
// disables the severity check.
func (p *Pipeline) isFilteredOut(ev *events.Event) bool {
	var cutoff time.Time
	if p.olderThanDays > 0 {
		cutoff = events.Cutoff(time.Now(), p.olderThanDays)
	}
	return ev.IsFilteredOut(p.sevThreshold, cutoff)
}

// cloudDetectionRelevant is the second dispatch gate. It applies only to
// EppDetectionSummaryEvent: the event is dropped when its cloud provider is in
// events.detections_exclude_clouds. A device that resolves to no provider (empty
// string) is dropped only when "unrecognized" is excluded, matching Python's
// treatment of unknown-cloud detections. Port of
// Backends.cloud_detection_is_relevant.
//
// The provider comes from Hosts enrichment, which is triggered lazily: this gate
// enriches only for detection events and only when the exclude set is non-empty,
// so a deployment with an empty detections_exclude_clouds issues zero enrichment
// lookups. A returned error is a terminal enrichment failure (the enricher has
// already exhausted its internal retries), surfaced to the caller to apply the
// delivery-failure policy; the boolean is meaningless when err is non-nil.
func (p *Pipeline) cloudDetectionRelevant(ctx context.Context, ev *events.EnrichedEvent) (bool, error) {
	if ev.EventType() != eppDetectionEventType {
		return true, nil
	}
	if len(p.excludeClouds) == 0 {
		return true, nil
	}

	provider, err := ev.CloudProvider(ctx)
	if err != nil {
		return false, err
	}
	if p.excludeClouds[provider] {
		return false, nil
	}
	if provider == "" && p.excludeClouds["unrecognized"] {
		return false, nil
	}
	return true, nil
}

// eventTypeAccepted is the first dispatch gate: the backend accepts the event's
// type either explicitly (RelevantEventTypes contains it) or via the "*"
// AllEventTypes sentinel. Port of Backends.event_type_is_accepted.
func eventTypeAccepted(b backend.Backend, ev *events.Event) bool {
	et := ev.EventType()
	for _, t := range b.RelevantEventTypes() {
		if t == "*" || t == et {
			return true
		}
	}
	return false
}
