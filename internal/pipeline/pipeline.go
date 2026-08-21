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
	"github.com/crowdstrike/falcon-integration-gateway/internal/utils"
)

// eppDetectionEventType is the event type gated by the cloud-detection filter
// (second dispatch gate). Port of fig/backends/__init__.py:39.
const eppDetectionEventType = events.EppDetectionSummaryEventType

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
// bounded retry: drop (ack and move on) or block (stall the watermark).
type deliveryPolicy int

const (
	// policyDrop discards a failed event: it logs dropped=true, bumps
	// fig_events_dropped_after_retry_total, and treats the event as handled so
	// the resume watermark advances. There is no dead-letter sink — the payload
	// is gone. This matches Python's move-on resilience while making the loss
	// visible. This is the default.
	policyDrop deliveryPolicy = iota
	// policyBlock does NOT mark a failed event done, so its offset never enters
	// the contiguous run and the resume watermark stalls indefinitely. It stops
	// the world on repeated failure: pending offsets accumulate (bounded by
	// events.pending_max) and delivery only resumes after the failing backend
	// recovers and the process is restarted. For strict / compliance deployments
	// that must never drop an event.
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

// Params holds the constructor inputs for New: the resolved config, the built
// backends, the enricher, an offset store, and a logger.
type Params struct {
	Config   *config.Config
	Backends []backend.Backend
	Enricher events.Enricher
	Store    offset.Store
	Logger   *slog.Logger
}

// New constructs a Pipeline from resolved config, the built backends, the
// enricher, an offset store, and a logger. It validates the worker count
// (defensively; config validation already constrains it to [1,127]) and
// resolves the delivery-failure policy (default drop).
func New(p Params) (*Pipeline, error) {
	if p.Config == nil {
		return nil, fmt.Errorf("pipeline: nil config")
	}
	if p.Enricher == nil {
		return nil, fmt.Errorf("pipeline: nil enricher")
	}
	if p.Store == nil {
		return nil, fmt.Errorf("pipeline: nil offset store")
	}
	if p.Logger == nil {
		return nil, fmt.Errorf("pipeline: nil logger")
	}

	workers := p.Config.Gateway.WorkerThreads
	if workers < 1 {
		return nil, fmt.Errorf("pipeline: worker_threads must be >= 1, got %d", workers)
	}

	excludeClouds := make(map[string]bool, len(p.Config.DetectionsExcludeClouds))
	for _, c := range p.Config.DetectionsExcludeClouds {
		excludeClouds[c] = true
	}

	policy, err := parseDeliveryPolicy(p.Config.Events.DeliveryFailure)
	if err != nil {
		return nil, err
	}

	return &Pipeline{
		workers:       workers,
		backends:      p.Backends,
		enricher:      p.Enricher,
		excludeClouds: excludeClouds,
		sevThreshold:  p.Config.Events.SeverityThreshold,
		olderThanDays: p.Config.Events.OlderThanDaysThreshold,
		policy:        policy,
		tracker: newCommitTracker(commitTrackerConfig{
			store:                p.Store,
			logger:               p.Logger,
			pendingWarnThreshold: p.Config.Events.PendingWarnThreshold,
			pendingMax:           p.Config.Events.PendingMax,
		}),
		store:        p.Store,
		logger:       p.Logger,
		retryBase:    retryBaseDelay,
		noOpInterval: noOpWarnInterval,
	}, nil
}

// parseDeliveryPolicy maps events.delivery_failure to a deliveryPolicy. An
// empty value defaults to drop (matching the config default). "dlq" is accepted
// as a deprecated alias for "drop": the old name implied a dead-letter sink that
// never existed, so it maps to the same discard behavior.
func parseDeliveryPolicy(raw string) (deliveryPolicy, error) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "", "drop", "discard", "dlq":
		return policyDrop, nil
	case "block":
		return policyBlock, nil
	default:
		return 0, fmt.Errorf("pipeline: invalid delivery_failure %q (want drop|discard|block)", raw)
	}
}

// Run spawns the worker pool and blocks until the input channel is closed and
// drained (the graceful-shutdown path: the producer stops on ctx cancel and
// closes in, workers finish the remaining events), then flushes the offset
// store. It returns the store-flush error, if any.
//
// A single dispatcher goroutine reads in and hands each event to the worker
// pool over an internal channel; the workers range over that channel rather
// than selecting on ctx.Done so that events already buffered in the bounded
// input channel are drained on shutdown (the whole chain terminates on channel
// close, not on ctx). A hard second-signal exit is the caller's concern.
func (p *Pipeline) Run(ctx context.Context, in <-chan *events.Event) error {
	p.logActiveFilters()

	// The no-op watcher runs alongside the workers and is torn down once they
	// drain, so it never outlives the pipeline.
	stop := make(chan struct{})
	var mon sync.WaitGroup
	mon.Go(func() {
		p.watchNoOp(ctx, stop)
	})

	// One dispatcher records each event as received — in strict stream order,
	// which the in-order commit watermark depends on — samples the queue depth
	// from this single goroutine, and forwards to the workers. Recording from N
	// workers instead would order the received offsets by scheduling luck and let
	// the watermark skip a lower offset that had not yet been recorded in flight.
	// The forward blocks (no ctx select) so buffered events are drained on
	// shutdown; the chain unwinds when the producer closes in.
	work := make(chan *events.Event)
	var disp sync.WaitGroup
	disp.Go(func() {
		defer close(work)
		for ev := range in {
			metrics.QueueDepth.Set(float64(len(in)))
			p.markReceived(ctx, ev)
			work <- ev
		}
	})

	var wg sync.WaitGroup
	for i := 0; i < p.workers; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			p.worker(ctx, id, work)
		}(i)
	}
	disp.Wait()
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

// worker consumes events from the dispatcher until the channel is closed. Each
// event is dispatched inside a panic-recovery boundary so one poison event
// never kills the worker — a faithful port of Python's blanket "except
// Exception" in WorkerThread.run.
func (p *Pipeline) worker(ctx context.Context, id int, work <-chan *events.Event) {
	logger := p.logger.With("component", "pipeline", "worker", id)
	for ev := range work {
		p.safeDispatch(ctx, logger, ev)
	}
}

// safeDispatch runs dispatch under a deferred recover so a panic in a backend
// or in event handling is logged and contained, never crashing the worker — a
// faithful port of Python's blanket "except Exception" in WorkerThread.run.
//
// A recovered panic is treated as a delivery failure subject to the configured
// policy: under drop (default) the event is discarded and its watermark
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
		metrics.EventsDroppedAfterRetry.Inc()
		logger.Error("dropping panicked event after recovery",
			"feed_id", ev.FeedID,
			"offset", ev.Offset(),
			"dropped", true,
		)
		p.markDone(ctx, logger, ev)
	}()
	p.dispatch(ctx, logger, ev)
}

// dispatch applies the three gates to select the backends for this event, then
// delivers to each. The event's offset is marked done (advancing the watermark)
// only after every dispatched-to backend succeeds or is dropped. An event
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
// gate 2 is routed through the delivery-failure policy (drop or block); a
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
			p.handleEnrichmentFailure(ctx, enrichFailureInput{logger: logger, event: ev, err: err})
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
		if err := p.deliver(ctx, deliverInput{logger: bl, backend: b, event: enriched}); err != nil {
			// A deliberate drop is handled but not delivered: record it under
			// its reason and leave the watermark to advance, without counting a
			// failure or dropping.
			var drop *backend.DropError
			if errors.As(err, &drop) {
				metrics.EventsDropped.WithLabelValues(b.Name(), drop.Reason).Inc()
				bl.Debug("backend dropped event", "reason", drop.Reason)
				continue
			}
			metrics.EventsFailed.Inc()
			if p.policy == policyBlock {
				bl.Error("backend delivery failed; blocking watermark", "error", err)
				handled = false
				continue
			}
			metrics.EventsDroppedAfterRetry.Inc()
			bl.Error("backend delivery failed; dropping event",
				"error", err,
				"dropped", true,
			)
			continue
		}
		metrics.EventsDelivered.Inc()
	}

	if handled {
		p.markDone(ctx, logger, ev)
	}
}

// enrichFailureInput carries the event whose gate-2 enrichment lookup failed,
// the per-event logger, and the terminal error, into handleEnrichmentFailure.
type enrichFailureInput struct {
	logger *slog.Logger
	event  *events.Event
	err    error
}

// handleEnrichmentFailure applies the delivery-failure policy to an event whose
// gate-2 enrichment lookup terminally failed. A context cancellation/deadline is
// treated as shutdown: the watermark is held (not advanced, not dropped)
// so the event is retried on the next run. Any other error bumps the enrichment
// failure counter and, under drop, discards the event (advancing the
// watermark); under block, holds the watermark.
func (p *Pipeline) handleEnrichmentFailure(ctx context.Context, in enrichFailureInput) {
	if utils.IsCanceled(in.err) {
		in.logger.Warn("enrichment aborted by context; holding watermark",
			"error", in.err,
			"feed_id", in.event.FeedID,
			"offset", in.event.Offset(),
			"event_type", in.event.EventType(),
		)
		return
	}

	metrics.EventsEnrichmentFailed.Inc()
	if p.policy == policyBlock {
		in.logger.Error("enrichment failed; blocking watermark",
			"error", in.err,
			"feed_id", in.event.FeedID,
			"offset", in.event.Offset(),
		)
		return
	}
	metrics.EventsDroppedAfterRetry.Inc()
	in.logger.Error("enrichment failed; dropping event",
		"error", in.err,
		"feed_id", in.event.FeedID,
		"offset", in.event.Offset(),
		"dropped", true,
	)
	p.markDone(ctx, in.logger, in.event)
}

// deliverInput carries the target backend, the enriched event, and the
// per-backend logger into Pipeline.deliver.
type deliverInput struct {
	logger  *slog.Logger
	backend backend.Backend
	event   *events.EnrichedEvent
}

// deliver calls Process with a bounded number of attempts, returning the last
// error if all attempts fail. Between attempts it waits a linearly growing
// delay with a per-event skew (de-synchronizing concurrent workers' retries),
// aborting early if the context is cancelled.
func (p *Pipeline) deliver(ctx context.Context, in deliverInput) error {
	var err error
	for attempt := 1; attempt <= maxDeliveryAttempts; attempt++ {
		if err = in.backend.Process(ctx, in.event); err == nil {
			return nil
		}
		// A deliberate drop is a terminal, successful-ish outcome: the caller
		// records it and advances the watermark, so it must not be retried.
		var drop *backend.DropError
		if errors.As(err, &drop) {
			return err
		}
		if ctx.Err() != nil {
			return fmt.Errorf("delivery aborted: %w", ctx.Err())
		}
		if attempt < maxDeliveryAttempts {
			delay := p.retryDelay(attempt, in.event.Offset())
			in.logger.Warn("backend delivery failed; retrying",
				"attempt", attempt, "retry_in", delay, "error", err)
			if !utils.Sleep(ctx, delay) {
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

// markReceived records that an event has been dequeued from the ordered stream
// and is now in flight. It must be called from the single dispatcher goroutine
// so offsets are recorded in stream order. A tracker error (a failed store load
// while seeding a feed) is logged and swallowed: the offset is simply not
// tracked as in-flight, costing at-least-once re-delivery on restart, never
// loss.
func (p *Pipeline) markReceived(ctx context.Context, ev *events.Event) {
	if err := p.tracker.Received(ctx, ev.FeedID, ev.Offset()); err != nil {
		p.logger.Error("failed to record received offset",
			"error", err,
			"feed_id", ev.FeedID,
			"offset", ev.Offset(),
		)
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
