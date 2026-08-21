package pipeline

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"
	"testing"

	prommetrics "github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/crowdstrike/falcon-integration-gateway/internal/backend"
	"github.com/crowdstrike/falcon-integration-gateway/internal/common"
	"github.com/crowdstrike/falcon-integration-gateway/internal/config"
	"github.com/crowdstrike/falcon-integration-gateway/internal/events"
	"github.com/crowdstrike/falcon-integration-gateway/internal/metrics"
	"github.com/crowdstrike/falcon-integration-gateway/internal/offset"
	"github.com/crowdstrike/falcon-integration-gateway/internal/testutil"
)

// mustEvent builds a events.Event for offset/eventType (feed "f") via ParseLine
// so the real accessors are exercised.
func mustEvent(t *testing.T, off uint64, eventType string) *events.Event {
	t.Helper()
	return testutil.MustEvent(t, testutil.EventOptions{FeedID: "f", Offset: off, EventType: eventType})
}

// errBoom is a terminal (non-context) enrichment error used to exercise the
// enrichment-failure delivery policy.
var errBoom = errors.New("boom")

// noopEnricher resolves every lookup to an empty, successful result. It lets a
// pipeline be constructed for tests that never trigger enrichment (empty
// exclude set or non-detection events).
type noopEnricher struct{}

func (noopEnricher) HostDetails(_ context.Context, _ string) (*common.HostDetails, error) {
	return &common.HostDetails{}, nil
}

func (noopEnricher) MDMIdentifier(_ context.Context, _, _ string) (string, error) {
	return "", nil
}

func (noopEnricher) ArcConfig(_ context.Context, _, _ string) (*events.ArcConfig, error) {
	return nil, nil
}

// --- commit tracker -------------------------------------------------------

// received records a run of offsets as received via the tracker, in the
// ascending stream order the tracker requires (a single dispatcher goroutine
// provides this in production).
func received(t *testing.T, tr *commitTracker, feedID string, offs ...uint64) {
	t.Helper()
	for _, off := range offs {
		if err := tr.Received(context.Background(), feedID, off); err != nil {
			t.Fatalf("Received(%d): %v", off, err)
		}
	}
}

// done marks a run of offsets done via the tracker, in the given order.
func done(t *testing.T, tr *commitTracker, feedID string, offs ...uint64) {
	t.Helper()
	for _, off := range offs {
		if err := tr.Done(context.Background(), feedID, off); err != nil {
			t.Fatalf("Done(%d): %v", off, err)
		}
	}
}

func TestCommitTracker_OutOfOrderCompletionAdvancesToReceived(t *testing.T) {
	t.Parallel()
	store := testutil.NewRecordingStore()
	tr := newCommitTracker(commitTrackerConfig{store: store, logger: testutil.DiscardLogger()})
	const feed = "f1"

	// Offsets arrive in stream order (1..5) but complete out of order. Once all
	// are done the watermark reaches 5, and the committed sequence never
	// regresses.
	received(t, tr, feed, 1, 2, 3, 4, 5)
	done(t, tr, feed, 3, 1, 2, 5, 4)

	if got := store.LastCommitted(feed); got != 5 {
		t.Fatalf("committed = %d, want 5", got)
	}

	seq := store.Committed(feed)
	var prev uint64
	for _, c := range seq {
		if c < prev {
			t.Fatalf("commit sequence not monotonic: %v", seq)
		}
		prev = c
	}
}

func TestCommitTracker_SkipsNeverReceivedGaps(t *testing.T) {
	t.Parallel()
	store := testutil.NewRecordingStore()
	tr := newCommitTracker(commitTrackerConfig{store: store, logger: testutil.DiscardLogger()})
	const feed = "f1"

	// Offset 2 is never received: a server-side eventType filter dropped it from
	// this feed, so its offset never arrives. The watermark must advance across
	// the gap to 5 rather than stalling — the core of the ordered-gap-aware fix.
	received(t, tr, feed, 1, 3, 4, 5)
	done(t, tr, feed, 1, 3, 4, 5)

	if got := store.LastCommitted(feed); got != 5 {
		t.Fatalf("committed = %d, want 5 (offset 2 was a filter gap, skipped)", got)
	}
}

func TestCommitTracker_InFlightOffsetHoldsWatermark(t *testing.T) {
	t.Parallel()
	store := testutil.NewRecordingStore()
	tr := newCommitTracker(commitTrackerConfig{store: store, logger: testutil.DiscardLogger()})
	const feed = "f1"

	// All of 1..5 are received, but offset 2 is still in flight (received, not
	// done). The watermark can advance only to 1 — it must never pass a
	// received-but-unfinished offset, or that event would be lost on a crash.
	received(t, tr, feed, 1, 2, 3, 4, 5)
	done(t, tr, feed, 1, 3, 4, 5) // 2 withheld

	if got := store.LastCommitted(feed); got != 1 {
		t.Fatalf("committed = %d, want 1 (held by in-flight offset 2)", got)
	}

	// Completing 2 releases the watermark through the rest of the received run.
	done(t, tr, feed, 2)
	if got := store.LastCommitted(feed); got != 5 {
		t.Fatalf("committed = %d, want 5 after in-flight offset cleared", got)
	}
}

func TestCommitTracker_SeedsFromStoreAndIgnoresReplays(t *testing.T) {
	t.Parallel()
	store := testutil.NewRecordingStore()
	store.LoadBase["f1"] = 10
	tr := newCommitTracker(commitTrackerConfig{store: store, logger: testutil.DiscardLogger()})
	const feed = "f1"

	// Offsets at or below the loaded watermark are re-deliveries after a restart:
	// received but never tracked in flight, so they must not commit or move the
	// watermark backwards.
	received(t, tr, feed, 5, 9, 10)
	done(t, tr, feed, 5, 9, 10)
	if got := store.LastCommitted(feed); got != 0 {
		t.Fatalf("unexpected commit %d for replayed offsets", got)
	}

	// The next offset after the seed advances.
	received(t, tr, feed, 11)
	done(t, tr, feed, 11)
	if got := store.LastCommitted(feed); got != 11 {
		t.Fatalf("committed = %d, want 11", got)
	}
}

func TestCommitTracker_PerFeedIsolation(t *testing.T) {
	t.Parallel()
	store := testutil.NewRecordingStore()
	tr := newCommitTracker(commitTrackerConfig{store: store, logger: testutil.DiscardLogger()})

	received(t, tr, "a", 1, 2)
	received(t, tr, "b", 1)
	done(t, tr, "a", 1)
	done(t, tr, "b", 1)
	// b has received only offset 1 (committed 1); a advances to 2 independently.
	done(t, tr, "a", 2)

	if got := store.LastCommitted("a"); got != 2 {
		t.Fatalf("feed a committed = %d, want 2", got)
	}
	if got := store.LastCommitted("b"); got != 1 {
		t.Fatalf("feed b committed = %d, want 1", got)
	}
}

// TestCommitTracker_PendingCap verifies pendingMax is an observability bound: an
// in-flight set larger than the cap increments fig_pending_overflow_total, but
// the offsets are still tracked (never silently dropped) so no event is lost —
// the operator must restart to drain a stuck block-policy backlog.
func TestCommitTracker_PendingCap(t *testing.T) {
	t.Parallel()
	store := testutil.NewRecordingStore()
	const feed = "cap-feed"
	tr := newCommitTracker(commitTrackerConfig{
		store:      store,
		logger:     testutil.DiscardLogger(),
		pendingMax: 2,
	})

	before := prommetrics.ToFloat64(metrics.PendingOverflow.WithLabelValues(feed))

	// Offsets 1..4 are received but none complete, so all four stay in flight.
	// The set exceeds the cap of 2 as 3 and 4 are added -> two overflow events.
	received(t, tr, feed, 1, 2, 3, 4)
	if got := store.LastCommitted(feed); got != 0 {
		t.Fatalf("committed = %d, want 0 (nothing done yet)", got)
	}
	if got := prommetrics.ToFloat64(metrics.PendingOverflow.WithLabelValues(feed)) - before; got != 2 {
		t.Fatalf("overflow delta = %v, want 2 (offsets 3 and 4 exceeded the cap)", got)
	}

	// The offsets were tracked despite the cap: completing them advances the
	// watermark through the whole run to 4, proving nothing was dropped.
	done(t, tr, feed, 1, 2, 3, 4)
	if got := store.LastCommitted(feed); got != 4 {
		t.Fatalf("committed = %d, want 4 (cap is observability-only, no drop)", got)
	}
}

// TestCommitTracker_FreshStartAdvancesToFirstOffset covers the fresh-tenant
// start_from_newest case: the stream connects at whence=2 and the first event
// arrives at a high offset (e.g. 5001, not 1). The ordered-gap-aware watermark
// treats every lower offset as never-received and advances straight to the first
// received offset — with or without a seeded store — so there is no stall.
//
// The store seed still matters for a different window (a reconnect before the
// first event is committed falls back to the stored offset rather than
// whence=2), which the stream tests cover (TestConnection_SeedsFloorBeforeFirstEmit,
// TestSeedFloorFunc_SeedsOnceThenGuards); it is no longer needed to keep the
// tracker itself from stalling.
func TestCommitTracker_FreshStartAdvancesToFirstOffset(t *testing.T) {
	t.Parallel()

	const feed = "f1"
	const firstOffset uint64 = 5001

	tests := []struct {
		name     string
		loadBase uint64 // store.Load result; 0 models an unseeded fresh start
	}{
		{name: "unseeded fresh start", loadBase: 0},
		{name: "seam seeds firstOffset-1", loadBase: firstOffset - 1},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			store := testutil.NewRecordingStore()
			if tc.loadBase != 0 {
				store.LoadBase[feed] = tc.loadBase
			}
			tr := newCommitTracker(commitTrackerConfig{store: store, logger: testutil.DiscardLogger()})

			received(t, tr, feed, firstOffset)
			done(t, tr, feed, firstOffset)

			if got := store.LastCommitted(feed); got != firstOffset {
				t.Fatalf("committed = %d, want %d", got, firstOffset)
			}
		})
	}
}

// BenchmarkCommitTrackerDone measures the received-then-done path under maximal
// worker contention: all GOMAXPROCS goroutines hammer a single feed, each with a
// unique offset, so the mutex is never uncontended. It is the evidence for
// whether calling store.Commit while holding commitTracker.mu is a real
// bottleneck. The Memory store's Commit is the common case (a single map write;
// the durable stores debounce to that in steady state), so this isolates the
// lock cost rather than store I/O. If the per-op cost here is negligible the
// lock stays as-is; per-feed locks or committing outside the lock would only pay
// off if this showed real contention.
func BenchmarkCommitTrackerDone(b *testing.B) {
	const feed = "bench"
	tr := newCommitTracker(commitTrackerConfig{store: offset.NewMemory(), logger: testutil.DiscardLogger()})
	ctx := context.Background()

	var next atomic.Uint64
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			off := next.Add(1)
			if err := tr.Received(ctx, feed, off); err != nil {
				b.Fatalf("Received(%d): %v", off, err)
			}
			if err := tr.Done(ctx, feed, off); err != nil {
				b.Fatalf("Done(%d): %v", off, err)
			}
		}
	})
}

// --- gates ----------------------------------------------------------------

// fakeBackend is a controllable Backend for gate/dispatch tests.
type fakeBackend struct {
	name       string
	eventTypes []string
	relevant   bool
	failN      int // fail the first failN Process calls (per event); 0 = succeed

	mu        sync.Mutex
	processed []uint64
	attempts  map[uint64]int
}

func newFakeBackend(name string, eventTypes []string) *fakeBackend {
	return &fakeBackend{
		name:       name,
		eventTypes: eventTypes,
		relevant:   true,
		attempts:   map[uint64]int{},
	}
}

func (f *fakeBackend) Name() string                 { return f.name }
func (f *fakeBackend) RelevantEventTypes() []string { return f.eventTypes }
func (f *fakeBackend) IsRelevant(_ context.Context, _ *events.EnrichedEvent) bool {
	return f.relevant
}

func (f *fakeBackend) Process(_ context.Context, ev *events.EnrichedEvent) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.attempts[ev.Offset()]++
	if f.attempts[ev.Offset()] <= f.failN {
		return fmt.Errorf("fakeBackend %s: forced failure", f.name)
	}
	f.processed = append(f.processed, ev.Offset())
	return nil
}

func (f *fakeBackend) processedOffsets() []uint64 {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]uint64, len(f.processed))
	copy(out, f.processed)
	return out
}

func TestEventTypeAccepted(t *testing.T) {
	t.Parallel()
	ev := mustEvent(t, 1, "EppDetectionSummaryEvent")
	tests := []struct {
		name  string
		types []string
		want  bool
	}{
		{"explicit match", []string{"EppDetectionSummaryEvent"}, true},
		{"wildcard", backend.AllEventTypes, true},
		{"no match", []string{"AuthActivityAuditEvent"}, false},
		{"wildcard among others", []string{"Other", "*"}, true},
		{"empty", nil, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			b := newFakeBackend("b", tc.types)
			if got := eventTypeAccepted(b, ev); got != tc.want {
				t.Fatalf("eventTypeAccepted = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestCloudDetectionRelevant(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name          string
		excludeClouds map[string]bool
		eventType     string
		enricher      events.Enricher
		wantRelevant  bool
		wantErr       error
	}{
		{
			name:          "non-detection event is always relevant, no enrichment",
			excludeClouds: map[string]bool{"AWS": true},
			eventType:     "AuthActivityAuditEvent",
			enricher:      &testutil.FakeEnricher{HostErr: errBoom}, // must not be consulted
			wantRelevant:  true,
		},
		{
			name:          "detection with empty exclude set is relevant, no enrichment",
			excludeClouds: map[string]bool{},
			eventType:     eppDetectionEventType,
			enricher:      &testutil.FakeEnricher{HostErr: errBoom}, // must not be consulted
			wantRelevant:  true,
		},
		{
			name:          "detection on excluded provider is dropped",
			excludeClouds: map[string]bool{"AWS": true},
			eventType:     eppDetectionEventType,
			enricher:      &testutil.FakeEnricher{Host: &common.HostDetails{Known: true, CloudProvider: "AWS"}},
			wantRelevant:  false,
		},
		{
			name:          "detection on non-excluded provider passes",
			excludeClouds: map[string]bool{"AWS": true},
			eventType:     eppDetectionEventType,
			enricher:      &testutil.FakeEnricher{Host: &common.HostDetails{Known: true, CloudProvider: "Azure"}},
			wantRelevant:  true,
		},
		{
			name:          "unknown device with unrecognized excluded is dropped",
			excludeClouds: map[string]bool{"unrecognized": true},
			eventType:     eppDetectionEventType,
			enricher:      &testutil.FakeEnricher{Host: &common.HostDetails{}},
			wantRelevant:  false,
		},
		{
			name:          "unknown device without unrecognized excluded passes",
			excludeClouds: map[string]bool{"AWS": true},
			eventType:     eppDetectionEventType,
			enricher:      &testutil.FakeEnricher{Host: &common.HostDetails{}},
			wantRelevant:  true,
		},
		{
			name:          "terminal enrichment error surfaces",
			excludeClouds: map[string]bool{"AWS": true},
			eventType:     eppDetectionEventType,
			enricher:      &testutil.FakeEnricher{HostErr: errBoom},
			wantRelevant:  false,
			wantErr:       errBoom,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			p := &Pipeline{excludeClouds: tc.excludeClouds}
			enriched := events.NewEnrichedEvent(mustEvent(t, 1, tc.eventType), tc.enricher)
			got, err := p.cloudDetectionRelevant(context.Background(), enriched)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("err = %v, want %v", err, tc.wantErr)
			}
			if got != tc.wantRelevant {
				t.Fatalf("relevant = %v, want %v", got, tc.wantRelevant)
			}
		})
	}
}

// --- pipeline dispatch (Run) ---------------------------------------------

func newTestPipeline(t *testing.T, workers int, policy string, backends []backend.Backend, store offset.Store) *Pipeline {
	t.Helper()
	cfg := &config.Config{}
	cfg.Gateway.WorkerThreads = workers
	cfg.Events.DeliveryFailure = policy
	p, err := New(Params{Config: cfg, Backends: backends, Enricher: noopEnricher{}, Store: store, Logger: testutil.DiscardLogger()})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	p.retryBase = 0 // deterministic, no real sleeps between retries in tests
	return p
}

func feed(t *testing.T, evs ...*events.Event) <-chan *events.Event {
	t.Helper()
	ch := make(chan *events.Event, len(evs))
	for _, ev := range evs {
		ch <- ev
	}
	close(ch)
	return ch
}

func TestPipeline_DispatchAllSucceed(t *testing.T) {
	t.Parallel()
	b := newFakeBackend("GENERIC", backend.AllEventTypes)
	store := testutil.NewRecordingStore()
	p := newTestPipeline(t, 4, "dlq", []backend.Backend{b}, store)

	in := feed(t,
		mustEvent(t, 1, "T"),
		mustEvent(t, 2, "T"),
		mustEvent(t, 3, "T"),
	)
	if err := p.Run(context.Background(), in); err != nil {
		t.Fatalf("Run: %v", err)
	}

	if got := store.LastCommitted("f"); got != 3 {
		t.Fatalf("committed = %d, want 3", got)
	}
	if len(b.processedOffsets()) != 3 {
		t.Fatalf("processed %d events, want 3", len(b.processedOffsets()))
	}
	if !store.Closed() {
		t.Fatal("store not closed on Run completion")
	}
}

func TestPipeline_EventPassingNoBackendIsHandled(t *testing.T) {
	t.Parallel()
	// Backend only wants a type the events don't have -> zero dispatched, but
	// the watermark must still advance (trivially handled).
	b := newFakeBackend("B", []string{"OtherType"})
	store := testutil.NewRecordingStore()
	p := newTestPipeline(t, 1, "dlq", []backend.Backend{b}, store)

	in := feed(t, mustEvent(t, 1, "T"), mustEvent(t, 2, "T"))
	if err := p.Run(context.Background(), in); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if got := store.LastCommitted("f"); got != 2 {
		t.Fatalf("committed = %d, want 2", got)
	}
	if len(b.processedOffsets()) != 0 {
		t.Fatalf("backend processed %d events, want 0", len(b.processedOffsets()))
	}
}

func TestPipeline_DLQAdvancesWatermarkOnFailure(t *testing.T) {
	t.Parallel()
	b := newFakeBackend("B", backend.AllEventTypes)
	b.failN = maxDeliveryAttempts + 1 // always fail
	store := testutil.NewRecordingStore()
	p := newTestPipeline(t, 1, "dlq", []backend.Backend{b}, store)

	in := feed(t, mustEvent(t, 1, "T"), mustEvent(t, 2, "T"))
	if err := p.Run(context.Background(), in); err != nil {
		t.Fatalf("Run: %v", err)
	}
	// DLQ treats failures as handled -> watermark advances to 2.
	if got := store.LastCommitted("f"); got != 2 {
		t.Fatalf("committed = %d, want 2 (dlq acks failures)", got)
	}
}

func TestPipeline_BlockStallsWatermarkOnFailure(t *testing.T) {
	t.Parallel()
	// Offset 1 always fails; offset 2 succeeds. Under block policy, 1 is never
	// done, so the watermark must never advance (stays 0) even though 2
	// completes out of order.
	b := &conditionalBackend{failOffsets: map[uint64]bool{1: true}}
	store := testutil.NewRecordingStore()
	p := newTestPipeline(t, 4, "block", []backend.Backend{b}, store)

	in := feed(t, mustEvent(t, 1, "T"), mustEvent(t, 2, "T"))
	if err := p.Run(context.Background(), in); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if got := store.LastCommitted("f"); got != 0 {
		t.Fatalf("committed = %d, want 0 (blocked on failed offset 1)", got)
	}
}

// conditionalBackend fails Process for a fixed set of offsets, always.
type conditionalBackend struct {
	failOffsets map[uint64]bool
}

func (c *conditionalBackend) Name() string                 { return "COND" }
func (c *conditionalBackend) RelevantEventTypes() []string { return backend.AllEventTypes }
func (c *conditionalBackend) IsRelevant(_ context.Context, _ *events.EnrichedEvent) bool {
	return true
}

func (c *conditionalBackend) Process(_ context.Context, ev *events.EnrichedEvent) error {
	if c.failOffsets[ev.Offset()] {
		return errors.New("forced failure")
	}
	return nil
}

// droppingBackend returns a backend.DropError for every event, counting Process
// calls so a test can assert a deliberate drop is not retried.
type droppingBackend struct {
	reason string

	mu    sync.Mutex
	calls int
}

func (d *droppingBackend) Name() string                 { return "DROP" }
func (d *droppingBackend) RelevantEventTypes() []string { return backend.AllEventTypes }
func (d *droppingBackend) IsRelevant(_ context.Context, _ *events.EnrichedEvent) bool {
	return true
}

func (d *droppingBackend) Process(_ context.Context, _ *events.EnrichedEvent) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.calls++
	return backend.Dropped(d.reason)
}

func (d *droppingBackend) processCalls() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.calls
}

// TestPipeline_BackendDropIsRecordedNotDelivered pins the DropError contract: a
// deliberate drop is handled (watermark advances) but counted under
// fig_events_dropped_total rather than as a delivery, and it is never retried.
//
// This test is deliberately not parallel: it asserts before/after deltas on the
// process-global EventsDelivered counter, which concurrently running tests would
// perturb.
func TestPipeline_BackendDropIsRecordedNotDelivered(t *testing.T) {
	const reason = "unit_test_reason"
	b := &droppingBackend{reason: reason}
	store := testutil.NewRecordingStore()
	p := newTestPipeline(t, 1, "dlq", []backend.Backend{b}, store)

	deliveredBefore := prommetrics.ToFloat64(metrics.EventsDelivered)
	failedBefore := prommetrics.ToFloat64(metrics.EventsFailed)
	droppedBefore := prommetrics.ToFloat64(metrics.EventsDropped.WithLabelValues("DROP", reason))

	in := feed(t, mustEvent(t, 1, "T"))
	if err := p.Run(context.Background(), in); err != nil {
		t.Fatalf("Run: %v", err)
	}

	// A deliberate drop is handled: the watermark advances.
	if got := store.LastCommitted("f"); got != 1 {
		t.Fatalf("committed = %d, want 1 (drop is handled)", got)
	}
	// A drop is not retried: Process is called exactly once.
	if got := b.processCalls(); got != 1 {
		t.Fatalf("Process calls = %d, want 1 (drop must not retry)", got)
	}
	// The drop is counted under fig_events_dropped_total{backend,reason}.
	if got := prommetrics.ToFloat64(metrics.EventsDropped.WithLabelValues("DROP", reason)) - droppedBefore; got != 1 {
		t.Fatalf("EventsDropped delta = %v, want 1", got)
	}
	// It is not counted as a delivery or a failure.
	if got := prommetrics.ToFloat64(metrics.EventsDelivered) - deliveredBefore; got != 0 {
		t.Fatalf("EventsDelivered delta = %v, want 0 (drop is not a delivery)", got)
	}
	if got := prommetrics.ToFloat64(metrics.EventsFailed) - failedBefore; got != 0 {
		t.Fatalf("EventsFailed delta = %v, want 0 (drop is not a failure)", got)
	}
}

func TestPipeline_RetrySucceedsWithinBudget(t *testing.T) {
	t.Parallel()
	b := newFakeBackend("B", backend.AllEventTypes)
	b.failN = maxDeliveryAttempts - 1 // fail then succeed on the last attempt
	store := testutil.NewRecordingStore()
	p := newTestPipeline(t, 1, "dlq", []backend.Backend{b}, store)

	in := feed(t, mustEvent(t, 1, "T"))
	if err := p.Run(context.Background(), in); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if got := store.LastCommitted("f"); got != 1 {
		t.Fatalf("committed = %d, want 1", got)
	}
	if len(b.processedOffsets()) != 1 {
		t.Fatalf("processed %d, want 1", len(b.processedOffsets()))
	}
}

func TestPipeline_MultipleBackendsAllMustSucceed(t *testing.T) {
	t.Parallel()
	ok := newFakeBackend("OK", backend.AllEventTypes)
	bad := &conditionalBackend{failOffsets: map[uint64]bool{1: true}}
	store := testutil.NewRecordingStore()
	// block policy so a failure on one dispatched-to backend holds the offset.
	p := newTestPipeline(t, 1, "block", []backend.Backend{ok, bad}, store)

	in := feed(t, mustEvent(t, 1, "T"))
	if err := p.Run(context.Background(), in); err != nil {
		t.Fatalf("Run: %v", err)
	}
	// One backend failed under block -> offset held.
	if got := store.LastCommitted("f"); got != 0 {
		t.Fatalf("committed = %d, want 0 (one backend failed)", got)
	}
}

func TestPipeline_PanicInBackendIsContained(t *testing.T) {
	t.Parallel()
	store := testutil.NewRecordingStore()
	p := newTestPipeline(t, 1, "dlq", []backend.Backend{&panicBackend{}}, store)

	in := feed(t, mustEvent(t, 1, "T"), mustEvent(t, 2, "T"))
	// Must not panic the test process; Run returns normally.
	if err := p.Run(context.Background(), in); err != nil {
		t.Fatalf("Run: %v", err)
	}
	// Under DLQ, a panicked event is dead-lettered and its watermark advances,
	// so one poison event cannot wedge the feed's resume offset forever.
	if got := store.LastCommitted("f"); got != 2 {
		t.Fatalf("committed = %d, want 2 (panicked events dead-lettered under dlq)", got)
	}
}

func TestPipeline_PanicUnderBlockPolicyStallsWatermark(t *testing.T) {
	t.Parallel()
	store := testutil.NewRecordingStore()
	p := newTestPipeline(t, 1, "block", []backend.Backend{&panicBackend{}}, store)

	in := feed(t, mustEvent(t, 1, "T"), mustEvent(t, 2, "T"))
	if err := p.Run(context.Background(), in); err != nil {
		t.Fatalf("Run: %v", err)
	}
	// Under block, a panicked event holds the watermark (strict/compliance mode),
	// matching a non-panicking block-policy delivery failure.
	if got := store.LastCommitted("f"); got != 0 {
		t.Fatalf("committed = %d, want 0 (panic holds watermark under block)", got)
	}
}

type panicBackend struct{}

func (p *panicBackend) Name() string                 { return "PANIC" }
func (p *panicBackend) RelevantEventTypes() []string { return backend.AllEventTypes }
func (p *panicBackend) IsRelevant(_ context.Context, _ *events.EnrichedEvent) bool {
	panic("boom in IsRelevant")
}
func (p *panicBackend) Process(_ context.Context, _ *events.EnrichedEvent) error { return nil }

func TestPipeline_IsRelevantFalseSkipsBackend(t *testing.T) {
	t.Parallel()
	b := newFakeBackend("B", backend.AllEventTypes)
	b.relevant = false
	store := testutil.NewRecordingStore()
	p := newTestPipeline(t, 1, "dlq", []backend.Backend{b}, store)

	in := feed(t, mustEvent(t, 1, "T"))
	if err := p.Run(context.Background(), in); err != nil {
		t.Fatalf("Run: %v", err)
	}
	// Not relevant -> zero dispatched -> trivially handled, watermark advances.
	if got := store.LastCommitted("f"); got != 1 {
		t.Fatalf("committed = %d, want 1", got)
	}
	if len(b.processedOffsets()) != 0 {
		t.Fatalf("processed %d, want 0", len(b.processedOffsets()))
	}
}

// --- GATE2 cloud-detection gate (Run integration) ------------------------

// newGate2Pipeline builds a pipeline whose cloud-detection gate is live: the
// exclude-clouds set and a custom enricher are wired in, and a single
// all-accepting backend records what survives the gate.
func newGate2Pipeline(t *testing.T, policy string, excludeClouds []string, enricher events.Enricher, store offset.Store) (*Pipeline, *fakeBackend) {
	t.Helper()
	b := newFakeBackend("B", backend.AllEventTypes)
	cfg := &config.Config{}
	cfg.Gateway.WorkerThreads = 1
	cfg.Events.DeliveryFailure = policy
	cfg.DetectionsExcludeClouds = excludeClouds
	p, err := New(Params{Config: cfg, Backends: []backend.Backend{b}, Enricher: enricher, Store: store, Logger: testutil.DiscardLogger()})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	p.retryBase = 0
	return p, b
}

func TestPipeline_Gate2DropsExcludedProvider(t *testing.T) {
	t.Parallel()
	store := testutil.NewRecordingStore()
	p, b := newGate2Pipeline(t, "dlq", []string{"AWS"}, &testutil.FakeEnricher{Host: &common.HostDetails{Known: true, CloudProvider: "AWS"}}, store)

	in := feed(t, mustEvent(t, 1, eppDetectionEventType))
	if err := p.Run(context.Background(), in); err != nil {
		t.Fatalf("Run: %v", err)
	}
	// Excluded provider -> gate drops it -> zero dispatched, watermark advances.
	if got := store.LastCommitted("f"); got != 1 {
		t.Fatalf("committed = %d, want 1", got)
	}
	if len(b.processedOffsets()) != 0 {
		t.Fatalf("processed %d, want 0 (dropped by gate)", len(b.processedOffsets()))
	}
}

func TestPipeline_Gate2UnrecognizedBucketHonored(t *testing.T) {
	t.Parallel()
	store := testutil.NewRecordingStore()
	// Unknown device (empty provider) with "unrecognized" excluded -> dropped.
	p, b := newGate2Pipeline(t, "dlq", []string{"unrecognized"}, &testutil.FakeEnricher{Host: &common.HostDetails{}}, store)

	in := feed(t, mustEvent(t, 1, eppDetectionEventType))
	if err := p.Run(context.Background(), in); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if got := store.LastCommitted("f"); got != 1 {
		t.Fatalf("committed = %d, want 1", got)
	}
	if len(b.processedOffsets()) != 0 {
		t.Fatalf("processed %d, want 0 (unrecognized dropped)", len(b.processedOffsets()))
	}
}

func TestPipeline_Gate2TerminalErrorDLQAdvancesWatermark(t *testing.T) {
	t.Parallel()
	store := testutil.NewRecordingStore()
	p, b := newGate2Pipeline(t, "dlq", []string{"AWS"}, &testutil.FakeEnricher{HostErr: errBoom}, store)

	in := feed(t, mustEvent(t, 1, eppDetectionEventType))
	if err := p.Run(context.Background(), in); err != nil {
		t.Fatalf("Run: %v", err)
	}
	// Terminal enrichment error under DLQ dead-letters -> watermark advances.
	if got := store.LastCommitted("f"); got != 1 {
		t.Fatalf("committed = %d, want 1 (dlq acks enrichment failure)", got)
	}
	if len(b.processedOffsets()) != 0 {
		t.Fatalf("processed %d, want 0 (never reached backend)", len(b.processedOffsets()))
	}
}

func TestPipeline_Gate2TerminalErrorBlockStallsWatermark(t *testing.T) {
	t.Parallel()
	store := testutil.NewRecordingStore()
	p, _ := newGate2Pipeline(t, "block", []string{"AWS"}, &testutil.FakeEnricher{HostErr: errBoom}, store)

	in := feed(t, mustEvent(t, 1, eppDetectionEventType))
	if err := p.Run(context.Background(), in); err != nil {
		t.Fatalf("Run: %v", err)
	}
	// Terminal enrichment error under block holds the watermark.
	if got := store.LastCommitted("f"); got != 0 {
		t.Fatalf("committed = %d, want 0 (block holds on enrichment failure)", got)
	}
}

func TestPipeline_Gate2ContextCancelHoldsWatermark(t *testing.T) {
	t.Parallel()
	store := testutil.NewRecordingStore()
	// A context error is shutdown, not a data failure: even under DLQ the event
	// must be held (not dead-lettered), so the watermark does not advance.
	p, _ := newGate2Pipeline(t, "dlq", []string{"AWS"}, &testutil.FakeEnricher{HostErr: context.Canceled}, store)

	in := feed(t, mustEvent(t, 1, eppDetectionEventType))
	if err := p.Run(context.Background(), in); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if got := store.LastCommitted("f"); got != 0 {
		t.Fatalf("committed = %d, want 0 (ctx-cancel holds, never dead-letters)", got)
	}
}

// --- global severity/age filter ------------------------------------------

// filterEvent builds an event with an explicit SeverityName and creation time
// so the global filter can be exercised.
func filterEvent(t *testing.T, feedID string, off uint64, severityName string, creationMillis int64) *events.Event {
	t.Helper()
	return testutil.MustEvent(t, testutil.EventOptions{
		FeedID:         feedID,
		EventType:      "EppDetectionSummaryEvent",
		Offset:         off,
		SeverityName:   severityName,
		CreationMillis: creationMillis,
	})
}

func TestPipeline_SeverityFilterAdvancesWatermarkWithoutDispatch(t *testing.T) {
	t.Parallel()
	b := newFakeBackend("B", backend.AllEventTypes)
	store := testutil.NewRecordingStore()
	p := newTestPipeline(t, 1, "dlq", []backend.Backend{b}, store)
	// Drop anything below High (4).
	p.sevThreshold = 4

	// Low (2) is below threshold -> filtered; High (4) passes.
	in := feed(t,
		filterEvent(t, "f", 1, "Low", 0),
		filterEvent(t, "f", 2, "High", 0),
	)
	if err := p.Run(context.Background(), in); err != nil {
		t.Fatalf("Run: %v", err)
	}
	// Filtered offset 1 is still marked done, so the watermark advances past it
	// and reaches 2.
	if got := store.LastCommitted("f"); got != 2 {
		t.Fatalf("committed = %d, want 2", got)
	}
	// Only the High event reached the backend.
	if got := b.processedOffsets(); len(got) != 1 || got[0] != 2 {
		t.Fatalf("processed = %v, want [2]", got)
	}
}

func TestPipeline_ZeroThresholdsDisableFilter(t *testing.T) {
	t.Parallel()
	b := newFakeBackend("B", backend.AllEventTypes)
	store := testutil.NewRecordingStore()
	p := newTestPipeline(t, 1, "dlq", []backend.Backend{b}, store)
	// Default thresholds (0/0): nothing is filtered even for an Informational,
	// long-past event.
	in := feed(t, filterEvent(t, "f", 1, "Informational", 0))
	if err := p.Run(context.Background(), in); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if got := b.processedOffsets(); len(got) != 1 {
		t.Fatalf("processed = %v, want the event delivered", got)
	}
}

// --- New validation -------------------------------------------------------

func TestNew_Validation(t *testing.T) {
	t.Parallel()
	base := func() *config.Config {
		c := &config.Config{}
		c.Gateway.WorkerThreads = 4
		c.Events.DeliveryFailure = "drop"
		return c
	}
	tests := []struct {
		name    string
		mutate  func(*config.Config)
		store   offset.Store
		logger  *slog.Logger
		wantErr bool
	}{
		{"ok", func(*config.Config) {}, offset.NewMemory(), testutil.DiscardLogger(), false},
		{"zero workers", func(c *config.Config) { c.Gateway.WorkerThreads = 0 }, offset.NewMemory(), testutil.DiscardLogger(), true},
		{"bad policy", func(c *config.Config) { c.Events.DeliveryFailure = "nope" }, offset.NewMemory(), testutil.DiscardLogger(), true},
		{"nil store", func(*config.Config) {}, nil, testutil.DiscardLogger(), true},
		{"nil logger", func(*config.Config) {}, offset.NewMemory(), nil, true},
		{"empty policy defaults drop", func(c *config.Config) { c.Events.DeliveryFailure = "" }, offset.NewMemory(), testutil.DiscardLogger(), false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			cfg := base()
			tc.mutate(cfg)
			_, err := New(Params{Config: cfg, Enricher: noopEnricher{}, Store: tc.store, Logger: tc.logger})
			if (err != nil) != tc.wantErr {
				t.Fatalf("New err = %v, wantErr %v", err, tc.wantErr)
			}
		})
	}
}

func TestParseDeliveryPolicy(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		raw     string
		want    deliveryPolicy
		wantErr bool
	}{
		{"empty defaults drop", "", policyDrop, false},
		{"drop", "drop", policyDrop, false},
		{"discard", "discard", policyDrop, false},
		{"dlq deprecated alias", "dlq", policyDrop, false},
		{"block", "block", policyBlock, false},
		{"case-insensitive and trimmed", "  BLOCK  ", policyBlock, false},
		{"invalid", "nope", 0, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := parseDeliveryPolicy(tc.raw)
			if (err != nil) != tc.wantErr {
				t.Fatalf("parseDeliveryPolicy(%q) err = %v, wantErr %v", tc.raw, err, tc.wantErr)
			}
			if err == nil && got != tc.want {
				t.Fatalf("parseDeliveryPolicy(%q) = %v, want %v", tc.raw, got, tc.want)
			}
		})
	}
}

func TestNew_NilConfig(t *testing.T) {
	t.Parallel()
	if _, err := New(Params{Config: nil, Enricher: noopEnricher{}, Store: offset.NewMemory(), Logger: testutil.DiscardLogger()}); err == nil {
		t.Fatal("expected error for nil config")
	}
}

func TestNew_NilEnricher(t *testing.T) {
	t.Parallel()
	cfg := &config.Config{}
	cfg.Gateway.WorkerThreads = 4
	cfg.Events.DeliveryFailure = "drop"
	if _, err := New(Params{Config: cfg, Enricher: nil, Store: offset.NewMemory(), Logger: testutil.DiscardLogger()}); err == nil {
		t.Fatal("expected error for nil enricher")
	}
}

func TestShouldWarnNoOp(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		received uint64
		filtered uint64
		want     bool
	}{
		{"idle window warns about nothing", 0, 0, false},
		{"all delivered", 100, 0, false},
		{"partial filtering is healthy", 100, 99, false},
		{"every event filtered", 100, 100, true},
		{"filtered exceeds received across boundary", 100, 101, true},
		{"single filtered event", 1, 1, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := shouldWarnNoOp(tc.received, tc.filtered); got != tc.want {
				t.Fatalf("shouldWarnNoOp(%d, %d) = %v, want %v", tc.received, tc.filtered, got, tc.want)
			}
		})
	}
}
