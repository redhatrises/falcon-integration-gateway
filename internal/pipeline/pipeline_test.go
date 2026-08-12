package pipeline

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"testing"

	"github.com/crowdstrike/falcon-integration-gateway/internal/backend"
	"github.com/crowdstrike/falcon-integration-gateway/internal/config"
	"github.com/crowdstrike/falcon-integration-gateway/internal/events"
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

func (noopEnricher) HostDetails(_ context.Context, _ string) (*events.HostDetails, error) {
	return &events.HostDetails{}, nil
}

func (noopEnricher) MDMIdentifier(_ context.Context, _, _ string) (string, error) {
	return "", nil
}

// fakeEnricher resolves host details to a fixed cloud provider, or returns a
// fixed error. A provider of "" models device-not-found (the enricher's
// non-error empty-provider fallback); a non-nil err models a terminal or
// context lookup failure.
type fakeEnricher struct {
	provider string
	err      error
}

func (f *fakeEnricher) HostDetails(_ context.Context, _ string) (*events.HostDetails, error) {
	if f.err != nil {
		return nil, f.err
	}
	return &events.HostDetails{Known: f.provider != "", CloudProvider: f.provider}, nil
}

func (f *fakeEnricher) MDMIdentifier(_ context.Context, _, _ string) (string, error) {
	return "", nil
}

// --- commit tracker -------------------------------------------------------

// countingStore records every Commit so tests can assert the committed
// watermark sequence.
type countingStore struct {
	mu       sync.Mutex
	loadBase map[string]uint64
	commits  map[string][]uint64
	last     map[string]uint64
	closed   bool
}

func newCountingStore() *countingStore {
	return &countingStore{
		loadBase: map[string]uint64{},
		commits:  map[string][]uint64{},
		last:     map[string]uint64{},
	}
}

func (s *countingStore) Load(_ context.Context, feedID string) (uint64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.loadBase[feedID], nil
}

func (s *countingStore) Commit(_ context.Context, feedID string, off uint64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.commits[feedID] = append(s.commits[feedID], off)
	s.last[feedID] = off
	return nil
}

func (s *countingStore) Close(_ context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closed = true
	return nil
}

func (s *countingStore) lastCommitted(feedID string) uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.last[feedID]
}

func TestCommitTracker_OutOfOrderAdvancesMonotonically(t *testing.T) {
	t.Parallel()
	store := newCountingStore()
	tr := newCommitTracker(store, testutil.DiscardLogger())
	ctx := context.Background()
	const feed = "f1"

	// Feed offsets out of order: 3,1,2,5,4 -> watermark must reach 5 with no
	// gap skipped.
	for _, off := range []uint64{3, 1, 2, 5, 4} {
		if err := tr.Done(ctx, feed, off); err != nil {
			t.Fatalf("Done(%d): %v", off, err)
		}
	}

	if got := store.lastCommitted(feed); got != 5 {
		t.Fatalf("committed = %d, want 5", got)
	}

	// The committed sequence must be monotonically non-decreasing.
	store.mu.Lock()
	seq := store.commits[feed]
	store.mu.Unlock()
	var prev uint64
	for _, c := range seq {
		if c < prev {
			t.Fatalf("commit sequence not monotonic: %v", seq)
		}
		prev = c
	}
}

func TestCommitTracker_MissingMiddleStallsWatermark(t *testing.T) {
	t.Parallel()
	store := newCountingStore()
	tr := newCommitTracker(store, testutil.DiscardLogger())
	ctx := context.Background()
	const feed = "f1"

	// Never Done(2): watermark must stall at 1.
	for _, off := range []uint64{1, 3, 4, 5} {
		if err := tr.Done(ctx, feed, off); err != nil {
			t.Fatalf("Done(%d): %v", off, err)
		}
	}

	if got := store.lastCommitted(feed); got != 1 {
		t.Fatalf("committed = %d, want 1 (stalled on missing offset 2)", got)
	}

	// Delivering the missing offset unblocks the full contiguous run to 5.
	if err := tr.Done(ctx, feed, 2); err != nil {
		t.Fatalf("Done(2): %v", err)
	}
	if got := store.lastCommitted(feed); got != 5 {
		t.Fatalf("committed = %d, want 5 after gap filled", got)
	}
}

func TestCommitTracker_SeedsFromStoreAndIgnoresReplays(t *testing.T) {
	t.Parallel()
	store := newCountingStore()
	store.loadBase["f1"] = 10
	tr := newCommitTracker(store, testutil.DiscardLogger())
	ctx := context.Background()

	// Offsets at or below the loaded watermark are ignored (at-least-once
	// re-delivery after restart) and must not commit or move backwards.
	for _, off := range []uint64{5, 9, 10} {
		if err := tr.Done(ctx, "f1", off); err != nil {
			t.Fatalf("Done(%d): %v", off, err)
		}
	}
	if got := store.lastCommitted("f1"); got != 0 {
		t.Fatalf("unexpected commit %d for replayed offsets", got)
	}

	// The next contiguous offset after the seed advances.
	if err := tr.Done(ctx, "f1", 11); err != nil {
		t.Fatalf("Done(11): %v", err)
	}
	if got := store.lastCommitted("f1"); got != 11 {
		t.Fatalf("committed = %d, want 11", got)
	}
}

func TestCommitTracker_PerFeedIsolation(t *testing.T) {
	t.Parallel()
	store := newCountingStore()
	tr := newCommitTracker(store, testutil.DiscardLogger())
	ctx := context.Background()

	if err := tr.Done(ctx, "a", 1); err != nil {
		t.Fatal(err)
	}
	if err := tr.Done(ctx, "b", 1); err != nil {
		t.Fatal(err)
	}
	// b stalls at 1 (no 2); a advances to 2.
	if err := tr.Done(ctx, "a", 2); err != nil {
		t.Fatal(err)
	}
	if got := store.lastCommitted("a"); got != 2 {
		t.Fatalf("feed a committed = %d, want 2", got)
	}
	if got := store.lastCommitted("b"); got != 1 {
		t.Fatalf("feed b committed = %d, want 1", got)
	}
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
			enricher:      &fakeEnricher{err: errBoom}, // must not be consulted
			wantRelevant:  true,
		},
		{
			name:          "detection with empty exclude set is relevant, no enrichment",
			excludeClouds: map[string]bool{},
			eventType:     eppDetectionEventType,
			enricher:      &fakeEnricher{err: errBoom}, // must not be consulted
			wantRelevant:  true,
		},
		{
			name:          "detection on excluded provider is dropped",
			excludeClouds: map[string]bool{"AWS": true},
			eventType:     eppDetectionEventType,
			enricher:      &fakeEnricher{provider: "AWS"},
			wantRelevant:  false,
		},
		{
			name:          "detection on non-excluded provider passes",
			excludeClouds: map[string]bool{"AWS": true},
			eventType:     eppDetectionEventType,
			enricher:      &fakeEnricher{provider: "Azure"},
			wantRelevant:  true,
		},
		{
			name:          "unknown device with unrecognized excluded is dropped",
			excludeClouds: map[string]bool{"unrecognized": true},
			eventType:     eppDetectionEventType,
			enricher:      &fakeEnricher{provider: ""},
			wantRelevant:  false,
		},
		{
			name:          "unknown device without unrecognized excluded passes",
			excludeClouds: map[string]bool{"AWS": true},
			eventType:     eppDetectionEventType,
			enricher:      &fakeEnricher{provider: ""},
			wantRelevant:  true,
		},
		{
			name:          "terminal enrichment error surfaces",
			excludeClouds: map[string]bool{"AWS": true},
			eventType:     eppDetectionEventType,
			enricher:      &fakeEnricher{err: errBoom},
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
	cfg.Main.WorkerThreads = workers
	cfg.Events.DeliveryFailure = policy
	p, err := New(cfg, backends, noopEnricher{}, store, testutil.DiscardLogger())
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
	store := newCountingStore()
	p := newTestPipeline(t, 4, "dlq", []backend.Backend{b}, store)

	in := feed(t,
		mustEvent(t, 1, "T"),
		mustEvent(t, 2, "T"),
		mustEvent(t, 3, "T"),
	)
	if err := p.Run(context.Background(), in); err != nil {
		t.Fatalf("Run: %v", err)
	}

	if got := store.lastCommitted("f"); got != 3 {
		t.Fatalf("committed = %d, want 3", got)
	}
	if len(b.processedOffsets()) != 3 {
		t.Fatalf("processed %d events, want 3", len(b.processedOffsets()))
	}
	if !store.closed {
		t.Fatal("store not closed on Run completion")
	}
}

func TestPipeline_EventPassingNoBackendIsHandled(t *testing.T) {
	t.Parallel()
	// Backend only wants a type the events don't have -> zero dispatched, but
	// the watermark must still advance (trivially handled).
	b := newFakeBackend("B", []string{"OtherType"})
	store := newCountingStore()
	p := newTestPipeline(t, 1, "dlq", []backend.Backend{b}, store)

	in := feed(t, mustEvent(t, 1, "T"), mustEvent(t, 2, "T"))
	if err := p.Run(context.Background(), in); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if got := store.lastCommitted("f"); got != 2 {
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
	store := newCountingStore()
	p := newTestPipeline(t, 1, "dlq", []backend.Backend{b}, store)

	in := feed(t, mustEvent(t, 1, "T"), mustEvent(t, 2, "T"))
	if err := p.Run(context.Background(), in); err != nil {
		t.Fatalf("Run: %v", err)
	}
	// DLQ treats failures as handled -> watermark advances to 2.
	if got := store.lastCommitted("f"); got != 2 {
		t.Fatalf("committed = %d, want 2 (dlq acks failures)", got)
	}
}

func TestPipeline_BlockStallsWatermarkOnFailure(t *testing.T) {
	t.Parallel()
	// Offset 1 always fails; offset 2 succeeds. Under block policy, 1 is never
	// done, so the watermark must never advance (stays 0) even though 2
	// completes out of order.
	b := &conditionalBackend{failOffsets: map[uint64]bool{1: true}}
	store := newCountingStore()
	p := newTestPipeline(t, 4, "block", []backend.Backend{b}, store)

	in := feed(t, mustEvent(t, 1, "T"), mustEvent(t, 2, "T"))
	if err := p.Run(context.Background(), in); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if got := store.lastCommitted("f"); got != 0 {
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

func TestPipeline_RetrySucceedsWithinBudget(t *testing.T) {
	t.Parallel()
	b := newFakeBackend("B", backend.AllEventTypes)
	b.failN = maxDeliveryAttempts - 1 // fail then succeed on the last attempt
	store := newCountingStore()
	p := newTestPipeline(t, 1, "dlq", []backend.Backend{b}, store)

	in := feed(t, mustEvent(t, 1, "T"))
	if err := p.Run(context.Background(), in); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if got := store.lastCommitted("f"); got != 1 {
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
	store := newCountingStore()
	// block policy so a failure on one dispatched-to backend holds the offset.
	p := newTestPipeline(t, 1, "block", []backend.Backend{ok, bad}, store)

	in := feed(t, mustEvent(t, 1, "T"))
	if err := p.Run(context.Background(), in); err != nil {
		t.Fatalf("Run: %v", err)
	}
	// One backend failed under block -> offset held.
	if got := store.lastCommitted("f"); got != 0 {
		t.Fatalf("committed = %d, want 0 (one backend failed)", got)
	}
}

func TestPipeline_PanicInBackendIsContained(t *testing.T) {
	t.Parallel()
	store := newCountingStore()
	p := newTestPipeline(t, 1, "dlq", []backend.Backend{&panicBackend{}}, store)

	in := feed(t, mustEvent(t, 1, "T"), mustEvent(t, 2, "T"))
	// Must not panic the test process; Run returns normally.
	if err := p.Run(context.Background(), in); err != nil {
		t.Fatalf("Run: %v", err)
	}
	// Under DLQ, a panicked event is dead-lettered and its watermark advances,
	// so one poison event cannot wedge the feed's resume offset forever.
	if got := store.lastCommitted("f"); got != 2 {
		t.Fatalf("committed = %d, want 2 (panicked events dead-lettered under dlq)", got)
	}
}

func TestPipeline_PanicUnderBlockPolicyStallsWatermark(t *testing.T) {
	t.Parallel()
	store := newCountingStore()
	p := newTestPipeline(t, 1, "block", []backend.Backend{&panicBackend{}}, store)

	in := feed(t, mustEvent(t, 1, "T"), mustEvent(t, 2, "T"))
	if err := p.Run(context.Background(), in); err != nil {
		t.Fatalf("Run: %v", err)
	}
	// Under block, a panicked event holds the watermark (strict/compliance mode),
	// matching a non-panicking block-policy delivery failure.
	if got := store.lastCommitted("f"); got != 0 {
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
	store := newCountingStore()
	p := newTestPipeline(t, 1, "dlq", []backend.Backend{b}, store)

	in := feed(t, mustEvent(t, 1, "T"))
	if err := p.Run(context.Background(), in); err != nil {
		t.Fatalf("Run: %v", err)
	}
	// Not relevant -> zero dispatched -> trivially handled, watermark advances.
	if got := store.lastCommitted("f"); got != 1 {
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
	cfg.Main.WorkerThreads = 1
	cfg.Events.DeliveryFailure = policy
	cfg.DetectionsExcludeClouds = excludeClouds
	p, err := New(cfg, []backend.Backend{b}, enricher, store, testutil.DiscardLogger())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	p.retryBase = 0
	return p, b
}

func TestPipeline_Gate2DropsExcludedProvider(t *testing.T) {
	t.Parallel()
	store := newCountingStore()
	p, b := newGate2Pipeline(t, "dlq", []string{"AWS"}, &fakeEnricher{provider: "AWS"}, store)

	in := feed(t, mustEvent(t, 1, eppDetectionEventType))
	if err := p.Run(context.Background(), in); err != nil {
		t.Fatalf("Run: %v", err)
	}
	// Excluded provider -> gate drops it -> zero dispatched, watermark advances.
	if got := store.lastCommitted("f"); got != 1 {
		t.Fatalf("committed = %d, want 1", got)
	}
	if len(b.processedOffsets()) != 0 {
		t.Fatalf("processed %d, want 0 (dropped by gate)", len(b.processedOffsets()))
	}
}

func TestPipeline_Gate2UnrecognizedBucketHonored(t *testing.T) {
	t.Parallel()
	store := newCountingStore()
	// Unknown device (empty provider) with "unrecognized" excluded -> dropped.
	p, b := newGate2Pipeline(t, "dlq", []string{"unrecognized"}, &fakeEnricher{provider: ""}, store)

	in := feed(t, mustEvent(t, 1, eppDetectionEventType))
	if err := p.Run(context.Background(), in); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if got := store.lastCommitted("f"); got != 1 {
		t.Fatalf("committed = %d, want 1", got)
	}
	if len(b.processedOffsets()) != 0 {
		t.Fatalf("processed %d, want 0 (unrecognized dropped)", len(b.processedOffsets()))
	}
}

func TestPipeline_Gate2TerminalErrorDLQAdvancesWatermark(t *testing.T) {
	t.Parallel()
	store := newCountingStore()
	p, b := newGate2Pipeline(t, "dlq", []string{"AWS"}, &fakeEnricher{err: errBoom}, store)

	in := feed(t, mustEvent(t, 1, eppDetectionEventType))
	if err := p.Run(context.Background(), in); err != nil {
		t.Fatalf("Run: %v", err)
	}
	// Terminal enrichment error under DLQ dead-letters -> watermark advances.
	if got := store.lastCommitted("f"); got != 1 {
		t.Fatalf("committed = %d, want 1 (dlq acks enrichment failure)", got)
	}
	if len(b.processedOffsets()) != 0 {
		t.Fatalf("processed %d, want 0 (never reached backend)", len(b.processedOffsets()))
	}
}

func TestPipeline_Gate2TerminalErrorBlockStallsWatermark(t *testing.T) {
	t.Parallel()
	store := newCountingStore()
	p, _ := newGate2Pipeline(t, "block", []string{"AWS"}, &fakeEnricher{err: errBoom}, store)

	in := feed(t, mustEvent(t, 1, eppDetectionEventType))
	if err := p.Run(context.Background(), in); err != nil {
		t.Fatalf("Run: %v", err)
	}
	// Terminal enrichment error under block holds the watermark.
	if got := store.lastCommitted("f"); got != 0 {
		t.Fatalf("committed = %d, want 0 (block holds on enrichment failure)", got)
	}
}

func TestPipeline_Gate2ContextCancelHoldsWatermark(t *testing.T) {
	t.Parallel()
	store := newCountingStore()
	// A context error is shutdown, not a data failure: even under DLQ the event
	// must be held (not dead-lettered), so the watermark does not advance.
	p, _ := newGate2Pipeline(t, "dlq", []string{"AWS"}, &fakeEnricher{err: context.Canceled}, store)

	in := feed(t, mustEvent(t, 1, eppDetectionEventType))
	if err := p.Run(context.Background(), in); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if got := store.lastCommitted("f"); got != 0 {
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
	store := newCountingStore()
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
	if got := store.lastCommitted("f"); got != 2 {
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
	store := newCountingStore()
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
		c.Main.WorkerThreads = 4
		c.Events.DeliveryFailure = "dlq"
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
		{"zero workers", func(c *config.Config) { c.Main.WorkerThreads = 0 }, offset.NewMemory(), testutil.DiscardLogger(), true},
		{"bad policy", func(c *config.Config) { c.Events.DeliveryFailure = "nope" }, offset.NewMemory(), testutil.DiscardLogger(), true},
		{"nil store", func(*config.Config) {}, nil, testutil.DiscardLogger(), true},
		{"nil logger", func(*config.Config) {}, offset.NewMemory(), nil, true},
		{"empty policy defaults dlq", func(c *config.Config) { c.Events.DeliveryFailure = "" }, offset.NewMemory(), testutil.DiscardLogger(), false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			cfg := base()
			tc.mutate(cfg)
			_, err := New(cfg, nil, noopEnricher{}, tc.store, tc.logger)
			if (err != nil) != tc.wantErr {
				t.Fatalf("New err = %v, wantErr %v", err, tc.wantErr)
			}
		})
	}
}

func TestNew_NilConfig(t *testing.T) {
	t.Parallel()
	if _, err := New(nil, nil, noopEnricher{}, offset.NewMemory(), testutil.DiscardLogger()); err == nil {
		t.Fatal("expected error for nil config")
	}
}

func TestNew_NilEnricher(t *testing.T) {
	t.Parallel()
	cfg := &config.Config{}
	cfg.Main.WorkerThreads = 4
	cfg.Events.DeliveryFailure = "dlq"
	if _, err := New(cfg, nil, nil, offset.NewMemory(), testutil.DiscardLogger()); err == nil {
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
