// Package pipeline implements the consumer side of FIG: a bounded worker pool
// that applies the three dispatch gates, submits to each passing backend, and
// advances a durable, in-order resume watermark only after delivery succeeds.
//
// It replaces fig/worker.py (the WorkerThread get->process loop that swallowed
// all exceptions) and the at-most-once offset advancement in
// fig/queue/__init__.py (which advanced the resume offset at dequeue). The
// three gates are ported from fig/backends/__init__.py:37-56.
package pipeline

import (
	"context"
	"fmt"
	"log/slog"
	"sync"

	"github.com/crowdstrike/falcon-integration-gateway/internal/metrics"
	"github.com/crowdstrike/falcon-integration-gateway/internal/offset"
)

// feedTracker holds the in-order commit state for a single Falcon feed_id.
//
// committed is the highest offset known safe to resume after. received is the
// highest offset the ordered stream has delivered for this feed. inflight holds
// offsets that have been received but not yet completed (out-of-order worker
// completions and, under the block policy, stuck deliveries).
//
// The Falcon stream delivers offsets in ascending order, but the offset counter
// reflects the unfiltered stream position: applying a server-side eventType
// filter delivers offsets with large gaps (offsets belonging to filtered-out
// event types are never delivered). The watermark therefore advances over those
// gaps — an offset below received that was never received is a filter gap that
// will never arrive, not an in-flight event — while never advancing past an
// offset still in flight. This keeps delivery at-least-once without stalling the
// watermark on the first filter gap.
//
// warned latches the "watermark not advancing" warning for the current stall
// episode so a persistent stall logs once rather than on every completion; it
// clears when inflight drops back below the warn threshold.
type feedTracker struct {
	committed uint64
	received  uint64
	inflight  map[uint64]bool
	warned    bool
}

// commitTracker tracks, per feed_id, the in-order commit watermark and
// persists advances through an offset.Store.
//
// This is the crux of at-least-once delivery: workers complete events
// concurrently and out of order, but an offset is only committed once every
// received offset up to and including it has completed.
//
// Two debounce layers sit between "event fully delivered" and "resume floor is
// durable on disk", and a crash in either window re-delivers already-handled
// events (duplicates, never loss — consistent with the at-least-once contract):
//
//  1. In-order gate (here). Done removes an offset from the in-flight set but
//     advances committed only to just below the lowest offset still in flight.
//     An offset that finished out of order — delivered and Done while a lower
//     offset is still being worked — is not yet reflected in committed, so a
//     crash before that lower offset completes re-delivers the higher one.
//  2. Time coalescing (offset.BufferedStore, behind store.Commit). Even once
//     committed advances and store.Commit is called, the durable Stores update
//     only their in-memory map and coalesce the disk/SSM write to at most once
//     per flush interval. A crash within that interval leaves the persisted
//     floor behind this in-memory committed value.
//
// So the on-disk resume floor can lag committed by both the in-flight span and
// up to one flush interval; a crash re-delivers everything after that persisted
// floor, not everything after committed. Graceful shutdown closes the store,
// whose final flush collapses layer 2; only an abrupt crash exposes the window.
type commitTracker struct {
	mu     sync.Mutex
	feeds  map[string]*feedTracker
	store  offset.Store
	logger *slog.Logger
	// pendingWarnThreshold logs a throttled warning when a feed holds more than
	// this many in-flight offsets (a stuck backend under the block policy, or a
	// slow-draining backlog). Zero disables it.
	pendingWarnThreshold int
	// pendingMax bounds the in-flight set: when a feed exceeds it, the overage is
	// counted via PendingOverflow and logged so a runaway block-policy backlog is
	// visible before it exhausts memory. Zero disables the check.
	pendingMax int
}

// commitTrackerConfig carries the inputs to newCommitTracker.
type commitTrackerConfig struct {
	store                offset.Store
	logger               *slog.Logger
	pendingWarnThreshold int
	pendingMax           int
}

// newCommitTracker returns a commitTracker backed by cfg.store.
func newCommitTracker(cfg commitTrackerConfig) *commitTracker {
	return &commitTracker{
		feeds:                make(map[string]*feedTracker),
		store:                cfg.store,
		logger:               cfg.logger,
		pendingWarnThreshold: cfg.pendingWarnThreshold,
		pendingMax:           cfg.pendingMax,
	}
}

// feed returns the tracker for feedID, seeding it from the store on first use so
// a resumed stream (which restarts at committed+1) advances correctly instead of
// treating the resume point as an unrecognized gap. Called with t.mu held.
func (t *commitTracker) feed(ctx context.Context, feedID string) (*feedTracker, error) {
	if f, ok := t.feeds[feedID]; ok {
		return f, nil
	}
	base, err := t.store.Load(ctx, feedID)
	if err != nil {
		return nil, fmt.Errorf("pipeline: load offset for feed %s: %w", feedID, err)
	}
	f := &feedTracker{committed: base, received: base, inflight: make(map[uint64]bool)}
	t.feeds[feedID] = f
	return f, nil
}

// Received records that the event at offset for feedID has been dequeued from
// the stream and handed to a worker. It MUST be called in stream (ascending
// offset) order from a single goroutine: the in-order guarantee is what lets the
// watermark treat an un-received lower offset as a filter gap rather than an
// in-flight event. It advances the received cursor and adds the offset to the
// in-flight set (unless it is at or below the watermark, i.e. a re-delivery after
// restart).
func (t *commitTracker) Received(ctx context.Context, feedID string, off uint64) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	f, err := t.feed(ctx, feedID)
	if err != nil {
		return err
	}
	if off > f.received {
		f.received = off
	}
	// A re-delivery at or below the watermark is already durably covered; do not
	// track it as in-flight.
	if off <= f.committed {
		return nil
	}
	f.inflight[off] = true

	if t.pendingMax > 0 && len(f.inflight) > t.pendingMax {
		metrics.PendingOverflow.WithLabelValues(feedID).Inc()
		t.logger.Error("in-flight offset set exceeded pending_max; backlog is not draining (restart required under block policy)",
			"feed_id", feedID,
			"committed", f.committed,
			"inflight", len(f.inflight),
			"pending_max", t.pendingMax,
		)
	}

	metrics.PendingEvents.WithLabelValues(feedID).Set(float64(len(f.inflight)))
	t.maybeWarnStall(f, feedID)
	return nil
}

// Done records that the event at offset for feedID has been fully handled (all
// dispatched-to backends succeeded, or it was trivially handled / dropped). It
// removes offset from the in-flight set, advances the committed watermark to the
// highest offset with no lower in-flight offset outstanding, and — when the
// watermark advances — persists it via store.Commit and updates the
// fig_offset_committed gauge. It always publishes the current in-flight size to
// fig_pending_events.
func (t *commitTracker) Done(ctx context.Context, feedID string, off uint64) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	f, err := t.feed(ctx, feedID)
	if err != nil {
		return err
	}
	delete(f.inflight, off)

	// The watermark advances to the highest offset below every outstanding
	// in-flight offset: the whole received range when nothing is in flight, else
	// just below the lowest in-flight offset. Offsets between the old watermark
	// and this target that were never received are filter gaps, skipped safely.
	target := f.received
	if len(f.inflight) > 0 {
		target = minKey(f.inflight) - 1
	}

	metrics.PendingEvents.WithLabelValues(feedID).Set(float64(len(f.inflight)))
	t.maybeWarnStall(f, feedID)

	if target <= f.committed {
		return nil
	}
	f.committed = target
	if err := t.store.Commit(ctx, feedID, f.committed); err != nil {
		return fmt.Errorf("pipeline: commit offset %d for feed %s: %w", f.committed, feedID, err)
	}
	metrics.OffsetCommitted.WithLabelValues(feedID).Set(float64(f.committed))
	return nil
}

// minKey returns the smallest key in a non-empty set. The in-flight set is small
// under normal operation (bounded by worker concurrency); it only grows when a
// backend stalls under the block policy, which is a restart-required condition.
func minKey(m map[uint64]bool) uint64 {
	var lowest uint64
	first := true
	for k := range m {
		if first || k < lowest {
			lowest, first = k, false
		}
	}
	return lowest
}

// maybeWarnStall logs one warning per stall episode when a feed's in-flight set
// crosses pendingWarnThreshold, surfacing a resume watermark that is not
// advancing because a backend is stuck under the block policy. The latch resets
// once the backlog falls back below the threshold. Called with t.mu held.
func (t *commitTracker) maybeWarnStall(f *feedTracker, feedID string) {
	if t.pendingWarnThreshold <= 0 {
		return
	}
	if len(f.inflight) < t.pendingWarnThreshold {
		f.warned = false
		return
	}
	if f.warned {
		return
	}
	f.warned = true
	t.logger.Warn("resume watermark not advancing; in-flight backlog is growing",
		"feed_id", feedID,
		"committed", f.committed,
		"inflight", len(f.inflight),
	)
}
