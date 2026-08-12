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
// committed is the highest contiguous offset known delivered. pending holds
// completed-but-not-yet-contiguous offsets (out-of-order worker completions).
// The watermark advances only through a contiguous run, so a missing middle
// offset stalls it — guaranteeing at-least-once with no gap ever skipped.
type feedTracker struct {
	committed uint64
	pending   map[uint64]bool
}

// commitTracker tracks, per feed_id, the in-order commit watermark and
// persists advances through an offset.Store.
//
// This is the crux of at-least-once delivery: workers complete events
// concurrently and out of order, but an offset is only committed once every
// offset up to and including it has completed. A crash re-delivers everything
// after the last committed watermark.
type commitTracker struct {
	mu     sync.Mutex
	feeds  map[string]*feedTracker
	store  offset.Store
	logger *slog.Logger
}

// newCommitTracker returns a commitTracker backed by store.
func newCommitTracker(store offset.Store, logger *slog.Logger) *commitTracker {
	return &commitTracker{
		feeds:  make(map[string]*feedTracker),
		store:  store,
		logger: logger,
	}
}

// Done records that the event at offset for feedID has been fully handled
// (all dispatched-to backends succeeded, or it was trivially handled / dead-
// lettered). It inserts offset into the feed's pending set, then advances the
// committed watermark while (committed+1) is pending, and — when the watermark
// advances — persists it via store.Commit and updates the fig_offset_committed
// gauge.
//
// The first time a feed is seen the watermark is seeded from store.Load so
// that a resumed stream (which restarts at committed+1) advances correctly
// instead of stalling because offset 1 never arrives.
func (t *commitTracker) Done(ctx context.Context, feedID string, off uint64) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	f, ok := t.feeds[feedID]
	if !ok {
		base, err := t.store.Load(ctx, feedID)
		if err != nil {
			return fmt.Errorf("pipeline: load offset for feed %s: %w", feedID, err)
		}
		f = &feedTracker{committed: base, pending: make(map[uint64]bool)}
		t.feeds[feedID] = f
	}

	// Ignore offsets at or below the watermark: a re-delivery after restart
	// (at-least-once) or a duplicate. Never move the watermark backwards.
	if off <= f.committed {
		return nil
	}

	f.pending[off] = true

	advanced := false
	for f.pending[f.committed+1] {
		delete(f.pending, f.committed+1)
		f.committed++
		advanced = true
	}

	if !advanced {
		return nil
	}

	if err := t.store.Commit(ctx, feedID, f.committed); err != nil {
		return fmt.Errorf("pipeline: commit offset %d for feed %s: %w", f.committed, feedID, err)
	}
	metrics.OffsetCommitted.WithLabelValues(feedID).Set(float64(f.committed))
	return nil
}
