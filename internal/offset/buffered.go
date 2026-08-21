package offset

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"
)

// marshalOffsets serializes the per-feed offset map to JSON for persistence. It
// is shared by the file and SSM stores, whose persist methods differ only in how
// they write the resulting bytes.
func marshalOffsets(offsets map[string]uint64) ([]byte, error) {
	data, err := json.Marshal(offsets)
	if err != nil {
		return nil, fmt.Errorf("offset: marshaling store: %w", err)
	}
	return data, nil
}

// DefaultFlushInterval bounds how often a BufferedStore persists dirty state.
// Commits that arrive within this window of the previous persist are coalesced
// (kept in memory and written by the next persist or the final Close flush),
// avoiding an I/O storm under a high-throughput stream.
const DefaultFlushInterval = time.Second

// ErrClosed is returned by BufferedStore.Commit after the store has been closed.
var ErrClosed = errors.New("offset: commit on closed store")

// PersistFunc durably writes a snapshot of the offset map. The BufferedStore
// invokes it serially while holding its lock, so an implementation needs no
// additional synchronization; it must not retain the map, whose contents may
// change after the call returns.
type PersistFunc func(ctx context.Context, offsets map[string]uint64) error

// BufferedStoreConfig configures a BufferedStore. It is declared before
// NewBufferedStore, its sole consumer.
type BufferedStoreConfig struct {
	// Initial seeds the in-memory watermark map with previously persisted state.
	// The BufferedStore takes ownership of the map; pass nil for an empty store.
	Initial map[string]uint64
	// Interval bounds how often Persist runs: a commit within Interval of the
	// last flush is coalesced. Zero persists on every advancing commit.
	Interval time.Duration
	// Persist durably writes the offset map. Required.
	Persist PersistFunc
}

// BufferedStore is a monotonic, write-coalescing per-feed offset accumulator
// shared by the durable Stores and the cloudtraillake backend guard. It advances
// an in-memory watermark synchronously on every accepted commit but throttles the
// durable Persist call to at most once per Interval, with a guaranteed final
// flush on Close.
//
// The watermark is monotonic: a commit at or below a feed's current value is a
// no-op that never persists, so a stale or out-of-order commit cannot regress
// the resume floor. Because the watermark advances in memory immediately,
// dedup within a running process is exact; only the durable write lags, bounded
// by Interval and reconciled by the Close flush. BufferedStore is safe for
// concurrent use.
//
// This time coalescing is the second of the two crash-loss debounce layers on
// the resume floor (the first is the pipeline commit tracker's in-order gate):
// a commit accepted here advances the in-memory watermark but may not reach disk
// for up to Interval, so an abrupt crash within that window re-delivers events
// after the last persisted floor. Close's final flush collapses this layer on a
// graceful shutdown.
type BufferedStore struct {
	interval time.Duration
	persist  PersistFunc

	mu        sync.Mutex
	offsets   map[string]uint64
	dirty     bool
	lastFlush time.Time
	closed    bool
}

// NewBufferedStore constructs a BufferedStore from cfg.
func NewBufferedStore(cfg BufferedStoreConfig) *BufferedStore {
	offsets := cfg.Initial
	if offsets == nil {
		offsets = make(map[string]uint64)
	}
	return &BufferedStore{
		interval: cfg.Interval,
		persist:  cfg.Persist,
		offsets:  offsets,
	}
}

// Load returns the current watermark for feedID, or 0 when absent.
func (d *BufferedStore) Load(feedID string) uint64 {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.offsets[feedID]
}

// Commit advances feedID's watermark and persists when the flush interval has
// elapsed; otherwise the value is retained in memory and flushed by a later
// Commit or by Close. A commit at or below the current watermark is a no-op.
// Commit after Close returns ErrClosed.
func (d *BufferedStore) Commit(ctx context.Context, feedID string, offset uint64) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.closed {
		return ErrClosed
	}
	if !applyOffset(d.offsets, feedID, offset) {
		return nil
	}
	d.dirty = true

	if time.Since(d.lastFlush) < d.interval {
		return nil
	}
	return d.persistLocked(ctx)
}

// Close flushes any pending state and marks the BufferedStore closed. It is safe
// to call once; subsequent Commits return ErrClosed.
func (d *BufferedStore) Close(ctx context.Context) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.closed {
		return nil
	}
	d.closed = true

	if !d.dirty {
		return nil
	}
	return d.persistLocked(ctx)
}

// persistLocked invokes the PersistFunc and, on success, clears the dirty flag
// and resets the flush window. A failed persist leaves the state dirty so a
// later Commit or Close retries it. The caller must hold d.mu.
func (d *BufferedStore) persistLocked(ctx context.Context) error {
	if err := d.persist(ctx, d.offsets); err != nil {
		return err
	}
	d.dirty = false
	d.lastFlush = time.Now()
	return nil
}
