package offset

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// flushInterval bounds how often dirty state is fsynced to disk. Commits that
// arrive within this window of the previous persist are coalesced (the value
// is kept in memory and written by the next persist or the final Close flush),
// avoiding an fsync storm under a high-throughput stream.
const flushInterval = time.Second

// File is a durable, disk-backed Store. It persists a JSON object mapping
// feed_id -> offset to a single file, replacing the in-memory-only offset
// tracking in the Python daemon (fig/queue/__init__.py) so that resume offsets
// survive a process restart.
//
// Writes are atomic (write to path+".tmp" then os.Rename) and debounced: a
// Commit updates in-memory state immediately but only persists to disk at most
// once per flushInterval, with a guaranteed final flush on Close. All state is
// guarded by a single mutex.
type File struct {
	path string

	mu        sync.Mutex
	offsets   map[string]uint64
	dirty     bool
	lastFlush time.Time
	closed    bool
}

// NewFile constructs a File store persisting to path, creating parent
// directories as needed. Existing contents are hydrated into memory; a missing
// file is treated as an empty store (not an error).
func NewFile(path string) (*File, error) {
	if path == "" {
		return nil, fmt.Errorf("offset: file store path must not be empty")
	}
	if dir := filepath.Dir(path); dir != "" {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return nil, fmt.Errorf("offset: creating store directory %q: %w", dir, err)
		}
	}

	f := &File{
		path:    path,
		offsets: make(map[string]uint64),
	}

	data, err := os.ReadFile(path) //nolint:gosec // path is operator-configured
	switch {
	case os.IsNotExist(err):
		// missing file => empty store
	case err != nil:
		return nil, fmt.Errorf("offset: reading store %q: %w", path, err)
	default:
		if len(data) > 0 {
			if err := json.Unmarshal(data, &f.offsets); err != nil {
				return nil, fmt.Errorf("offset: parsing store %q: %w", path, err)
			}
		}
	}

	return f, nil
}

// Load returns the current in-memory offset for feedID (hydrated from disk on
// construction), or 0 when absent.
func (f *File) Load(_ context.Context, feedID string) (uint64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.offsets[feedID], nil
}

// Commit advances feedID's offset in memory and persists to disk if the
// debounce window has elapsed. Otherwise the value is retained and flushed by a
// later Commit or by Close.
//
// The stored offset is monotonic: a commit at or below the current value is a
// no-op. The watermark is a resume floor, and moving it backward would replay
// or re-deliver events that were already handled, so a stale or out-of-order
// commit must never regress it.
func (f *File) Commit(_ context.Context, feedID string, offset uint64) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	if f.closed {
		return fmt.Errorf("offset: commit on closed store")
	}

	if cur, ok := f.offsets[feedID]; ok && cur >= offset {
		return nil
	}
	f.offsets[feedID] = offset
	f.dirty = true

	if time.Since(f.lastFlush) < flushInterval {
		return nil
	}
	return f.persistLocked()
}

// Close flushes any pending state to disk and marks the store closed. It is
// safe to call once; subsequent Commits return an error.
func (f *File) Close(_ context.Context) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	if f.closed {
		return nil
	}
	f.closed = true

	if !f.dirty {
		return nil
	}
	return f.persistLocked()
}

// persistLocked atomically writes the current offset map to disk. The caller
// must hold f.mu.
func (f *File) persistLocked() error {
	data, err := json.Marshal(f.offsets)
	if err != nil {
		return fmt.Errorf("offset: marshaling store: %w", err)
	}

	tmp := f.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return fmt.Errorf("offset: writing temp store %q: %w", tmp, err)
	}
	if err := os.Rename(tmp, f.path); err != nil {
		// Best-effort cleanup so a failed rename leaves no stray .tmp behind.
		_ = os.Remove(tmp)
		return fmt.Errorf("offset: renaming temp store into place: %w", err)
	}

	f.dirty = false
	f.lastFlush = time.Now()
	return nil
}
