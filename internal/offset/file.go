package offset

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// File is a durable, disk-backed Store. It persists a JSON object mapping
// feed_id -> offset to a single file, replacing the in-memory-only offset
// tracking in the Python daemon (fig/queue/__init__.py) so that resume offsets
// survive a process restart.
//
// Writes are atomic (write to path+".tmp" then os.Rename) and buffered by an
// embedded BufferedStore: a Commit updates in-memory state immediately but only
// persists to disk at most once per DefaultFlushInterval, with a guaranteed
// final flush on Close.
type File struct {
	path string
	buf  *BufferedStore
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

	offsets := make(map[string]uint64)

	data, err := os.ReadFile(path) //nolint:gosec // path is operator-configured
	switch {
	case os.IsNotExist(err):
		// missing file => empty store
	case err != nil:
		return nil, fmt.Errorf("offset: reading store %q: %w", path, err)
	default:
		if len(data) > 0 {
			if err := json.Unmarshal(data, &offsets); err != nil {
				return nil, fmt.Errorf("offset: parsing store %q: %w", path, err)
			}
		}
	}

	f := &File{path: path}
	f.buf = NewBufferedStore(BufferedStoreConfig{
		Initial:  offsets,
		Interval: DefaultFlushInterval,
		Persist:  f.persist,
	})
	return f, nil
}

// Load returns the current in-memory offset for feedID (hydrated from disk on
// construction), or 0 when absent.
func (f *File) Load(_ context.Context, feedID string) (uint64, error) {
	return f.buf.Load(feedID), nil
}

// Commit advances feedID's offset in memory and persists to disk if the flush
// window has elapsed. Otherwise the value is retained and flushed by a later
// Commit or by Close.
//
// The stored offset is monotonic: a commit at or below the current value is a
// no-op. The watermark is a resume floor, and moving it backward would replay
// or re-deliver events that were already handled, so a stale or out-of-order
// commit must never regress it.
func (f *File) Commit(ctx context.Context, feedID string, offset uint64) error {
	return f.buf.Commit(ctx, feedID, offset)
}

// Close flushes any pending state to disk and marks the store closed. It is
// safe to call once; subsequent Commits return an error.
func (f *File) Close(ctx context.Context) error {
	return f.buf.Close(ctx)
}

// persist atomically writes offsets to disk. The BufferedStore invokes it
// serially under its lock, so it needs no additional synchronization.
func (f *File) persist(_ context.Context, offsets map[string]uint64) error {
	data, err := marshalOffsets(offsets)
	if err != nil {
		return err
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
	return nil
}
