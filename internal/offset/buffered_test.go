package offset

import (
	"context"
	"errors"
	"maps"
	"sync"
	"testing"
	"time"
)

// countingPersist is a PersistFunc that records how many times it was invoked
// and the last snapshot it was given, so tests can assert coalescing and
// monotonic behavior. It is safe for concurrent use.
type countingPersist struct {
	mu    sync.Mutex
	calls int
	last  map[string]uint64
	err   error
}

func (c *countingPersist) persist(_ context.Context, offsets map[string]uint64) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.err != nil {
		return c.err
	}
	c.calls++
	snapshot := make(map[string]uint64, len(offsets))
	maps.Copy(snapshot, offsets)
	c.last = snapshot
	return nil
}

func (c *countingPersist) setErr(err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.err = err
}

func (c *countingPersist) callCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.calls
}

func (c *countingPersist) lastValue() (uint64, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	v, ok := c.last["feed"]
	return v, ok
}

func TestBufferedStoreCoalescesWithinInterval(t *testing.T) {
	t.Parallel()

	p := &countingPersist{}
	// A huge interval means every commit after the first is coalesced.
	d := NewBufferedStore(BufferedStoreConfig{Interval: time.Hour, Persist: p.persist})

	ctx := context.Background()
	for _, off := range []uint64{1, 2, 3} {
		if err := d.Commit(ctx, "feed", off); err != nil {
			t.Fatalf("Commit(%d): %v", off, err)
		}
	}

	// The first advancing commit persists immediately (lastFlush is zero);
	// the rest are coalesced within the interval.
	if got := p.callCount(); got != 1 {
		t.Fatalf("persist calls before Close = %d, want 1 (first flush + 2 coalesced)", got)
	}
	if got := d.Load("feed"); got != 3 {
		t.Fatalf("in-memory watermark = %d, want 3 (advances synchronously)", got)
	}

	if err := d.Close(ctx); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if got := p.callCount(); got != 2 {
		t.Fatalf("persist calls after Close = %d, want 2 (Close flushes the pending write)", got)
	}
	if v, ok := p.lastValue(); !ok || v != 3 {
		t.Fatalf("last persisted feed = (%d, %v), want (3, true)", v, ok)
	}
}

func TestBufferedStoreMonotonicNeverPersistsLower(t *testing.T) {
	t.Parallel()

	p := &countingPersist{}
	// Interval 0 means every advancing commit persists, so the persisted value
	// tracks each accepted advance and we can prove a lower offset is rejected.
	d := NewBufferedStore(BufferedStoreConfig{Interval: 0, Persist: p.persist})

	ctx := context.Background()
	if err := d.Commit(ctx, "feed", 100); err != nil {
		t.Fatalf("Commit(100): %v", err)
	}
	if err := d.Commit(ctx, "feed", 50); err != nil {
		t.Fatalf("Commit(50): %v", err)
	}
	if err := d.Commit(ctx, "feed", 100); err != nil {
		t.Fatalf("Commit(100) equal: %v", err)
	}
	if err := d.Commit(ctx, "feed", 101); err != nil {
		t.Fatalf("Commit(101): %v", err)
	}

	// Only 100 and 101 are advancing commits; 50 and the repeated 100 are no-ops
	// that never persist.
	if got := p.callCount(); got != 2 {
		t.Fatalf("persist calls = %d, want 2 (100 and 101 only)", got)
	}
	if got := d.Load("feed"); got != 101 {
		t.Fatalf("watermark = %d, want 101", got)
	}
	if v, _ := p.lastValue(); v != 101 {
		t.Fatalf("last persisted = %d, want 101 (a lower offset never overwrites)", v)
	}
}

func TestBufferedStoreCommitAfterCloseErrors(t *testing.T) {
	t.Parallel()

	p := &countingPersist{}
	d := NewBufferedStore(BufferedStoreConfig{Interval: time.Hour, Persist: p.persist})

	ctx := context.Background()
	if err := d.Close(ctx); err != nil {
		t.Fatalf("Close: %v", err)
	}
	err := d.Commit(ctx, "feed", 1)
	if !errors.Is(err, ErrClosed) {
		t.Fatalf("Commit after Close = %v, want ErrClosed", err)
	}
}

func TestBufferedStorePersistErrorStaysDirty(t *testing.T) {
	t.Parallel()

	p := &countingPersist{}
	// Interval 0 so the advancing commit attempts to persist immediately.
	d := NewBufferedStore(BufferedStoreConfig{Interval: 0, Persist: p.persist})

	boom := errors.New("persist failed")
	p.setErr(boom)

	ctx := context.Background()
	if err := d.Commit(ctx, "feed", 100); !errors.Is(err, boom) {
		t.Fatalf("Commit with failing persist = %v, want %v", err, boom)
	}

	// The failed flush must leave the write pending so Close retries it.
	p.setErr(nil)
	if err := d.Close(ctx); err != nil {
		t.Fatalf("Close after clearing error: %v", err)
	}
	if v, ok := p.lastValue(); !ok || v != 100 {
		t.Fatalf("last persisted = (%d, %v), want (100, true) — Close must flush the pending write", v, ok)
	}
}

func TestBufferedStoreConcurrentCommits(t *testing.T) {
	t.Parallel()

	p := &countingPersist{}
	d := NewBufferedStore(BufferedStoreConfig{Interval: 0, Persist: p.persist})

	ctx := context.Background()
	const workers = 8
	const perWorker = 50

	var wg sync.WaitGroup
	for range workers {
		wg.Go(func() {
			for off := uint64(1); off <= perWorker; off++ {
				if err := d.Commit(ctx, "feed", off); err != nil {
					t.Errorf("Commit(%d): %v", off, err)
					return
				}
			}
		})
	}
	wg.Wait()

	if got := d.Load("feed"); got != perWorker {
		t.Fatalf("watermark = %d, want %d", got, perWorker)
	}
	if err := d.Close(ctx); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if v, _ := p.lastValue(); v != perWorker {
		t.Fatalf("last persisted = %d, want %d (Close flushes final watermark)", v, perWorker)
	}
}
