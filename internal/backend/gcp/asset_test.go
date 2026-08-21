package gcp

import (
	"context"
	"errors"
	"sync"
	"testing"
)

// fakeAssetLister records calls and returns canned resource names / error.
type fakeAssetLister struct {
	names []string
	err   error
	calls int
}

func (f *fakeAssetLister) listAssetResourceNames(_ context.Context, _, _ string) ([]string, error) {
	f.calls++
	return f.names, f.err
}

// countingLister resolves each instance id to a distinct, deterministic name
// and counts calls per instance id, so eviction tests can prove an evicted
// entry is re-fetched. It is safe for concurrent use.
type countingLister struct {
	mu    sync.Mutex
	calls map[string]int
}

func (l *countingLister) listAssetResourceNames(_ context.Context, _, instanceID string) ([]string, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.calls == nil {
		l.calls = map[string]int{}
	}
	l.calls[instanceID]++
	return []string{"name-" + instanceID}, nil
}

func (l *countingLister) callCount(instanceID string) int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.calls[instanceID]
}

func TestAssetCacheResourceName(t *testing.T) {
	t.Parallel()

	t.Run("single asset resolves and caches", func(t *testing.T) {
		t.Parallel()
		lister := &fakeAssetLister{names: []string{"//compute.googleapis.com/projects/p/zones/z/instances/i"}}
		c := newAssetCache(lister, defaultAssetCacheSize)

		got, err := c.resourceName(context.Background(), "42", "9876543210")
		if err != nil {
			t.Fatalf("resourceName: unexpected error %v", err)
		}
		if want := "//compute.googleapis.com/projects/p/zones/z/instances/i"; got != want {
			t.Errorf("resourceName = %q, want %q", got, want)
		}

		if _, err := c.resourceName(context.Background(), "42", "9876543210"); err != nil {
			t.Fatalf("second resourceName: unexpected error %v", err)
		}
		if lister.calls != 1 {
			t.Errorf("lister calls = %d, want 1 (result should be cached)", lister.calls)
		}
	})

	t.Run("zero assets returns ErrAssetNotFound", func(t *testing.T) {
		t.Parallel()
		lister := &fakeAssetLister{names: nil}
		c := newAssetCache(lister, defaultAssetCacheSize)

		_, err := c.resourceName(context.Background(), "99", "missing")
		if !errors.Is(err, ErrAssetNotFound) {
			t.Errorf("error = %v, want ErrAssetNotFound", err)
		}
	})

	t.Run("multiple assets is an error but not AssetNotFound", func(t *testing.T) {
		t.Parallel()
		lister := &fakeAssetLister{names: []string{"a", "b"}}
		c := newAssetCache(lister, defaultAssetCacheSize)

		_, err := c.resourceName(context.Background(), "7", "dup")
		if err == nil {
			t.Fatal("resourceName: expected error for multiple assets")
		}
		if errors.Is(err, ErrAssetNotFound) {
			t.Errorf("error = %v, want a non-AssetNotFound error", err)
		}
	})

	t.Run("lister error propagates and is not cached", func(t *testing.T) {
		t.Parallel()
		boom := errors.New("boom")
		lister := &fakeAssetLister{err: boom}
		c := newAssetCache(lister, defaultAssetCacheSize)

		if _, err := c.resourceName(context.Background(), "42", "x"); !errors.Is(err, boom) {
			t.Fatalf("error = %v, want boom", err)
		}

		lister.err = nil
		lister.names = []string{"resolved"}
		got, err := c.resourceName(context.Background(), "42", "x")
		if err != nil {
			t.Fatalf("retry resourceName: unexpected error %v", err)
		}
		if got != "resolved" {
			t.Errorf("resourceName = %q, want %q", got, "resolved")
		}
		if lister.calls != 2 {
			t.Errorf("lister calls = %d, want 2 (failed lookup must not be cached)", lister.calls)
		}
	})
}

func TestAssetCacheEviction(t *testing.T) {
	t.Parallel()

	lister := &countingLister{}
	c := newAssetCache(lister, 2)
	ctx := context.Background()

	resolve := func(id string) {
		t.Helper()
		got, err := c.resourceName(ctx, "proj", id)
		if err != nil {
			t.Fatalf("resourceName(%s): %v", id, err)
		}
		if want := "name-" + id; got != want {
			t.Fatalf("resourceName(%s) = %q, want %q", id, got, want)
		}
	}

	// Fill to capacity, then overflow: i3 evicts the oldest entry, i1.
	resolve("i1")
	resolve("i2")
	resolve("i3")

	// i2 and i3 are still hot: re-lookups hit the cache, no re-fetch.
	resolve("i2")
	resolve("i3")

	// i1 was evicted: a re-lookup must re-fetch it (and in turn evict i2).
	resolve("i1")

	if got := lister.callCount("i1"); got != 2 {
		t.Errorf("i1 fetches = %d, want 2 (evicted then re-fetched)", got)
	}
	if got := lister.callCount("i2"); got != 1 {
		t.Errorf("i2 fetches = %d, want 1 (stayed cached across the overflow)", got)
	}
	if got := lister.callCount("i3"); got != 1 {
		t.Errorf("i3 fetches = %d, want 1", got)
	}
}
