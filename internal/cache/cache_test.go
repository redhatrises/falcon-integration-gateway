package cache

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
)

// size reports the number of memoized entries under the read lock. It is a
// test-only accessor for asserting the eviction bound holds.
func (c *Cache[K, V]) size() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.entries)
}

// countingCacheLoader resolves each key to a deterministic value and counts
// loads per key, so tests can prove memoization, error-not-cached, and single
// resolution under concurrency. It is safe for concurrent use.
type countingCacheLoader struct {
	mu    sync.Mutex
	calls map[string]int
	err   error
}

func (l *countingCacheLoader) load(key string) func(context.Context) (string, error) {
	return func(context.Context) (string, error) {
		l.mu.Lock()
		defer l.mu.Unlock()
		l.calls[key]++
		if l.err != nil {
			return "", l.err
		}
		return "v-" + key, nil
	}
}

func (l *countingCacheLoader) callCount(key string) int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.calls[key]
}

func newCountingCacheLoader() *countingCacheLoader {
	return &countingCacheLoader{calls: map[string]int{}}
}

func TestCacheMemoizes(t *testing.T) {
	t.Parallel()
	loader := newCountingCacheLoader()
	c := New[string, string](0)

	for i := range 3 {
		got, err := c.Get(context.Background(), "k", loader.load("k"))
		if err != nil {
			t.Fatalf("Get() call %d: %v", i, err)
		}
		if got != "v-k" {
			t.Errorf("Get() = %q, want %q", got, "v-k")
		}
	}
	if n := loader.callCount("k"); n != 1 {
		t.Errorf("loads = %d, want 1 (subsequent gets served from cache)", n)
	}
}

func TestCacheErrorNotCached(t *testing.T) {
	t.Parallel()
	loader := newCountingCacheLoader()
	loader.err = errors.New("transient")
	c := New[string, string](0)

	if _, err := c.Get(context.Background(), "k", loader.load("k")); err == nil {
		t.Fatal("first Get() = nil error, want loader error")
	}

	loader.mu.Lock()
	loader.err = nil
	loader.mu.Unlock()

	got, err := c.Get(context.Background(), "k", loader.load("k"))
	if err != nil {
		t.Fatalf("second Get(): %v", err)
	}
	if got != "v-k" {
		t.Errorf("second Get() = %q, want %q (failed loads must not be cached)", got, "v-k")
	}
	if n := loader.callCount("k"); n != 2 {
		t.Errorf("loads = %d, want 2 (failed load re-invokes)", n)
	}
}

func TestCacheConcurrentSingleLoad(t *testing.T) {
	t.Parallel()
	loader := newCountingCacheLoader()
	c := New[string, string](0)

	const goroutines = 32
	var wg sync.WaitGroup
	errs := make([]error, goroutines)
	wg.Add(goroutines)
	for i := range goroutines {
		go func(idx int) {
			defer wg.Done()
			_, errs[idx] = c.Get(context.Background(), "k", loader.load("k"))
		}(i)
	}
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Fatalf("goroutine %d: %v", i, err)
		}
	}
	if n := loader.callCount("k"); n != 1 {
		t.Errorf("loads = %d, want exactly 1 under concurrency", n)
	}
}

func TestCacheUnboundedRetainsAll(t *testing.T) {
	t.Parallel()
	loader := newCountingCacheLoader()
	c := New[string, string](0)

	const keys = 100
	for i := range keys {
		if _, err := c.Get(context.Background(), fmt.Sprintf("k%d", i), loader.load(fmt.Sprintf("k%d", i))); err != nil {
			t.Fatalf("Get(k%d): %v", i, err)
		}
	}
	if got := c.size(); got != keys {
		t.Errorf("size = %d, want %d (unbounded cache retains all)", got, keys)
	}
}

func TestCacheBoundedFIFOEviction(t *testing.T) {
	t.Parallel()
	loader := newCountingCacheLoader()
	c := New[string, string](2)
	ctx := context.Background()

	get := func(k string) {
		t.Helper()
		if _, err := c.Get(ctx, k, loader.load(k)); err != nil {
			t.Fatalf("Get(%s): %v", k, err)
		}
	}

	// Fill to capacity, then overflow: k3 evicts the oldest entry, k1.
	get("k1")
	get("k2")
	get("k3")

	// k2 and k3 are still hot: re-gets hit the cache.
	get("k2")
	get("k3")

	// k1 was evicted: a re-get must re-load it.
	get("k1")

	if n := loader.callCount("k1"); n != 2 {
		t.Errorf("k1 loads = %d, want 2 (evicted then re-loaded)", n)
	}
	if n := loader.callCount("k2"); n != 1 {
		t.Errorf("k2 loads = %d, want 1 (stayed cached across overflow)", n)
	}
	if n := loader.callCount("k3"); n != 1 {
		t.Errorf("k3 loads = %d, want 1", n)
	}
	if got := c.size(); got != 2 {
		t.Errorf("size = %d, want 2 (bound must hold)", got)
	}
}

// TestCacheConcurrentBounded proves the size bound holds under concurrent churn:
// many goroutines resolving far more distinct keys than the capacity must never
// leave the cache larger than its bound.
func TestCacheConcurrentBounded(t *testing.T) {
	t.Parallel()

	const (
		capacity = 16
		keys     = 256
		workers  = 32
	)
	loader := newCountingCacheLoader()
	c := New[string, string](capacity)
	ctx := context.Background()

	var wg sync.WaitGroup
	for w := range workers {
		wg.Add(1)
		go func(seed int) {
			defer wg.Done()
			for i := range keys {
				k := fmt.Sprintf("k%d", (seed+i)%keys)
				if _, err := c.Get(ctx, k, loader.load(k)); err != nil {
					t.Errorf("Get(%s): %v", k, err)
					return
				}
			}
		}(w)
	}
	wg.Wait()

	if got := c.size(); got > capacity {
		t.Errorf("size = %d, want <= %d (bound must hold under churn)", got, capacity)
	}
}

// TestCacheGenericKeyValue proves the cache is not string-locked: an int key and
// a struct value round-trip and memoize.
func TestCacheGenericKeyValue(t *testing.T) {
	t.Parallel()
	type entry struct{ name string }
	c := New[int, entry](0)

	var loads int
	load := func(context.Context) (entry, error) {
		loads++
		return entry{name: "answer"}, nil
	}
	for range 3 {
		got, err := c.Get(context.Background(), 42, load)
		if err != nil {
			t.Fatalf("Get(42): %v", err)
		}
		if got.name != "answer" {
			t.Errorf("Get(42) = %+v, want {answer}", got)
		}
	}
	if loads != 1 {
		t.Errorf("loads = %d, want 1", loads)
	}
}
