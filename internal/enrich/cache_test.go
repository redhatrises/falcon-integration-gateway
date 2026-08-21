package enrich

import (
	"errors"
	"sync"
	"testing"
	"time"
)

// countingLoader records how many times a load func it hands out was actually
// invoked, so a test can prove memoization (one load) and non-caching (a load
// per call). It is safe for concurrent use.
type countingLoader struct {
	mu    sync.Mutex
	calls int
}

func (l *countingLoader) count() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.calls
}

// load returns a load func that resolves to value, stores per store, fails with
// err, and increments the call counter each time it runs.
func (l *countingLoader) load(value string, store bool, err error) func() (string, bool, error) {
	return func() (string, bool, error) {
		l.mu.Lock()
		l.calls++
		l.mu.Unlock()
		return value, store, err
	}
}

func TestSingleflightCacheCachesWhenStoreTrue(t *testing.T) {
	t.Parallel()

	m := newSingleflightCache[string](16, time.Hour)
	loader := &countingLoader{}

	for i := range 3 {
		v, _, err := m.get("k", loader.load("resolved", true, nil))
		if err != nil {
			t.Fatalf("get() call %d error: %v", i, err)
		}
		if v != "resolved" {
			t.Errorf("get() call %d = %q, want %q", i, v, "resolved")
		}
	}
	if loader.count() != 1 {
		t.Errorf("load calls = %d, want 1 (store=true must memoize)", loader.count())
	}
}

func TestSingleflightCacheDoesNotCacheWhenStoreFalse(t *testing.T) {
	t.Parallel()

	m := newSingleflightCache[string](16, time.Hour)
	loader := &countingLoader{}

	for i := range 3 {
		v, _, err := m.get("k", loader.load("unstored", false, nil))
		if err != nil {
			t.Fatalf("get() call %d error: %v", i, err)
		}
		if v != "unstored" {
			t.Errorf("get() call %d = %q, want %q", i, v, "unstored")
		}
	}
	if loader.count() != 3 {
		t.Errorf("load calls = %d, want 3 (store=false must not cache)", loader.count())
	}
}

func TestSingleflightCacheDoesNotCacheErrors(t *testing.T) {
	t.Parallel()

	m := newSingleflightCache[string](16, time.Hour)
	loader := &countingLoader{}
	boom := errors.New("boom")

	for i := range 3 {
		if _, _, err := m.get("k", loader.load("", true, boom)); !errors.Is(err, boom) {
			t.Fatalf("get() call %d error = %v, want boom", i, err)
		}
	}
	if loader.count() != 3 {
		t.Errorf("load calls = %d, want 3 (errors must not be cached)", loader.count())
	}
}

func TestSingleflightCacheReportsHit(t *testing.T) {
	t.Parallel()

	m := newSingleflightCache[string](16, time.Hour)
	loader := &countingLoader{}

	if _, hit, err := m.get("k", loader.load("resolved", true, nil)); err != nil || hit {
		t.Fatalf("first get() hit = %v, err = %v; want hit=false (miss) with no error", hit, err)
	}
	if _, hit, err := m.get("k", loader.load("resolved", true, nil)); err != nil || !hit {
		t.Fatalf("second get() hit = %v, err = %v; want hit=true (served from cache)", hit, err)
	}
}

func TestSingleflightCacheConcurrentSingleLoad(t *testing.T) {
	t.Parallel()

	m := newSingleflightCache[string](16, time.Hour)

	const goroutines = 32
	// arrived signals the leader has entered the load; release unblocks it so
	// all followers are parked in singleflight before it returns.
	arrived := make(chan struct{}, 1)
	release := make(chan struct{})

	var calls int
	var mu sync.Mutex
	// The error result is always nil here; the signature matches the loader
	// contract get expects, and this test exercises the success path only.
	loader := func() (string, bool, error) { //nolint:unparam // signature fixed by singleflightCache.get's load parameter
		mu.Lock()
		calls++
		mu.Unlock()
		select {
		case arrived <- struct{}{}:
		default:
		}
		<-release
		return "resolved", true, nil
	}

	var wg sync.WaitGroup
	results := make([]string, goroutines)
	errs := make([]error, goroutines)
	wg.Add(goroutines)
	for i := range goroutines {
		go func(idx int) {
			defer wg.Done()
			results[idx], _, errs[idx] = m.get("k", loader)
		}(i)
	}

	<-arrived
	close(release)
	wg.Wait()

	for i := range goroutines {
		if errs[i] != nil {
			t.Fatalf("goroutine %d error: %v", i, errs[i])
		}
		if results[i] != "resolved" {
			t.Errorf("goroutine %d = %q, want %q", i, results[i], "resolved")
		}
	}
	mu.Lock()
	defer mu.Unlock()
	if calls != 1 {
		t.Errorf("load calls = %d, want 1 (concurrent misses must collapse)", calls)
	}
}

func TestSingleflightCacheGenericValueType(t *testing.T) {
	t.Parallel()

	type payload struct {
		id   int
		name string
	}
	m := newSingleflightCache[payload](16, time.Hour)

	var calls int
	load := func() (payload, bool, error) {
		calls++
		return payload{id: 7, name: "seven"}, true, nil
	}

	for range 3 {
		got, _, err := m.get("k", load)
		if err != nil {
			t.Fatalf("get() error: %v", err)
		}
		if got.id != 7 || got.name != "seven" {
			t.Errorf("get() = %+v, want {7 seven}", got)
		}
	}
	if calls != 1 {
		t.Errorf("load calls = %d, want 1 (struct value must memoize)", calls)
	}
}

func TestSingleflightCacheEvictsBeyondSize(t *testing.T) {
	t.Parallel()

	m := newSingleflightCache[string](1, time.Hour)

	var mu sync.Mutex
	calls := map[string]int{}
	load := func(key, value string) func() (string, bool, error) {
		return func() (string, bool, error) {
			mu.Lock()
			calls[key]++
			mu.Unlock()
			return value, true, nil
		}
	}

	// Size 1: loading k2 evicts k1, so a re-lookup of k1 must reload.
	if _, _, err := m.get("k1", load("k1", "v1")); err != nil {
		t.Fatalf("get(k1): %v", err)
	}
	if _, _, err := m.get("k2", load("k2", "v2")); err != nil {
		t.Fatalf("get(k2): %v", err)
	}
	if _, _, err := m.get("k1", load("k1", "v1")); err != nil {
		t.Fatalf("get(k1) after eviction: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if calls["k1"] != 2 {
		t.Errorf("k1 loads = %d, want 2 (evicted then reloaded)", calls["k1"])
	}
}
