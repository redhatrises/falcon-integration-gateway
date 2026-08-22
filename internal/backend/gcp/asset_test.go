package gcp

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// fakeResolver returns a canned set of matching resource names (or an error) for
// every lookup and records how many times it was called and the last
// (project, instance) it was asked for. Under the targeted seam the resolver
// already filters by instance id server-side, so a test controls the 0/1/many
// outcome purely by how many names it seeds. It is not safe for concurrent use;
// concurrent tests use blockingResolver or countingResolver instead.
type fakeResolver struct {
	names       []string
	err         error
	calls       int
	gotProject  string
	gotInstance string
}

// latencyResolver simulates a targeted GCE aggregatedList lookup: each call
// filters server-side by one instance id, so it sleeps a fixed per-lookup
// duration and returns that instance's single resource name. It counts calls so
// a benchmark can report how many lookups a workload triggered.
type latencyResolver struct {
	lookupLatency time.Duration
	calls         atomic.Int64
}

func (r *latencyResolver) resolveInstance(ctx context.Context, _, instanceID string) ([]string, error) {
	r.calls.Add(1)
	select {
	case <-time.After(r.lookupLatency):
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	return []string{"//compute.googleapis.com/projects/p/zones/z/instances/i-" + instanceID}, nil
}

// BenchmarkAssetResolveConcurrentInstances resolves many distinct instances in a
// single project concurrently. Each distinct instance is its own targeted
// lookup, so the workload legitimately issues one lookup per instance — the
// benchmark's purpose is to prove those lookups run concurrently rather than
// serializing behind a shared lock: the reported ms/op should track a single
// lookup's latency, not the sum across all instances. It also reports lookups/op
// (expected ~instancesPerProject, since distinct keys do not collapse).
func BenchmarkAssetResolveConcurrentInstances(b *testing.B) {
	const instancesPerProject = 64
	const lookupLatency = 1 * time.Millisecond

	var totalLookups int64
	for range b.N {
		resolver := &latencyResolver{lookupLatency: lookupLatency}
		c := newAssetCache(resolver, defaultAssetCacheSize)

		var wg sync.WaitGroup
		wg.Add(instancesPerProject)
		for i := range instancesPerProject {
			id := strconv.Itoa(i)
			go func() {
				defer wg.Done()
				if _, err := c.resourceName(context.Background(), "proj", id); err != nil {
					b.Errorf("resourceName(%s): %v", id, err)
				}
			}()
		}
		wg.Wait()
		totalLookups += resolver.calls.Load()
	}
	b.ReportMetric(float64(totalLookups)/float64(b.N), "lookups/op")
}

func (f *fakeResolver) resolveInstance(_ context.Context, projectNumber, instanceID string) ([]string, error) {
	f.calls++
	f.gotProject = projectNumber
	f.gotInstance = instanceID
	return f.names, f.err
}

// countingResolver serves a fixed per-key result and counts calls per
// (project, instance) key, so eviction tests can prove an evicted entry triggers
// a re-lookup of that key. It is safe for concurrent use.
type countingResolver struct {
	mu    sync.Mutex
	names map[string][]string
	calls map[string]int
}

func (r *countingResolver) resolveInstance(_ context.Context, projectNumber, instanceID string) ([]string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.calls == nil {
		r.calls = map[string]int{}
	}
	key := cacheKey(projectNumber, instanceID)
	r.calls[key]++
	return r.names[key], nil
}

func (r *countingResolver) callCount(projectNumber, instanceID string) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.calls[cacheKey(projectNumber, instanceID)]
}

func TestAssetCacheResourceName(t *testing.T) {
	t.Parallel()

	t.Run("single match resolves and caches", func(t *testing.T) {
		t.Parallel()
		const name = "//compute.googleapis.com/projects/p/zones/z/instances/i"
		resolver := &fakeResolver{names: []string{name}}
		c := newAssetCache(resolver, defaultAssetCacheSize)

		got, err := c.resourceName(context.Background(), "42", "9876543210")
		if err != nil {
			t.Fatalf("resourceName: unexpected error %v", err)
		}
		if got != name {
			t.Errorf("resourceName = %q, want %q", got, name)
		}

		if _, err := c.resourceName(context.Background(), "42", "9876543210"); err != nil {
			t.Fatalf("second resourceName: unexpected error %v", err)
		}
		if resolver.calls != 1 {
			t.Errorf("resolver calls = %d, want 1 (result should be cached)", resolver.calls)
		}
		if resolver.gotProject != "42" || resolver.gotInstance != "9876543210" {
			t.Errorf("resolver looked up (%q, %q), want (%q, %q)", resolver.gotProject, resolver.gotInstance, "42", "9876543210")
		}
	})

	t.Run("distinct keys resolve independently and cache", func(t *testing.T) {
		t.Parallel()
		resolver := &countingResolver{names: map[string][]string{
			cacheKey("p", "111"): {"//compute/instances/a"},
			cacheKey("p", "222"): {"//compute/instances/b"},
		}}
		c := newAssetCache(resolver, defaultAssetCacheSize)

		a, err := c.resourceName(context.Background(), "p", "111")
		if err != nil || a != "//compute/instances/a" {
			t.Fatalf("resourceName(111) = (%q, %v), want (//compute/instances/a, nil)", a, err)
		}
		b, err := c.resourceName(context.Background(), "p", "222")
		if err != nil || b != "//compute/instances/b" {
			t.Fatalf("resourceName(222) = (%q, %v), want (//compute/instances/b, nil)", b, err)
		}
		// Each key was looked up exactly once; a repeat lookup is a cache hit.
		if _, err := c.resourceName(context.Background(), "p", "111"); err != nil {
			t.Fatalf("repeat resourceName(111): %v", err)
		}
		if got := resolver.callCount("p", "111"); got != 1 {
			t.Errorf("lookups for 111 = %d, want 1 (cached)", got)
		}
		if got := resolver.callCount("p", "222"); got != 1 {
			t.Errorf("lookups for 222 = %d, want 1", got)
		}
	})

	t.Run("identical instance id in different projects does not collide", func(t *testing.T) {
		t.Parallel()
		resolver := &countingResolver{names: map[string][]string{
			cacheKey("p1", "dup"): {"//compute/p1/instances/i"},
			cacheKey("p2", "dup"): {"//compute/p2/instances/i"},
		}}
		c := newAssetCache(resolver, defaultAssetCacheSize)

		got1, err := c.resourceName(context.Background(), "p1", "dup")
		if err != nil || got1 != "//compute/p1/instances/i" {
			t.Fatalf("resourceName(p1/dup) = (%q, %v), want (//compute/p1/instances/i, nil)", got1, err)
		}
		got2, err := c.resourceName(context.Background(), "p2", "dup")
		if err != nil || got2 != "//compute/p2/instances/i" {
			t.Fatalf("resourceName(p2/dup) = (%q, %v), want (//compute/p2/instances/i, nil)", got2, err)
		}
	})

	t.Run("zero matches returns ErrAssetNotFound", func(t *testing.T) {
		t.Parallel()
		resolver := &fakeResolver{}
		c := newAssetCache(resolver, defaultAssetCacheSize)

		_, err := c.resourceName(context.Background(), "99", "missing")
		if !errors.Is(err, ErrAssetNotFound) {
			t.Errorf("error = %v, want ErrAssetNotFound", err)
		}
	})

	t.Run("multiple matches returns ErrMultipleAssets", func(t *testing.T) {
		t.Parallel()
		resolver := &fakeResolver{names: []string{"a", "b"}}
		c := newAssetCache(resolver, defaultAssetCacheSize)

		_, err := c.resourceName(context.Background(), "7", "dup")
		if !errors.Is(err, ErrMultipleAssets) {
			t.Errorf("error = %v, want ErrMultipleAssets", err)
		}
		if errors.Is(err, ErrAssetNotFound) {
			t.Errorf("error = %v, want a non-AssetNotFound error", err)
		}
		if !strings.Contains(err.Error(), "dup") || !strings.Contains(err.Error(), "7") {
			t.Errorf("error = %q, want it to name the instance (dup) and project (7)", err)
		}
	})

	t.Run("resolver error propagates and is not cached", func(t *testing.T) {
		t.Parallel()
		boom := errors.New("boom")
		resolver := &fakeResolver{err: boom}
		c := newAssetCache(resolver, defaultAssetCacheSize)

		if _, err := c.resourceName(context.Background(), "42", "x"); !errors.Is(err, boom) {
			t.Fatalf("error = %v, want boom", err)
		}

		resolver.err = nil
		resolver.names = []string{"resolved"}
		got, err := c.resourceName(context.Background(), "42", "x")
		if err != nil {
			t.Fatalf("retry resourceName: unexpected error %v", err)
		}
		if got != "resolved" {
			t.Errorf("resourceName = %q, want %q", got, "resolved")
		}
		if resolver.calls != 2 {
			t.Errorf("resolver calls = %d, want 2 (failed lookup must not be cached)", resolver.calls)
		}
	})

	t.Run("permission denial is not cached and self-heals", func(t *testing.T) {
		t.Parallel()
		resolver := &fakeResolver{err: ErrAssetPermissionDenied}
		c := newAssetCache(resolver, defaultAssetCacheSize)

		if _, err := c.resourceName(context.Background(), "42", "x"); !errors.Is(err, ErrAssetPermissionDenied) {
			t.Fatalf("error = %v, want ErrAssetPermissionDenied", err)
		}

		// Once the grant lands the next lookup resolves: a denied lookup must not
		// poison the key.
		resolver.err = nil
		resolver.names = []string{"resolved"}
		got, err := c.resourceName(context.Background(), "42", "x")
		if err != nil {
			t.Fatalf("post-grant resourceName: unexpected error %v", err)
		}
		if got != "resolved" {
			t.Errorf("resourceName = %q, want %q", got, "resolved")
		}
		if resolver.calls != 2 {
			t.Errorf("resolver calls = %d, want 2 (denial must not be cached)", resolver.calls)
		}
	})
}

func TestAssetCacheEviction(t *testing.T) {
	t.Parallel()

	resolver := &countingResolver{names: map[string][]string{
		cacheKey("p1", "i1"): {"name-i1"},
		cacheKey("p2", "i2"): {"name-i2"},
		cacheKey("p3", "i3"): {"name-i3"},
	}}
	c := newAssetCache(resolver, 2)
	ctx := context.Background()

	resolve := func(project, id string) {
		t.Helper()
		got, err := c.resourceName(ctx, project, id)
		if err != nil {
			t.Fatalf("resourceName(%s/%s): %v", project, id, err)
		}
		if want := "name-" + id; got != want {
			t.Fatalf("resourceName(%s/%s) = %q, want %q", project, id, got, want)
		}
	}

	// Fill to capacity, then overflow: p3/i3 evicts the oldest entry, p1/i1.
	resolve("p1", "i1")
	resolve("p2", "i2")
	resolve("p3", "i3")

	// p2 and p3 are still hot: re-lookups hit the cache, no re-resolve.
	resolve("p2", "i2")
	resolve("p3", "i3")

	// p1/i1 was evicted: a re-lookup must re-resolve it (and in turn evict p2/i2).
	resolve("p1", "i1")

	if got := resolver.callCount("p1", "i1"); got != 2 {
		t.Errorf("p1/i1 lookups = %d, want 2 (evicted then re-resolved)", got)
	}
	if got := resolver.callCount("p2", "i2"); got != 1 {
		t.Errorf("p2/i2 lookups = %d, want 1 (stayed cached across the overflow)", got)
	}
	if got := resolver.callCount("p3", "i3"); got != 1 {
		t.Errorf("p3/i3 lookups = %d, want 1", got)
	}
}

// blockingResolver holds its first lookup open until released, so a test can pile
// concurrent callers onto the single-flight before the lookup completes. It
// counts calls atomically and returns a fixed result.
type blockingResolver struct {
	names   []string
	calls   atomic.Int64
	entered chan struct{}
	release chan struct{}
	once    sync.Once
}

func (r *blockingResolver) resolveInstance(ctx context.Context, _, _ string) ([]string, error) {
	r.calls.Add(1)
	r.once.Do(func() { close(r.entered) })
	select {
	case <-r.release:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	return r.names, nil
}

// TestAssetCacheConcurrentSameKeyCollapses proves concurrent misses for the same
// (project, instance) key collapse into a single lookup: the lookup is held open
// until every caller has piled onto the single-flight, so all resolve from one
// call. It also exercises the cache under -race.
func TestAssetCacheConcurrentSameKeyCollapses(t *testing.T) {
	t.Parallel()

	const callers = 16
	const name = "//compute.googleapis.com/projects/p/zones/z/instances/i"
	resolver := &blockingResolver{
		names:   []string{name},
		entered: make(chan struct{}),
		release: make(chan struct{}),
	}
	c := newAssetCache(resolver, defaultAssetCacheSize)

	var ready sync.WaitGroup
	ready.Add(callers)
	var done sync.WaitGroup
	done.Add(callers)
	// arrived counts callers that have begun their lookup; allArrived closes once
	// every caller has, giving a deterministic release signal in place of a
	// wall-clock guess that they have piled onto the single-flight.
	var arrived atomic.Int64
	var arrivedOnce sync.Once
	allArrived := make(chan struct{})
	errs := make([]error, callers)
	got := make([]string, callers)
	for i := range callers {
		go func(idx int) {
			defer done.Done()
			ready.Done()
			if arrived.Add(1) == callers {
				arrivedOnce.Do(func() { close(allArrived) })
			}
			got[idx], errs[idx] = c.resourceName(context.Background(), "p", "9876543210")
		}(i)
	}

	// Release the held lookup only after every goroutine has begun its lookup and
	// the first has entered the single call, so the rest collapse onto the
	// single-flight rather than starting a second lookup.
	ready.Wait()
	<-resolver.entered
	<-allArrived
	close(resolver.release)
	done.Wait()

	for i := range callers {
		if errs[i] != nil {
			t.Fatalf("caller %d: %v", i, errs[i])
		}
		if got[i] != name {
			t.Errorf("caller %d resolved %q, want %q", i, got[i], name)
		}
	}
	if n := resolver.calls.Load(); n != 1 {
		t.Errorf("lookups = %d, want 1 (concurrent misses for one key must collapse)", n)
	}
}
