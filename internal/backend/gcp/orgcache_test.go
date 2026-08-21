package gcp

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/crowdstrike/falcon-integration-gateway/internal/cache"
)

// fakeOrgResolver stands in for the org-walk seam. It returns a configured org
// id per project number, counts calls, and can inject an error.
type fakeOrgResolver struct {
	mu     sync.Mutex
	byProj map[string]string
	err    error
	calls  int
}

func (f *fakeOrgResolver) resolve(_ context.Context, projectNumber string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	if f.err != nil {
		return "", f.err
	}
	return f.byProj[projectNumber], nil
}

func newOrgCache(resolver orgResolver) *orgCache {
	return &orgCache{resolver: resolver, cache: cache.New[string, string](0)}
}

func TestOrgCacheResolves(t *testing.T) {
	t.Parallel()
	resolver := &fakeOrgResolver{byProj: map[string]string{"123456789": "42"}}
	oc := newOrgCache(resolver)

	got, err := oc.get(context.Background(), "123456789")
	if err != nil {
		t.Fatalf("get() unexpected error: %v", err)
	}
	if got != "42" {
		t.Errorf("get() = %q, want %q", got, "42")
	}
}

func TestOrgCacheMemoizes(t *testing.T) {
	t.Parallel()
	resolver := &fakeOrgResolver{byProj: map[string]string{"123456789": "42"}}
	oc := newOrgCache(resolver)

	for i := range 3 {
		if _, err := oc.get(context.Background(), "123456789"); err != nil {
			t.Fatalf("get() call %d unexpected error: %v", i, err)
		}
	}
	if resolver.calls != 1 {
		t.Errorf("resolver.calls = %d, want 1 (subsequent gets served from cache)", resolver.calls)
	}
}

func TestOrgCacheErrorPropagates(t *testing.T) {
	t.Parallel()
	resolver := &fakeOrgResolver{err: errors.New("permission denied")}
	oc := newOrgCache(resolver)

	if _, err := oc.get(context.Background(), "123456789"); err == nil {
		t.Fatal("get() = nil error, want resolver error propagated")
	}
}

func TestOrgCacheErrorNotCached(t *testing.T) {
	t.Parallel()
	resolver := &fakeOrgResolver{err: errors.New("transient")}
	oc := newOrgCache(resolver)

	if _, err := oc.get(context.Background(), "123456789"); err == nil {
		t.Fatal("first get() = nil error, want resolver error")
	}
	resolver.mu.Lock()
	resolver.err = nil
	resolver.byProj = map[string]string{"123456789": "42"}
	resolver.mu.Unlock()

	got, err := oc.get(context.Background(), "123456789")
	if err != nil {
		t.Fatalf("second get() unexpected error: %v", err)
	}
	if got != "42" {
		t.Errorf("second get() = %q, want %q (failed lookups must not be cached)", got, "42")
	}
}

func TestOrgCacheConcurrentSingleResolve(t *testing.T) {
	t.Parallel()
	resolver := &fakeOrgResolver{byProj: map[string]string{"123456789": "42"}}
	oc := newOrgCache(resolver)

	const goroutines = 32
	var wg sync.WaitGroup
	errs := make([]error, goroutines)
	wg.Add(goroutines)
	for i := range goroutines {
		go func(idx int) {
			defer wg.Done()
			_, errs[idx] = oc.get(context.Background(), "123456789")
		}(i)
	}
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Fatalf("goroutine %d unexpected error: %v", i, err)
		}
	}
	if resolver.calls != 1 {
		t.Errorf("resolver.calls = %d, want exactly 1 under concurrency", resolver.calls)
	}
}
