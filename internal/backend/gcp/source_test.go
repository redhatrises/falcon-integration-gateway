package gcp

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/crowdstrike/falcon-integration-gateway/internal/cache"
)

// fakeSourceClient is a hermetic stand-in for the SCC source seam. It serves a
// pre-existing source per org when configured, otherwise records a create and
// returns a synthesized source name. All counters are mutex-guarded so the
// concurrency test stays race-clean.
type fakeSourceClient struct {
	mu          sync.Mutex
	existing    map[string]string
	findErr     error
	createErr   error
	findCalls   int
	createCalls int
	lastCreate  createSourceInput
}

func (f *fakeSourceClient) findSource(_ context.Context, orgID, _ string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.findCalls++
	if f.findErr != nil {
		return "", f.findErr
	}
	return f.existing[orgID], nil
}

func (f *fakeSourceClient) createSource(_ context.Context, in createSourceInput) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.createCalls++
	f.lastCreate = in
	if f.createErr != nil {
		return "", f.createErr
	}
	name := "organizations/" + in.orgID + "/sources/created"
	if f.existing == nil {
		f.existing = map[string]string{}
	}
	f.existing[in.orgID] = name
	return name, nil
}

func newSourceCache(client sourceClient) *sourceCache {
	return &sourceCache{client: client, cache: cache.New[string, string](0)}
}

func TestSourceCacheReturnsExisting(t *testing.T) {
	t.Parallel()
	client := &fakeSourceClient{existing: map[string]string{"42": "organizations/42/sources/existing"}}
	sc := newSourceCache(client)

	got, err := sc.get(context.Background(), "42")
	if err != nil {
		t.Fatalf("get() unexpected error: %v", err)
	}
	if got != "organizations/42/sources/existing" {
		t.Errorf("get() = %q, want existing source", got)
	}
	if client.createCalls != 0 {
		t.Errorf("createCalls = %d, want 0 (source already exists)", client.createCalls)
	}
}

func TestSourceCacheCreatesWhenAbsent(t *testing.T) {
	t.Parallel()
	client := &fakeSourceClient{}
	sc := newSourceCache(client)

	got, err := sc.get(context.Background(), "42")
	if err != nil {
		t.Fatalf("get() unexpected error: %v", err)
	}
	if got != "organizations/42/sources/created" {
		t.Errorf("get() = %q, want created source", got)
	}
	if client.createCalls != 1 {
		t.Errorf("createCalls = %d, want 1", client.createCalls)
	}
}

func TestSourceCacheMemoizes(t *testing.T) {
	t.Parallel()
	client := &fakeSourceClient{}
	sc := newSourceCache(client)

	for i := range 3 {
		if _, err := sc.get(context.Background(), "42"); err != nil {
			t.Fatalf("get() call %d unexpected error: %v", i, err)
		}
	}
	if client.findCalls != 1 {
		t.Errorf("findCalls = %d, want 1 (subsequent gets served from cache)", client.findCalls)
	}
	if client.createCalls != 1 {
		t.Errorf("createCalls = %d, want 1", client.createCalls)
	}
}

func TestSourceCacheFindErrorPropagates(t *testing.T) {
	t.Parallel()
	client := &fakeSourceClient{findErr: errors.New("permission denied")}
	sc := newSourceCache(client)

	if _, err := sc.get(context.Background(), "42"); err == nil {
		t.Fatal("get() = nil error, want find error propagated")
	}
}

func TestSourceCacheCreateErrorPropagates(t *testing.T) {
	t.Parallel()
	client := &fakeSourceClient{createErr: errors.New("permission denied")}
	sc := newSourceCache(client)

	if _, err := sc.get(context.Background(), "42"); err == nil {
		t.Fatal("get() = nil error, want create error propagated")
	}
}

func TestSourceCachePassesSourceMetadata(t *testing.T) {
	t.Parallel()
	client := &fakeSourceClient{}
	sc := newSourceCache(client)

	if _, err := sc.get(context.Background(), "42"); err != nil {
		t.Fatalf("get() unexpected error: %v", err)
	}
	if client.lastCreate.orgID != "42" {
		t.Errorf("createSource orgID = %q, want %q", client.lastCreate.orgID, "42")
	}
	if client.lastCreate.displayName != figSourceName {
		t.Errorf("createSource displayName = %q, want %q", client.lastCreate.displayName, figSourceName)
	}
	if client.lastCreate.description != figSourceDescription {
		t.Errorf("createSource description = %q, want %q", client.lastCreate.description, figSourceDescription)
	}
}

func TestSourceCacheConcurrentSingleCreate(t *testing.T) {
	t.Parallel()
	client := &fakeSourceClient{}
	sc := newSourceCache(client)

	const goroutines = 32
	var wg sync.WaitGroup
	results := make([]string, goroutines)
	errs := make([]error, goroutines)
	wg.Add(goroutines)
	for i := range goroutines {
		go func(idx int) {
			defer wg.Done()
			results[idx], errs[idx] = sc.get(context.Background(), "42")
		}(i)
	}
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Fatalf("goroutine %d unexpected error: %v", i, err)
		}
		if results[i] != "organizations/42/sources/created" {
			t.Errorf("goroutine %d got %q, want created source", i, results[i])
		}
	}
	if client.createCalls != 1 {
		t.Errorf("createCalls = %d, want exactly 1 under concurrency", client.createCalls)
	}
}
