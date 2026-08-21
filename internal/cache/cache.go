// Package cache provides a concurrency-safe, double-checked memoization cache
// with optional insertion-order (FIFO) eviction. It is dependency-free (stdlib
// only) so any package may depend on it; it is used by backends that memoize
// per-key lookups resolved over the network (for example region-by-account and
// asset-by-instance resolution).
package cache

import (
	"context"
	"sync"
)

// Cache is a concurrency-safe, double-checked memoization cache keyed by K. A
// hit takes only a read lock; a miss upgrades to the write lock, re-checks, then
// invokes the caller's loader once — so concurrent misses for the same key
// collapse into a single load — and stores a successful result. Failed loads are
// not cached, so a transient error never permanently poisons a key.
//
// When maxEntries > 0 the cache is bounded with insertion-order (FIFO) eviction:
// an entry overflowing the cap evicts the oldest-inserted one. maxEntries <= 0
// leaves the cache unbounded. Recency is deliberately not tracked so that a hit
// stays on the read lock; FIFO assumes the active working set fits within the
// cap, and evicting an in-use entry costs only a correct re-load, never a wrong
// answer.
//
// The loader is supplied per call rather than stored, so a single cache can
// serve keys whose resolution depends on extra per-call context (an asset cache
// keys on instance id but its loader also needs the project number).
type Cache[K comparable, V any] struct {
	maxEntries int

	mu      sync.RWMutex
	entries map[K]V
	order   []K // insertion order for FIFO eviction; unused when unbounded
}

// New returns an empty cache. maxEntries <= 0 leaves it unbounded; otherwise the
// cache is bounded to maxEntries with FIFO eviction.
func New[K comparable, V any](maxEntries int) *Cache[K, V] {
	return &Cache[K, V]{
		maxEntries: maxEntries,
		entries:    make(map[K]V),
	}
}

// Get returns the cached value for key, or invokes load exactly once to resolve
// it. load runs under the write lock, so concurrent misses for key collapse into
// a single call; a successful result is cached and an error is returned without
// caching.
func (c *Cache[K, V]) Get(ctx context.Context, key K, load func(context.Context) (V, error)) (V, error) {
	c.mu.RLock()
	v, ok := c.entries[key]
	c.mu.RUnlock()
	if ok {
		return v, nil
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	if v, ok := c.entries[key]; ok {
		return v, nil
	}

	v, err := load(ctx)
	if err != nil {
		var zero V
		return zero, err
	}
	c.storeLocked(key, v)
	return v, nil
}

// storeLocked memoizes value for key and, when bounded, records insertion order
// and evicts the oldest entry on overflow. The double-checked Get guarantees a
// key reaches here at most once, so order and entries stay in step. The caller
// must hold c.mu for writing.
func (c *Cache[K, V]) storeLocked(key K, value V) {
	c.entries[key] = value
	if c.maxEntries <= 0 {
		return
	}
	c.order = append(c.order, key)
	if len(c.order) > c.maxEntries {
		oldest := c.order[0]
		delete(c.entries, oldest)
		c.order = c.order[1:]
	}
}
