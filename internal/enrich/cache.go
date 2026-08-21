package enrich

import (
	"time"

	"github.com/hashicorp/golang-lru/v2/expirable"
	"golang.org/x/sync/singleflight"
)

// singleflightCache collapses concurrent lookups for the same key onto one load
// and caches the result in a bounded, expiring LRU. It is the shared machinery
// behind the host-detail, MDM-identifier, and Arc-config resolvers: each keys
// on a sensor id and wants at-most-one network round trip per key within the
// cache window, even under a burst of worker goroutines.
//
// The value type is generic but the key is always a string because
// singleflight groups on string keys and every caller keys on a sensor id.
type singleflightCache[V any] struct {
	cache *expirable.LRU[string, V]
	group singleflight.Group
}

// newSingleflightCache returns a singleflightCache whose cache holds at most
// size entries, each expiring after ttl.
func newSingleflightCache[V any](size int, ttl time.Duration) *singleflightCache[V] {
	return &singleflightCache[V]{
		cache: expirable.NewLRU[string, V](size, nil, ttl),
	}
}

// get returns the value for key, loading it at most once across concurrent
// callers. On a cache hit it returns immediately with hit=true. Otherwise it
// runs load under singleflight, re-checking the cache first so a caller that
// waited on an in-flight load sees that load's result. load returns the value,
// whether to cache it (store), and an error; get caches only when store is true
// and err is nil, so unresolved and failed lookups are never cached. hit is
// true only for a value served from the cache before load ran, letting a caller
// account for cache hits and misses without this type depending on metrics.
func (m *singleflightCache[V]) get(key string, load func() (V, bool, error)) (value V, hit bool, err error) {
	if v, ok := m.cache.Get(key); ok {
		return v, true, nil
	}

	result, err, _ := m.group.Do(key, func() (any, error) {
		if v, ok := m.cache.Get(key); ok {
			return v, nil
		}
		v, store, err := load()
		if err != nil {
			return nil, err
		}
		if store {
			m.cache.Add(key, v)
		}
		return v, nil
	})
	if err != nil {
		return value, false, err
	}
	// On the no-error path the load closure always returns a V, so the assertion
	// holds; the zero value is a harmless fallback if that ever changes.
	value, _ = result.(V)
	return value, false, nil
}
