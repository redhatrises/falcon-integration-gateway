package gcp

import (
	"context"
	"errors"
	"fmt"

	"github.com/crowdstrike/falcon-integration-gateway/internal/cache"
)

// defaultAssetCacheSize bounds the number of memoized instance-id -> resource
// name entries the asset cache retains. Across a large, churning fleet the
// lookup is genuinely reused per instance, so the cache must persist entries
// (unlike a per-event dedup), but capping it keeps memory bounded for the
// process lifetime. The mappings are tiny (two short strings), so a few
// thousand entries is negligible memory while covering a large active fleet.
const defaultAssetCacheSize = 4096

// ErrAssetNotFound is returned when the SCC asset lookup finds no asset for an
// instance id. Process treats it as a drop (log and advance) rather than a
// delivery failure.
var ErrAssetNotFound = errors.New("gcp: asset not found")

// assetLister is the seam over the SCC asset lookup. It returns the resource
// names of the assets whose numeric instance id matches instanceID within the
// project, via an SCC ListAssets call filtered by resource_properties.id.
// Returning plain strings keeps google protobuf types
// out of the seam so tests inject fakes without a live SCC endpoint.
type assetLister interface {
	listAssetResourceNames(ctx context.Context, projectNumber, instanceID string) ([]string, error)
}

// assetCache resolves the SCC resource name for a host's numeric instance id,
// looking it up once per instance id and memoizing the result. It is safe for
// concurrent use: concurrent lookups for the same instance collapse into a
// single call. Failed lookups (including ErrAssetNotFound) are not cached, so a
// transient error does not permanently poison an instance.
//
// The cache is bounded with insertion-order (FIFO) eviction; see cache for the
// eviction contract. The instance-id -> name mapping is immutable, so evicting a
// still-in-use entry only costs a correct re-fetch, never a wrong answer.
type assetCache struct {
	client assetLister
	cache  *cache.Cache[string, string]
}

// newAssetCache returns an assetCache over client, bounded to maxEntries entries
// with FIFO eviction. A maxEntries <= 0 falls back to defaultAssetCacheSize;
// the cache is always bounded.
func newAssetCache(client assetLister, maxEntries int) *assetCache {
	if maxEntries <= 0 {
		maxEntries = defaultAssetCacheSize
	}
	return &assetCache{
		client: client,
		cache:  cache.New[string, string](maxEntries),
	}
}

// resourceName returns the SCC resource name for instanceID within
// projectNumber, resolving it on first use. Exactly one matching asset is
// required: zero yields ErrAssetNotFound and more than one yields an error. The
// lookup is keyed on instanceID alone; projectNumber scopes the underlying list
// call and appears in the not-found and ambiguity errors.
func (c *assetCache) resourceName(ctx context.Context, projectNumber, instanceID string) (string, error) {
	return c.cache.Get(ctx, instanceID, func(ctx context.Context) (string, error) {
		names, err := c.client.listAssetResourceNames(ctx, projectNumber, instanceID)
		if err != nil {
			return "", err
		}
		switch len(names) {
		case 1:
			return names[0], nil
		case 0:
			return "", fmt.Errorf("%w: instance %s in project %s", ErrAssetNotFound, instanceID, projectNumber)
		default:
			return "", fmt.Errorf("gcp: multiple assets found for instance %s in project %s", instanceID, projectNumber)
		}
	})
}
