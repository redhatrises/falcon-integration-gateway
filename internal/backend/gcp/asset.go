package gcp

import (
	"context"
	"errors"
	"fmt"

	"github.com/crowdstrike/falcon-integration-gateway/internal/cache"
	"golang.org/x/sync/singleflight"
)

// defaultAssetCacheSize bounds the number of memoized (project/instance) ->
// resource name entries the asset cache retains. Across a large, churning fleet
// the lookup is genuinely reused per instance, so the cache must persist entries
// (unlike a per-event dedup), but capping it keeps memory bounded for the
// process lifetime. The mappings are tiny (two short strings), so a few thousand
// entries is negligible memory while covering a large active fleet.
const defaultAssetCacheSize = 4096

// ErrAssetNotFound is returned when the asset lookup finds no compute instance
// for an instance id. Process treats it as a drop (log and advance) rather than
// a delivery failure.
var ErrAssetNotFound = errors.New("gcp: asset not found")

// ErrMultipleAssets is returned when the asset lookup finds more than one
// compute instance for an instance id. A GCE numeric id is unique within the
// project scope of the search, so this is not expected; it is a genuine anomaly
// that retrying cannot resolve, so Process treats it as a drop rather than a
// delivery failure.
var ErrMultipleAssets = errors.New("gcp: multiple assets found")

// ErrAssetPermissionDenied is returned when the compute instance lookup is
// rejected for lack of IAM permission. Process treats it as a drop that names
// the required role and advances the watermark, rather than a delivery failure
// that would stall the pipeline; because the denial is not cached, delivery
// self-heals on the next event once the grant lands.
var ErrAssetPermissionDenied = errors.New("gcp: asset lookup permission denied")

// assetResolver is the seam over the targeted asset lookup. resolveInstance
// returns the full SCC resource name of every compute instance in the project
// whose numeric id matches instanceID. A GCE numeric id is unique within a
// project, so a healthy lookup returns zero or one name; more than one is a
// genuine anomaly the caller reports as ambiguous. Returning plain strings keeps
// the GCP SDK types out of the seam so tests inject fakes without a live
// endpoint.
type assetResolver interface {
	resolveInstance(ctx context.Context, projectNumber, instanceID string) ([]string, error)
}

// assetCache resolves the SCC resource name for a host's numeric instance id
// with a targeted point lookup, memoizing the result. A hit serves from the
// read lock alone; a miss issues one lookup for that instance, collapsing
// concurrent misses for the same (project, instance) into a single call so a
// burst of detections on one host does not fan out into duplicate lookups.
//
// It is safe for concurrent use. The memoized value is keyed on
// projectNumber + "/" + instanceID so identical instance ids in different
// projects do not collide, and distinct keys resolve concurrently rather than
// serializing behind a shared lock.
//
// Unresolved lookups (a not-found or ambiguous instance, a permission denial, or
// any other error) are not memoized, so a transient failure never permanently
// poisons a key and a newly-created instance self-heals on the next lookup.
//
// The positive cache is bounded with insertion-order (FIFO) eviction; see cache
// for the eviction contract. The instance-id -> name mapping is immutable, so
// evicting a still-in-use entry only costs a correct re-lookup, never a wrong
// answer.
type assetCache struct {
	client assetResolver
	cache  *cache.Cache[string, string]
	group  singleflight.Group
}

// newAssetCache returns an assetCache over client, bounded to maxEntries entries
// with FIFO eviction. A maxEntries <= 0 falls back to defaultAssetCacheSize; the
// positive cache is always bounded.
func newAssetCache(client assetResolver, maxEntries int) *assetCache {
	if maxEntries <= 0 {
		maxEntries = defaultAssetCacheSize
	}
	return &assetCache{
		client: client,
		cache:  cache.New[string, string](maxEntries),
	}
}

// cacheKey scopes an instance id to its project so identical numeric ids in
// different projects do not collide in the shared positive cache.
func cacheKey(projectNumber, instanceID string) string {
	return projectNumber + "/" + instanceID
}

// resourceName returns the SCC resource name for instanceID within
// projectNumber, looking it up on first use. Exactly one matching asset is
// required: zero yields ErrAssetNotFound and more than one yields
// ErrMultipleAssets. A cache hit serves from the read lock alone; a miss issues
// one point lookup (collapsing concurrent misses for the same instance) and
// caches only an unambiguous single match.
func (c *assetCache) resourceName(ctx context.Context, projectNumber, instanceID string) (string, error) {
	key := cacheKey(projectNumber, instanceID)
	if name, ok := c.cache.Peek(key); ok {
		return name, nil
	}

	result, err, _ := c.group.Do(key, func() (any, error) {
		// A prior flight for this key may have resolved and cached the name
		// while this caller waited past its initial miss, so re-check before
		// issuing a fresh lookup.
		if name, ok := c.cache.Peek(key); ok {
			return name, nil
		}

		names, err := c.client.resolveInstance(ctx, projectNumber, instanceID)
		if err != nil {
			return nil, err
		}
		switch len(names) {
		case 1:
			c.cache.Store(key, names[0])
			return names[0], nil
		case 0:
			return nil, fmt.Errorf("%w: instance %s in project %s", ErrAssetNotFound, instanceID, projectNumber)
		default:
			return nil, fmt.Errorf("%w: instance %s in project %s", ErrMultipleAssets, instanceID, projectNumber)
		}
	})
	if err != nil {
		return "", err
	}
	name, ok := result.(string)
	if !ok {
		return "", fmt.Errorf("gcp: unexpected asset lookup result type %T", result)
	}
	return name, nil
}
