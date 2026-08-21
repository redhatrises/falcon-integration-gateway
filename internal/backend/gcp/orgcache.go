package gcp

import (
	"context"

	"github.com/crowdstrike/falcon-integration-gateway/internal/cache"
)

// orgResolver is the seam over the project→folder→org hierarchy walk. It maps a
// GCP project number to its enclosing organization id. Keeping it a single-method
// interface lets tests inject a fake without a live resourcemanager endpoint.
type orgResolver interface {
	resolve(ctx context.Context, projectNumber string) (string, error)
}

// orgCache resolves the enclosing organization id for a GCP project number,
// walking the hierarchy once per project and memoizing the result. It is safe
// for concurrent use: concurrent lookups for the same project collapse into a
// single walk, and failed lookups are not cached, so a transient IAM error does
// not permanently poison a project.
type orgCache struct {
	resolver orgResolver
	cache    *cache.Cache[string, string]
}

// get returns the organization id enclosing projectNumber, resolving it on first
// use.
func (c *orgCache) get(ctx context.Context, projectNumber string) (string, error) {
	return c.cache.Get(ctx, projectNumber, func(ctx context.Context) (string, error) {
		return c.resolver.resolve(ctx, projectNumber)
	})
}
