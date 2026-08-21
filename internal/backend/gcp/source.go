package gcp

import (
	"context"

	"github.com/crowdstrike/falcon-integration-gateway/internal/cache"
)

// figSourceName is the display name of the single SCC Source under which every
// forwarded detection is recorded, matching the Python backend.
const figSourceName = "CrowdStrike Falcon"

// figSourceDescription is the SCC Source description set on creation.
const figSourceDescription = "CrowdStrike Falcon findings forwarded by falcon-integration-gateway"

// createSourceInput carries the values needed to create the FIG SCC Source
// under an organization. It is declared here so the seam and its callers share
// one shape.
type createSourceInput struct {
	orgID       string
	displayName string
	description string
}

// sourceClient is the seam over the SCC Source API. findSource returns the
// resource name of the existing FIG source under the organization, or "" when
// none exists yet. createSource creates it and returns its resource name.
// Returning plain strings keeps the seam free of google protobuf types so tests
// inject fakes without a live SCC endpoint.
type sourceClient interface {
	findSource(ctx context.Context, orgID, displayName string) (string, error)
	createSource(ctx context.Context, in createSourceInput) (string, error)
}

// sourceCache resolves the FIG SCC Source resource name for an organization,
// get-or-creating it once and memoizing the result. It is safe for concurrent
// use by worker goroutines: concurrent callers for the same organization
// collapse into a single find-or-create, so a source is created at most once per
// organization, mirroring the Python backend's module-level source lock.
type sourceCache struct {
	client sourceClient
	cache  *cache.Cache[string, string]
}

// get returns the FIG SCC Source resource name for orgID, resolving it on first
// use via a find-or-create.
func (c *sourceCache) get(ctx context.Context, orgID string) (string, error) {
	return c.cache.Get(ctx, orgID, func(ctx context.Context) (string, error) {
		name, err := c.client.findSource(ctx, orgID, figSourceName)
		if err != nil {
			return "", err
		}
		if name == "" {
			name, err = c.client.createSource(ctx, createSourceInput{
				orgID:       orgID,
				displayName: figSourceName,
				description: figSourceDescription,
			})
			if err != nil {
				return "", err
			}
		}
		return name, nil
	})
}
