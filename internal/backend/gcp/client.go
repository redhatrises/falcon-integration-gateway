package gcp

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	resourcemanager "cloud.google.com/go/resourcemanager/apiv3"
	securitycenter "cloud.google.com/go/securitycenter/apiv1"
	"cloud.google.com/go/securitycenter/apiv1/securitycenterpb"
	"google.golang.org/api/iterator"

	"github.com/crowdstrike/falcon-integration-gateway/internal/backend"
	"github.com/crowdstrike/falcon-integration-gateway/internal/cache"
	"github.com/crowdstrike/falcon-integration-gateway/internal/config"
)

// sccAdapter adapts the Security Command Center v1 client to the three narrow
// seams the backend consumes: Source get-or-create, asset lookup, and Finding
// get-or-create. It projects the protobuf responses down to the plain strings
// and payloads the caches and submitter expect, keeping google protobuf types
// out of those units.
type sccAdapter struct {
	client *securitycenter.Client
}

var (
	_ sourceClient  = (*sccAdapter)(nil)
	_ assetLister   = (*sccAdapter)(nil)
	_ findingClient = (*sccAdapter)(nil)
)

// findSource returns the resource name of the FIG Source whose display name
// matches under the organization, or "" when no such Source exists yet. It
// mirrors the Python get_fig_source scan over ListSources.
func (a *sccAdapter) findSource(ctx context.Context, orgID, displayName string) (string, error) {
	it := a.client.ListSources(ctx, &securitycenterpb.ListSourcesRequest{
		Parent: organizationPrefix + orgID,
	})
	for {
		src, err := it.Next()
		if errors.Is(err, iterator.Done) {
			return "", nil
		}
		if err != nil {
			return "", err
		}
		if src.GetDisplayName() == displayName {
			return src.GetName(), nil
		}
	}
}

// createSource creates the FIG Source under the organization and returns its
// resource name.
func (a *sccAdapter) createSource(ctx context.Context, in createSourceInput) (string, error) {
	src, err := a.client.CreateSource(ctx, &securitycenterpb.CreateSourceRequest{
		Parent: organizationPrefix + in.orgID,
		Source: &securitycenterpb.Source{
			DisplayName: in.displayName,
			Description: in.description,
		},
	})
	if err != nil {
		return "", err
	}
	return src.GetName(), nil
}

// listAssetResourceNames returns the SCC resource names of the assets whose
// numeric instance id matches within the project, mirroring the Python get_asset
// ListAssets call filtered by resource_properties.id.
func (a *sccAdapter) listAssetResourceNames(ctx context.Context, projectNumber, instanceID string) ([]string, error) {
	it := a.client.ListAssets(ctx, &securitycenterpb.ListAssetsRequest{ //nolint:staticcheck // SCC v1 ListAssets is deprecated but still functional; migration to Cloud Asset Inventory is tracked in docs/reviews/FOLLOWUP-gcp-asset-api-migration.md
		Parent: projectPrefix + projectNumber,
		Filter: fmt.Sprintf("resource_properties.id=%q", instanceID),
	})
	var names []string
	for {
		res, err := it.Next()
		if errors.Is(err, iterator.Done) {
			return names, nil
		}
		if err != nil {
			return nil, err
		}
		names = append(names, res.GetAsset().GetSecurityCenterProperties().GetResourceName())
	}
}

// findingExists reports whether a finding with findingName already exists under
// the source, mirroring the Python get_finding ListFindings filter by name.
func (a *sccAdapter) findingExists(ctx context.Context, source, findingName string) (bool, error) {
	it := a.client.ListFindings(ctx, &securitycenterpb.ListFindingsRequest{
		Parent: source,
		Filter: fmt.Sprintf("name=%q", findingName),
	})
	if _, err := it.Next(); err != nil {
		if errors.Is(err, iterator.Done) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

// createFinding creates one Finding under the source. The raw gRPC error is
// surfaced so the submitter can classify AlreadyExists.
func (a *sccAdapter) createFinding(ctx context.Context, in findingCreateInput) error {
	_, err := a.client.CreateFinding(ctx, &securitycenterpb.CreateFindingRequest{
		Parent:    in.source,
		FindingId: in.findingID,
		Finding:   in.finding,
	})
	return err
}

// New is the backend.Constructor. It builds the Security Command Center client
// and the resource-manager clients used for the project→folder→organization
// walk from Google Application Default Credentials, then wires them behind the
// per-event caches. The one-time startup work uses a background context because
// the constructor signature has no context to thread. GCP takes no gateway
// configuration, so cfg is unused. Returning an error aborts startup.
func New(_ *config.Config, logger *slog.Logger) (backend.Backend, error) {
	ctx := context.Background()

	sccClient, err := securitycenter.NewClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("gcp: creating Security Command Center client: %w", err)
	}
	projects, err := resourcemanager.NewProjectsClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("gcp: creating resource-manager projects client: %w", err)
	}
	folders, err := resourcemanager.NewFoldersClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("gcp: creating resource-manager folders client: %w", err)
	}

	rm := &sdkResourceManager{projects: projects, folders: folders}
	scc := &sccAdapter{client: sccClient}

	logger.Info("GCP Security Command Center backend is enabled.")
	return &Runtime{
		orgs:      &orgCache{resolver: &hierarchyResolver{rm: rm}, cache: cache.New[string, string](0)},
		sources:   &sourceCache{client: scc, cache: cache.New[string, string](0)},
		assets:    newAssetCache(scc, defaultAssetCacheSize),
		submitter: &findingSubmitter{client: scc},
		logger:    logger,
	}, nil
}

func init() {
	backend.Register(backendName, New)
}
