package gcp

import (
	"context"
	"fmt"
	"strings"

	resourcemanager "cloud.google.com/go/resourcemanager/apiv3"
	"cloud.google.com/go/resourcemanager/apiv3/resourcemanagerpb"
)

const (
	organizationPrefix = "organizations/"
	folderPrefix       = "folders/"
	projectPrefix      = "projects/"
)

// maxFolderDepth bounds the folder walk so a cyclic or unexpectedly deep
// hierarchy cannot loop forever.
const maxFolderDepth = 64

// resourceManager resolves the parent of a project or folder in the GCP
// resource hierarchy. It is a narrow seam over the resource-manager clients so
// the org walk can be exercised without live GCP.
type resourceManager interface {
	ProjectParent(ctx context.Context, name string) (string, error)
	FolderParent(ctx context.Context, name string) (string, error)
}

// resolveOrg walks the GCP resource hierarchy upward from a project number to
// its enclosing organization id. A project's parent is either an organization
// (walk done) or a folder; folders are followed until an organization is
// reached. A parent of any other type is unexpected and reported as an error.
func resolveOrg(ctx context.Context, rm resourceManager, projectNumber string) (string, error) {
	parent, err := rm.ProjectParent(ctx, projectPrefix+projectNumber)
	if err != nil {
		return "", fmt.Errorf("gcp: resolve parent of project %s: %w", projectNumber, err)
	}

	for range maxFolderDepth {
		switch {
		case strings.HasPrefix(parent, organizationPrefix):
			return strings.TrimPrefix(parent, organizationPrefix), nil
		case strings.HasPrefix(parent, folderPrefix):
			current := parent
			parent, err = rm.FolderParent(ctx, current)
			if err != nil {
				return "", fmt.Errorf("gcp: resolve parent of %s: %w", current, err)
			}
		default:
			return "", fmt.Errorf("gcp: project %s: unrecognized parent %q while resolving organization", projectNumber, parent)
		}
	}

	return "", fmt.Errorf("gcp: project %s: exceeded folder depth %d while resolving organization", projectNumber, maxFolderDepth)
}

// sdkResourceManager adapts the resource-manager SDK clients to the
// resourceManager seam by extracting the parent resource path from each
// lookup.
type sdkResourceManager struct {
	projects *resourcemanager.ProjectsClient
	folders  *resourcemanager.FoldersClient
}

var _ resourceManager = (*sdkResourceManager)(nil)

func (s *sdkResourceManager) ProjectParent(ctx context.Context, name string) (string, error) {
	project, err := s.projects.GetProject(ctx, &resourcemanagerpb.GetProjectRequest{Name: name})
	if err != nil {
		return "", err
	}
	return project.GetParent(), nil
}

func (s *sdkResourceManager) FolderParent(ctx context.Context, name string) (string, error) {
	folder, err := s.folders.GetFolder(ctx, &resourcemanagerpb.GetFolderRequest{Name: name})
	if err != nil {
		return "", err
	}
	return folder.GetParent(), nil
}

// hierarchyResolver adapts the resource-hierarchy walk to the orgResolver seam
// consumed by orgCache, so the cache is decoupled from the resolveOrg walk and
// the resource-manager clients behind it.
type hierarchyResolver struct {
	rm resourceManager
}

var _ orgResolver = (*hierarchyResolver)(nil)

func (h *hierarchyResolver) resolve(ctx context.Context, projectNumber string) (string, error) {
	return resolveOrg(ctx, h.rm, projectNumber)
}
