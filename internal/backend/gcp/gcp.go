// Package gcp forwards Falcon detection events to Google Cloud Security Command
// Center as SCC Findings. Each detection
// is resolved to the enclosing GCP organization (via a project→folder→org walk),
// recorded under a single get-or-created SCC Source named "CrowdStrike Falcon",
// and submitted as an ACTIVE Finding.
package gcp

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"github.com/crowdstrike/falcon-integration-gateway/internal/backend"
	"github.com/crowdstrike/falcon-integration-gateway/internal/events"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// backendName is the registry key and Name() value for this backend.
const backendName = "GCP"

// detectionEventType is the only Falcon event family this backend forwards.
const detectionEventType = events.EppDetectionSummaryEventType

// gcpCloudProvider is the CloudProvider label of a host that lives in GCP; only
// such hosts have a project number that resolves to an SCC organization.
const gcpCloudProvider = "GCP"

// Runtime is the GCP Security Command Center backend. Organization ids and the
// SCC Source are resolved lazily per event and memoized, so a single run can
// forward detections from hosts across multiple GCP projects and organizations.
type Runtime struct {
	sources   *sourceCache
	orgs      *orgCache
	assets    *assetCache
	submitter *findingSubmitter
	logger    *slog.Logger
}

// Name returns the backend's registry identifier.
func (r *Runtime) Name() string {
	return backendName
}

// RelevantEventTypes narrows the server-side stream filter to detection
// summaries, the only family this backend forwards.
func (r *Runtime) RelevantEventTypes() []string {
	return []string{detectionEventType}
}

// IsRelevant reports whether the event's host lives in GCP. An enrichment
// failure is treated as relevant (fail-open): the event proceeds to Process,
// which surfaces the enrichment error so the pipeline's delivery-failure policy
// governs the outcome rather than silently dropping the detection.
func (r *Runtime) IsRelevant(ctx context.Context, ev *events.EnrichedEvent) bool {
	return events.MatchesProvider(ctx, ev, func(provider string) bool {
		return provider == gcpCloudProvider
	})
}

// resolveOrgSource resolves both the enclosing organization id and the SCC
// Source resource name under which findings for the given GCP project number are
// recorded. It chains the two per-event lookups — project number to enclosing
// organization id, then organization id to the get-or-created FIG Source — both
// memoized and concurrency-safe. The organization id is returned alongside the
// source because the submitter deduplicates findings per organization; it is
// also returned when the source lookup itself fails, so a permission-denied
// warning can name the organization that must grant access.
func (r *Runtime) resolveOrgSource(ctx context.Context, projectNumber string) (orgID, source string, err error) {
	orgID, err = r.orgs.get(ctx, projectNumber)
	if err != nil {
		return "", "", err
	}
	source, err = r.sources.get(ctx, orgID)
	if err != nil {
		return orgID, "", err
	}
	return orgID, source, nil
}

// Process forwards one detection to GCP Security Command Center as a Finding. It
// resolves the host's GCP project number, walks to the enclosing organization
// and its FIG Source, looks up the SCC resource name of the originating asset,
// builds the Finding, and submits it (deduplicated per organization).
//
// Two conditions are a deliberate skip rather than a delivery failure: a
// PermissionDenied on project/organization resolution (the
// service account lacks access to that project) and an asset that cannot be
// found for the host's instance id. Both log a warning and return a
// backend.DropError so the pipeline records the drop and advances its watermark.
// Every other failure is returned so the pipeline's delivery-failure policy
// governs.
func (r *Runtime) Process(ctx context.Context, ev *events.EnrichedEvent) error {
	projectNumber, err := ev.CloudProviderAccountID(ctx)
	if err != nil {
		return fmt.Errorf("gcp: resolving cloud project number: %w", err)
	}

	orgID, source, err := r.resolveOrgSource(ctx, projectNumber)
	if err != nil {
		if status.Code(err) == codes.PermissionDenied {
			r.logger.Warn("permission denied resolving the GCP organization hierarchy or Security Command Center source; grant the service account resourcemanager read access across the project→folder→organization hierarchy and roles/securitycenter.admin in the organization",
				"project_number", projectNumber, "org_id", orgID, "error", err)
			return backend.Dropped("permission_denied")
		}
		return fmt.Errorf("gcp: resolving SCC source for project %s: %w", projectNumber, err)
	}

	instanceID, err := ev.InstanceID(ctx)
	if err != nil {
		return fmt.Errorf("gcp: resolving instance id: %w", err)
	}

	resourceName, err := r.assets.resourceName(ctx, projectNumber, instanceID)
	if err != nil {
		if errors.Is(err, ErrAssetNotFound) {
			r.logger.Warn("corresponding asset not found in GCP project; skipping detection",
				"project_number", projectNumber, "instance_id", instanceID)
			return backend.Dropped("asset_not_found")
		}
		return fmt.Errorf("gcp: resolving asset resource name: %w", err)
	}

	id := findingID(ev.EventID(), ev.CreationTime().UnixMilli())
	finding := buildFinding(findingInput{
		source:            source,
		findingID:         id,
		resourceName:      resourceName,
		eventID:           ev.EventID(),
		dedupKey:          ev.DedupKey(),
		computerName:      ev.ComputerName(),
		detectName:        ev.DetectName(),
		detectDescription: ev.DetectDescription(),
		severityName:      ev.SeverityName(),
		falconLink:        ev.FalconLink(),
		instanceID:        instanceID,
		fileName:          ev.FileName(),
		filePath:          ev.FilePath(),
		commandLine:       ev.CommandLine(),
		eventTime:         ev.CreationTime(),
	})

	if err := r.submitter.submit(ctx, submitFindingInput{
		source:    source,
		findingID: id,
		finding:   finding,
	}); err != nil {
		return fmt.Errorf("gcp: submitting finding %s: %w", id, err)
	}
	return nil
}
