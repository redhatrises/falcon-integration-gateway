// Package azure forwards Falcon detection events to Azure Monitor / Log
// Analytics. Three ingestion paths are supported behind a single uploader seam:
// the legacy HTTP Data Collector API (shared-key signed) and the Logs Ingestion
// API reached with either a client secret or a workload identity credential.
package azure

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/crowdstrike/falcon-integration-gateway/internal/backend"
	"github.com/crowdstrike/falcon-integration-gateway/internal/common"
	"github.com/crowdstrike/falcon-integration-gateway/internal/config"
	"github.com/crowdstrike/falcon-integration-gateway/internal/events"
)

// backendName is the registry key and Name() value for this backend.
const backendName = "AZURE"

// detectionEventType is the only Falcon event family this backend forwards.
const detectionEventType = events.EppDetectionSummaryEventType

func init() {
	backend.Register(backendName, New)
}

// azureCloudProvider is the provider label of a host that already lives in
// Azure; Arc autodiscovery is meaningless for such a host and is skipped.
const azureCloudProvider = "AZURE"

// k8sProductTypeDesc marks a Kubernetes pod sensor, which has no Arc-connected
// machine to correlate, so Arc autodiscovery is skipped for it.
const k8sProductTypeDesc = "Pod"

// unrecognizedCloud is the CloudProvider value reported for a host whose
// provider could not be resolved.
const unrecognizedCloud = "Unrecognized"

// uploader submits a batch of already-projected records to Azure. The concrete
// implementations (legacy shared-key HTTP and the Logs Ingestion SDK) are
// selected by auth method at construction; the backend logic depends only on
// this seam.
type uploader interface {
	upload(ctx context.Context, records []record) error
}

// record is the flat log entry the Azure Monitor custom log expects, one per
// detection. Marshaled as a JSON object; the json tags fix the field names the
// custom-log table is keyed on.
//
// FalconEventId carries the real Falcon detection/audit id (see
// events.Event.EventID). Falcon re-emits summary and alert events under the
// same id at new offsets when a detection is updated, so it is not unique per
// forwarded row. FigDeduplicationId carries the retry-stable dedup key (see
// events.Event.DedupKey) and is unique per stream event. Log Analytics does not
// de-duplicate on ingest, so a crash-restart redelivery still lands a duplicate
// row; a consumer query collapses duplicates by grouping on FigDeduplicationId.
type record struct {
	ExternalURI        string     `json:"ExternalUri"`
	FalconEventID      string     `json:"FalconEventId"`
	FigDeduplicationID string     `json:"FigDeduplicationId"`
	ComputerName       string     `json:"ComputerName"`
	Description        string     `json:"Description"`
	Severity           string     `json:"Severity"`
	Title              string     `json:"Title"`
	ProcessName        string     `json:"ProcessName"`
	ProcessPath        string     `json:"ProcessPath"`
	CommandLine        string     `json:"CommandLine"`
	DetectName         string     `json:"DetectName"`
	AccountID          string     `json:"AccountId"`
	InstanceID         string     `json:"InstanceId"`
	CloudProvider      string     `json:"CloudProvider"`
	ResourceGroup      string     `json:"ResourceGroup"`
	Arc                *arcRecord `json:"arc,omitempty"`
}

// arcRecord carries the Azure Arc identifiers correlated for a non-Azure host.
// It is nested under "arc" and omitted when autodiscovery resolves nothing.
type arcRecord struct {
	ResourceName   string `json:"resourceName"`
	ResourceGroup  string `json:"resourceGroup"`
	SubscriptionID string `json:"subscriptionId"`
	TenantID       string `json:"tenantId"`
	VMID           string `json:"vmId"`
}

// Runtime is the Azure backend. It projects each detection into an Azure
// Monitor record and hands the batch to the configured uploader.
type Runtime struct {
	up               uploader
	arcAutodiscovery bool
	logger           *slog.Logger
}

// New constructs the Azure backend. It builds the uploader for the configured
// auth method and wires the Arc autodiscovery toggle. Neither the primary key
// nor the client secret is logged.
func New(cfg *config.Config, logger *slog.Logger) (backend.Backend, error) {
	up, err := newUploader(cfg.Azure, logger)
	if err != nil {
		return nil, fmt.Errorf("azure: build uploader: %w", err)
	}
	logger.Info("AZURE Backend is enabled.",
		"auth_method", cfg.Azure.AuthMethod,
		"arc_autodiscovery", cfg.Azure.ArcAutodiscovery,
	)
	return &Runtime{
		up:               up,
		arcAutodiscovery: cfg.Azure.ArcAutodiscovery,
		logger:           logger,
	}, nil
}

// Name returns the backend's registry identifier.
func (r *Runtime) Name() string {
	return backendName
}

// RelevantEventTypes narrows the server-side stream filter to detection
// summaries, the only family this backend projects.
func (r *Runtime) RelevantEventTypes() []string {
	return []string{detectionEventType}
}

// IsRelevant accepts every event of a relevant type; no further per-event
// filtering is applied here.
func (r *Runtime) IsRelevant(_ context.Context, _ *events.EnrichedEvent) bool {
	return true
}

// Process projects the event into an Azure Monitor record and uploads it. A
// record-building failure (host resolution) or an upload failure is wrapped and
// returned so the worker can decide whether to retry. A sensor that resolves to
// no single device yields a backend.DropError so the pipeline records the drop
// (a deliberate skip) and advances its watermark, distinct from a
// delivery-failure drop after exhausted retries.
func (r *Runtime) Process(ctx context.Context, ev *events.EnrichedEvent) error {
	rec, err := r.buildRecord(ctx, ev)
	if err != nil {
		return err
	}
	if rec == nil {
		r.logger.Info("skipping event for unresolvable host", "sensor_id", ev.SensorID())
		return backend.Dropped("host_unresolved")
	}
	if err := r.up.upload(ctx, []record{*rec}); err != nil {
		return fmt.Errorf("azure: process event: %w", err)
	}
	return nil
}

// buildRecord projects an enriched detection event into the flat record the
// Azure Monitor custom log expects. Host resolution failures are propagated so
// the worker can retry. A sensor that resolves to no single device yields a
// nil record (and nil error): the detection is dropped rather than forwarded
// with empty instance identifiers. A successful projection carries the Arc
// identifiers as a nested "arc" object when autodiscovery resolves them.
func (r *Runtime) buildRecord(ctx context.Context, ev *events.EnrichedEvent) (*record, error) {
	host, err := ev.Host(ctx)
	if err != nil {
		return nil, fmt.Errorf("azure: resolve host: %w", err)
	}
	if !host.Known {
		return nil, nil
	}

	cloud := host.CloudProvider
	if cloud == "" {
		cloud = unrecognizedCloud
	}

	rec := &record{
		ExternalURI:        ev.FalconLink(),
		FalconEventID:      ev.EventID(),
		FigDeduplicationID: ev.DedupKey(),
		ComputerName:       ev.ComputerName(),
		Description:        ev.DetectDescription(),
		Severity:           ev.SeverityName(),
		Title:              fmt.Sprintf("Falcon Alert. Instance %s", host.InstanceID),
		ProcessName:        ev.FileName(),
		ProcessPath:        ev.FilePath(),
		CommandLine:        ev.CommandLine(),
		DetectName:         ev.DetectName(),
		AccountID:          host.CloudProviderAccountID,
		InstanceID:         host.InstanceID,
		CloudProvider:      cloud,
		ResourceGroup:      host.ZoneGroup,
	}

	if arc := r.autodiscover(ctx, ev, host); arc != nil {
		rec.Arc = &arcRecord{
			ResourceName:   arc.ResourceName,
			ResourceGroup:  arc.ResourceGroup,
			SubscriptionID: arc.SubscriptionID,
			TenantID:       arc.TenantID,
			VMID:           arc.VMID,
		}
	}

	return rec, nil
}

// autodiscover resolves the host's Azure Arc configuration, or returns nil when
// autodiscovery is disabled, the host is not an Arc candidate, or the RTR fetch
// fails. A fetch failure is logged and swallowed (fail-open): a detection is
// still forwarded without Arc correlation rather than dropped.
func (r *Runtime) autodiscover(ctx context.Context, ev *events.EnrichedEvent, host *common.HostDetails) *events.ArcConfig {
	if !r.arcAutodiscovery {
		return nil
	}
	if host.CloudProvider == azureCloudProvider {
		return nil
	}
	// The Arc agentconfig.json fetched over RTR exists only on full
	// Linux/Windows hosts, so autodiscovery does not run elsewhere.
	if host.Platform != "Linux" && host.Platform != "Windows" {
		r.logger.Info("skipping arc autodiscovery for unsupported platform", "platform", host.Platform)
		return nil
	}
	if host.ProductTypeDesc == k8sProductTypeDesc {
		r.logger.Info("skipping arc autodiscovery for kubernetes pod")
		return nil
	}

	arc, err := ev.ArcConfig(ctx)
	if err != nil {
		r.logger.Warn("arc autodiscovery failed", "sensor_id", host.SensorID)
		return nil
	}
	return arc
}
