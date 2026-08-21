package azure

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/monitor/ingestion/azlogs"

	"github.com/crowdstrike/falcon-integration-gateway/internal/config"
)

// monitorStreamName is the Data Collection Rule stream the records are ingested
// under.
const monitorStreamName = "Custom-FalconIntegrationGatewayLogs"

// logsIngestor is the subset of the Azure Logs Ingestion client the monitor
// uploader depends on. Declaring it here lets the uploader be tested with a
// fake and keeps the dependency on the concrete *azlogs.Client at construction.
type logsIngestor interface {
	Upload(ctx context.Context, ruleID, streamName string, logs []byte, opts *azlogs.UploadOptions) (azlogs.UploadResponse, error)
}

// monitorUploader posts records through the Azure Monitor Logs Ingestion API
// using a Data Collection Rule. It backs both the client_secret and
// workload_identity auth methods, which differ only in the credential handed to
// the underlying client at construction.
type monitorUploader struct {
	client     logsIngestor
	ruleID     string
	streamName string
}

// upload marshals records to a JSON array and ingests them via the Data
// Collection Rule. An ingestion failure is wrapped so the worker can retry.
func (u *monitorUploader) upload(ctx context.Context, records []record) error {
	body, err := json.Marshal(records)
	if err != nil {
		return fmt.Errorf("azure: marshal records: %w", err)
	}
	if _, err := u.client.Upload(ctx, u.ruleID, u.streamName, body, nil); err != nil {
		return fmt.Errorf("azure: upload to logs ingestion: %w", err)
	}
	return nil
}

// newUploader selects and constructs the uploader for the configured auth
// method. Config validation has already guaranteed the required fields for the
// chosen method are present, so this only dispatches and surfaces credential or
// client construction errors. The client secret is never logged.
func newUploader(cfg config.AzureConfig, logger *slog.Logger) (uploader, error) {
	switch cfg.AuthMethod {
	case "legacy":
		logger.Warn("Azure Backend is enabled using the deprecated HTTP Data Collector API. " +
			"Please migrate to the Logs Ingestion API by setting azure.auth_method to " +
			"'workload_identity' or 'client_secret'.")
		return &legacyUploader{
			workspaceID: cfg.WorkspaceID,
			primaryKey:  cfg.PrimaryKey,
			baseURL:     fmt.Sprintf("https://%s.ods.opinsights.azure.com", cfg.WorkspaceID),
			httpClient:  &http.Client{Timeout: 60 * time.Second},
			now:         time.Now,
		}, nil

	case "client_secret":
		cred, err := azidentity.NewClientSecretCredential(cfg.TenantID, cfg.ClientID, cfg.ClientSecret, nil)
		if err != nil {
			return nil, fmt.Errorf("azure: client secret credential: %w", err)
		}
		return newMonitorUploader(cfg, cred)

	case "workload_identity":
		cred, err := azidentity.NewDefaultAzureCredential(nil)
		if err != nil {
			return nil, fmt.Errorf("azure: default credential: %w", err)
		}
		return newMonitorUploader(cfg, cred)

	default:
		return nil, fmt.Errorf("azure: unknown auth method %q", cfg.AuthMethod)
	}
}

// newMonitorUploader builds a Logs Ingestion client for the given credential
// and wraps it in a monitorUploader bound to the configured Data Collection
// Rule endpoint and immutable ID.
func newMonitorUploader(cfg config.AzureConfig, cred azcore.TokenCredential) (*monitorUploader, error) {
	client, err := azlogs.NewClient(cfg.DCREndpoint, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("azure: logs ingestion client: %w", err)
	}
	return &monitorUploader{
		client:     client,
		ruleID:     cfg.DCRImmutableID,
		streamName: monitorStreamName,
	}, nil
}
