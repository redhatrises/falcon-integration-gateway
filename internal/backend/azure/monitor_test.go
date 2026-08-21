package azure

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"strings"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/monitor/ingestion/azlogs"

	"github.com/crowdstrike/falcon-integration-gateway/internal/config"
	"github.com/crowdstrike/falcon-integration-gateway/internal/testutil"
)

// fakeIngestor is a logsIngestor double capturing the last Upload call.
type fakeIngestor struct {
	ruleID     string
	streamName string
	logs       []byte
	err        error
	calls      int
}

func (f *fakeIngestor) Upload(_ context.Context, ruleID, streamName string, logs []byte, _ *azlogs.UploadOptions) (azlogs.UploadResponse, error) {
	f.calls++
	f.ruleID = ruleID
	f.streamName = streamName
	f.logs = logs
	return azlogs.UploadResponse{}, f.err
}

func TestNewUploaderLegacy(t *testing.T) {
	t.Parallel()

	cfg := config.AzureConfig{AuthMethod: "legacy", WorkspaceID: "ws", PrimaryKey: "key"}
	up, err := newUploader(cfg, testutil.DiscardLogger())
	if err != nil {
		t.Fatalf("newUploader: %v", err)
	}
	lu, ok := up.(*legacyUploader)
	if !ok {
		t.Fatalf("newUploader returned %T, want *legacyUploader", up)
	}
	if lu.baseURL != "https://ws.ods.opinsights.azure.com" {
		t.Errorf("baseURL = %q, want https://ws.ods.opinsights.azure.com", lu.baseURL)
	}
	if lu.workspaceID != "ws" || lu.primaryKey != "key" {
		t.Errorf("workspaceID/primaryKey = %q/%q, want ws/key", lu.workspaceID, lu.primaryKey)
	}
	if lu.now == nil || lu.httpClient == nil {
		t.Error("legacy uploader must have now and httpClient set")
	}
}

func TestNewUploaderClientSecret(t *testing.T) {
	t.Parallel()

	cfg := config.AzureConfig{
		AuthMethod:     "client_secret",
		TenantID:       "t",
		ClientID:       "c",
		ClientSecret:   "s",
		DCREndpoint:    "https://x.ingest.monitor.azure.com",
		DCRImmutableID: "dcr-1",
	}
	up, err := newUploader(cfg, testutil.DiscardLogger())
	if err != nil {
		t.Fatalf("newUploader: %v", err)
	}
	mu, ok := up.(*monitorUploader)
	if !ok {
		t.Fatalf("newUploader returned %T, want *monitorUploader", up)
	}
	if mu.ruleID != "dcr-1" {
		t.Errorf("ruleID = %q, want dcr-1", mu.ruleID)
	}
	if mu.streamName != "Custom-FalconIntegrationGatewayLogs" {
		t.Errorf("streamName = %q, want Custom-FalconIntegrationGatewayLogs", mu.streamName)
	}
}

func TestNewUploaderWorkloadIdentity(t *testing.T) {
	t.Parallel()

	cfg := config.AzureConfig{
		AuthMethod:     "workload_identity",
		DCREndpoint:    "https://x.ingest.monitor.azure.com",
		DCRImmutableID: "dcr-2",
	}
	up, err := newUploader(cfg, testutil.DiscardLogger())
	if err != nil {
		t.Fatalf("newUploader: %v", err)
	}
	mu, ok := up.(*monitorUploader)
	if !ok {
		t.Fatalf("newUploader returned %T, want *monitorUploader", up)
	}
	if mu.ruleID != "dcr-2" {
		t.Errorf("ruleID = %q, want dcr-2", mu.ruleID)
	}
}

func TestNewUploaderUnknownMethod(t *testing.T) {
	t.Parallel()

	cfg := config.AzureConfig{AuthMethod: "carrier-pigeon"}
	if _, err := newUploader(cfg, testutil.DiscardLogger()); err == nil {
		t.Fatal("newUploader: want error for unknown auth method, got nil")
	}
}

func TestNewUploaderLegacyWarnsDeprecated(t *testing.T) {
	t.Parallel()

	const secret = "SUPERSECRETPRIMARYKEY"
	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	cfg := config.AzureConfig{AuthMethod: "legacy", WorkspaceID: "ws", PrimaryKey: secret}

	if _, err := newUploader(cfg, logger); err != nil {
		t.Fatalf("newUploader: %v", err)
	}

	out := buf.String()
	if !strings.Contains(out, `"level":"WARN"`) {
		t.Errorf("newUploader(legacy) emitted no WARN log; got %q", out)
	}
	if !strings.Contains(strings.ToLower(out), "deprecat") {
		t.Errorf("newUploader(legacy) WARN did not mention deprecation; got %q", out)
	}
	if strings.Contains(out, secret) {
		t.Errorf("newUploader(legacy) log leaked the primary key")
	}
}

func TestMonitorUploaderUpload(t *testing.T) {
	t.Parallel()

	ing := &fakeIngestor{}
	u := &monitorUploader{
		client:     ing,
		ruleID:     "dcr-1",
		streamName: "Custom-FalconIntegrationGatewayLogs",
	}
	records := []record{{FalconEventID: "e1"}}

	if err := u.upload(context.Background(), records); err != nil {
		t.Fatalf("upload: %v", err)
	}
	if ing.calls != 1 {
		t.Fatalf("Upload calls = %d, want 1", ing.calls)
	}
	if ing.ruleID != "dcr-1" || ing.streamName != "Custom-FalconIntegrationGatewayLogs" {
		t.Errorf("ruleID/streamName = %q/%q", ing.ruleID, ing.streamName)
	}
	var sent []map[string]any
	if err := json.Unmarshal(ing.logs, &sent); err != nil {
		t.Fatalf("logs not a JSON array: %v", err)
	}
	if len(sent) != 1 || sent[0]["FalconEventId"] != "e1" {
		t.Errorf("logs = %v, want one record with FalconEventId=e1", sent)
	}
}

func TestMonitorUploaderUploadError(t *testing.T) {
	t.Parallel()

	sentinel := errors.New("ingestion rejected")
	u := &monitorUploader{
		client:     &fakeIngestor{err: sentinel},
		ruleID:     "dcr-1",
		streamName: "Custom-FalconIntegrationGatewayLogs",
	}
	if err := u.upload(context.Background(), []record{{FalconEventID: "x"}}); !errors.Is(err, sentinel) {
		t.Fatalf("upload error = %v, want wrapped %v", err, sentinel)
	}
}
