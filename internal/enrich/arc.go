package enrich

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"

	"github.com/bodgit/sevenzip"

	"github.com/crowdstrike/falcon-integration-gateway/internal/events"
)

// agentconfig.json locations written by the Azure Connected Machine (Arc) agent.
// The path is selected by OS: Linux uses the azcmagent state directory, every
// other platform uses the Windows ProgramData location.
const (
	linuxArcConfigPath   = "/var/opt/azcmagent/agentconfig.json"
	windowsArcConfigPath = `C:\ProgramData\AzureConnectedMachineAgent\Config\agentconfig.json`
)

// arcResult is the cached outcome of an Arc-config lookup. Both successes and
// failures are stored so a non-Arc host (the common case, which cannot produce
// an agentconfig.json) is not re-probed over RTR on every event within the
// cache window — an RTR round trip per event would be far more expensive than
// caching the negative result.
type arcResult struct {
	cfg *events.ArcConfig
	err error
}

// ArcConfig resolves the Azure Arc configuration for a sensor by fetching its
// agentconfig.json over RTR and decrypting the returned archive. The result and
// any failure are memoized per sensor. The lookup path is chosen by OS platform.
func (e *Resolver) ArcConfig(ctx context.Context, sensorID, platform string) (*events.ArcConfig, error) {
	// The loader always stores its arcResult, caching both successes and
	// failures: a non-Arc host is the common case and must not be re-probed over
	// RTR on every event within the cache window. The fetch error travels inside
	// the arcResult, so get itself never returns an error here.
	res, _, _ := e.arc.get(sensorID, func() (arcResult, bool, error) {
		path := windowsArcConfigPath
		if platform == "Linux" {
			path = linuxArcConfigPath
		}
		return e.fetchArcConfig(ctx, sensorID, path), true, nil
	})
	return res.cfg, res.err
}

// fetchArcConfig performs one Arc-config fetch-and-decode, returning the outcome
// as an arcResult so the caller can cache successes and failures uniformly. The
// fetch is bounded by its own deadline so a sensor whose RTR command never
// completes cannot park a worker indefinitely.
func (e *Resolver) fetchArcConfig(ctx context.Context, sensorID, path string) arcResult {
	ctx, cancel := context.WithTimeout(ctx, e.arcTimeout)
	defer cancel()

	raw, err := e.client.RTRFetchFile(ctx, sensorID, path)
	if err != nil {
		return arcResult{err: fmt.Errorf("enrich: fetch arc config: %w", err)}
	}
	cfg, err := decodeArcConfig(raw, e.arcKeyword)
	if err != nil {
		// The keyword and the decrypted payload are secrets and are never logged.
		e.logger.WarnContext(ctx, "failed to decode Azure Arc config", "sensor_id", sensorID)
		return arcResult{err: err}
	}
	return arcResult{cfg: cfg}
}

// decodeArcConfig decrypts the password-protected 7z archive holding
// agentconfig.json and projects the five Azure identifiers the Azure backend
// reports. The archive must contain exactly one file. The keyword and payload
// are secrets: neither appears in returned errors.
func decodeArcConfig(raw []byte, keyword string) (*events.ArcConfig, error) {
	r, err := sevenzip.NewReaderWithPassword(bytes.NewReader(raw), int64(len(raw)), keyword)
	if err != nil {
		return nil, fmt.Errorf("enrich: open arc archive: %w", err)
	}
	if len(r.File) != 1 {
		return nil, fmt.Errorf("enrich: arc archive has %d files, want 1", len(r.File))
	}

	rc, err := r.File[0].Open()
	if err != nil {
		return nil, fmt.Errorf("enrich: open arc archive entry: %w", err)
	}
	defer func() { _ = rc.Close() }()

	payload, err := io.ReadAll(rc)
	if err != nil {
		return nil, fmt.Errorf("enrich: read arc archive entry: %w", err)
	}

	var doc struct {
		ResourceName   string `json:"resourceName"`
		ResourceGroup  string `json:"resourceGroup"`
		SubscriptionID string `json:"subscriptionId"`
		TenantID       string `json:"tenantId"`
		VMID           string `json:"vmId"`
	}
	if err := json.Unmarshal(payload, &doc); err != nil {
		return nil, fmt.Errorf("enrich: parse arc config: %w", err)
	}

	return &events.ArcConfig{
		ResourceName:   doc.ResourceName,
		ResourceGroup:  doc.ResourceGroup,
		SubscriptionID: doc.SubscriptionID,
		TenantID:       doc.TenantID,
		VMID:           doc.VMID,
	}, nil
}
