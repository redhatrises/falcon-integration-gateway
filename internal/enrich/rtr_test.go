package enrich

import (
	"context"
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/crowdstrike/falcon-integration-gateway/internal/falcon/client"
	"github.com/crowdstrike/falcon-integration-gateway/internal/metrics"
)

// TestMetrics_HostAndRTR asserts the enrichment counters advance: a cache miss
// that fetches, a subsequent cache hit, and an RTR session opened for an MDM
// lookup. It does not call t.Parallel(): the counters are process-global, and
// the runner defers all parallel tests until sequential tests finish, so this
// body observes deltas with no concurrent mutation.
func TestMetrics_HostAndRTR(t *testing.T) {
	fake := &fakeClient{
		ddDevices: []*client.Device{{DeviceID: "dev-1", ServiceProvider: "AWS_EC2_V2"}},
		initSess:  &client.RTRSession{SessionID: "sess-1"},
		execRes:   &client.RTRCommandResult{CloudRequestID: "cr-1"},
		statuses:  []*client.RTRCommandStatus{{Complete: true, Stdout: "X = MDM-1\n"}},
	}
	e := newTestResolver(fake)

	fetched0 := testutil.ToFloat64(metrics.EnrichHostsFetched)
	hits0 := testutil.ToFloat64(metrics.EnrichCacheHits)
	misses0 := testutil.ToFloat64(metrics.EnrichCacheMisses)
	sessions0 := testutil.ToFloat64(metrics.EnrichRTRSessions)

	// First lookup misses the cache and fetches; second hits the cache.
	if _, err := e.HostDetails(context.Background(), "sensor-1"); err != nil {
		t.Fatalf("first HostDetails() error: %v", err)
	}
	if _, err := e.HostDetails(context.Background(), "sensor-1"); err != nil {
		t.Fatalf("second HostDetails() error: %v", err)
	}
	if _, err := e.MDMIdentifier(context.Background(), "sensor-1", "Windows"); err != nil {
		t.Fatalf("MDMIdentifier() error: %v", err)
	}

	if got := testutil.ToFloat64(metrics.EnrichHostsFetched) - fetched0; got != 1 {
		t.Errorf("EnrichHostsFetched delta = %v, want 1", got)
	}
	if got := testutil.ToFloat64(metrics.EnrichCacheHits) - hits0; got != 1 {
		t.Errorf("EnrichCacheHits delta = %v, want 1", got)
	}
	if got := testutil.ToFloat64(metrics.EnrichCacheMisses) - misses0; got != 1 {
		t.Errorf("EnrichCacheMisses delta = %v, want 1", got)
	}
	if got := testutil.ToFloat64(metrics.EnrichRTRSessions) - sessions0; got != 1 {
		t.Errorf("EnrichRTRSessions delta = %v, want 1", got)
	}
}
