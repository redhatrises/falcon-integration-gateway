package metrics

import (
	"testing"
)

// counterValue scans the registry's Gather() output for the named counter
// family and returns its summed value plus whether the family was present. It
// avoids the prometheus testutil helpers so the test adds no extra module
// dependency.
func counterValue(t *testing.T, name string) (float64, bool) {
	t.Helper()
	families, err := Registry().Gather()
	if err != nil {
		t.Fatalf("Gather() returned error: %v", err)
	}
	for _, family := range families {
		if family.GetName() != name {
			continue
		}
		var sum float64
		for _, m := range family.GetMetric() {
			sum += m.GetCounter().GetValue()
		}
		return sum, true
	}
	return 0, false
}

func TestEnrichmentCountersAreRegistered(t *testing.T) {
	counters := map[string]struct {
		metric interface{ Inc() }
		name   string
	}{
		"EnrichHostsFetched":     {EnrichHostsFetched, "fig_enrich_hosts_fetch_total"},
		"EnrichCacheHits":        {EnrichCacheHits, "fig_enrich_cache_hits_total"},
		"EnrichCacheMisses":      {EnrichCacheMisses, "fig_enrich_cache_misses_total"},
		"EnrichRTRSessions":      {EnrichRTRSessions, "fig_enrich_rtr_sessions_total"},
		"EventsEnrichmentFailed": {EventsEnrichmentFailed, "fig_events_enrichment_failed_total"},
	}

	for label, c := range counters {
		c.metric.Inc()
		if _, found := counterValue(t, c.name); !found {
			t.Fatalf("%s: expected metric family %q to be present in Gather() output", label, c.name)
		}
	}
}

func TestEnrichHostsFetchedCountsIncrements(t *testing.T) {
	before, _ := counterValue(t, "fig_enrich_hosts_fetch_total")
	EnrichHostsFetched.Inc()
	after, _ := counterValue(t, "fig_enrich_hosts_fetch_total")

	if after != before+1 {
		t.Fatalf("expected EnrichHostsFetched to increment by 1, got before=%v after=%v", before, after)
	}
}
