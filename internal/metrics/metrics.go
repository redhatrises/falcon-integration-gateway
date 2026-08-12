// Package metrics defines the Prometheus collectors for the FIG pipeline and
// exposes a package-private registry.
//
// The /metrics HTTP server is wired later by the Assemble agent; this package
// only defines and registers the collectors on a dedicated registry (no use of
// the global default registry, to keep tests and embedding clean).
package metrics

import "github.com/prometheus/client_golang/prometheus"

var (
	registry = prometheus.NewRegistry()

	// EventsReceived counts events pulled off the stream before filtering.
	EventsReceived = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "fig_events_received_total",
		Help: "Total events received from the Falcon Event Streams feed.",
	})

	// EventsFiltered counts events dropped by the global severity/age filters.
	EventsFiltered = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "fig_events_filtered_total",
		Help: "Total events dropped by global severity/age filters.",
	})

	// EventsDispatched counts events dispatched to at least one backend.
	EventsDispatched = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "fig_events_dispatched_total",
		Help: "Total events dispatched to one or more backends.",
	})

	// EventsDelivered counts successful backend deliveries.
	EventsDelivered = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "fig_events_delivered_total",
		Help: "Total successful backend deliveries.",
	})

	// EventsFailed counts backend delivery failures (after retry).
	EventsFailed = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "fig_events_failed_total",
		Help: "Total backend delivery failures after retry.",
	})

	// EventsDeadLettered counts events dead-lettered by the delivery policy.
	EventsDeadLettered = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "fig_events_dead_lettered_total",
		Help: "Total events dead-lettered by the delivery failure policy.",
	})

	// QueueDepth is the current depth of the bounded event channel.
	QueueDepth = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "fig_queue_depth",
		Help: "Current depth of the bounded event channel.",
	})

	// OffsetCommitted is the last committed offset watermark per feed.
	OffsetCommitted = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "fig_offset_committed",
		Help: "Last committed offset watermark, labeled by feed_id.",
	}, []string{"feed_id"})

	// StreamReconnects counts stream reconnection attempts.
	StreamReconnects = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "fig_stream_reconnects_total",
		Help: "Total Falcon stream reconnection attempts.",
	})

	// EnrichHostsFetched counts host-detail lookups that reached the Falcon
	// Hosts API (cache misses that resulted in a fetch).
	EnrichHostsFetched = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "fig_enrich_hosts_fetch_total",
		Help: "Total host-detail lookups served from the Falcon Hosts API.",
	})

	// EnrichCacheHits counts enrichment lookups served from cache.
	EnrichCacheHits = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "fig_enrich_cache_hits_total",
		Help: "Total enrichment lookups served from cache.",
	})

	// EnrichCacheMisses counts enrichment lookups that missed the cache.
	EnrichCacheMisses = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "fig_enrich_cache_misses_total",
		Help: "Total enrichment lookups that missed the cache.",
	})

	// EnrichRTRSessions counts Real Time Response sessions opened for MDM
	// identifier lookups.
	EnrichRTRSessions = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "fig_enrich_rtr_sessions_total",
		Help: "Total RTR sessions opened for MDM identifier lookups.",
	})

	// EventsEnrichmentFailed counts events whose enrichment terminally failed
	// and were routed through the delivery-failure policy.
	EventsEnrichmentFailed = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "fig_events_enrichment_failed_total",
		Help: "Total events whose enrichment terminally failed.",
	})
)

func init() {
	registry.MustRegister(
		EventsReceived,
		EventsFiltered,
		EventsDispatched,
		EventsDelivered,
		EventsFailed,
		EventsDeadLettered,
		QueueDepth,
		OffsetCommitted,
		StreamReconnects,
		EnrichHostsFetched,
		EnrichCacheHits,
		EnrichCacheMisses,
		EnrichRTRSessions,
		EventsEnrichmentFailed,
	)
}

// Registry returns the Prometheus registry all FIG collectors are registered
// on. The metrics HTTP handler (wired later) should serve from this registry.
func Registry() *prometheus.Registry {
	return registry
}
