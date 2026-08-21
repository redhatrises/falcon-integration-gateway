// Package metrics defines the Prometheus collectors for the FIG pipeline and
// exposes a package-private registry.
//
// Collectors are registered on a dedicated registry (not the global default
// registry) to keep tests and embedding clean; the /metrics HTTP handler serves
// from it via Registry().
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

	// EventsDroppedAfterRetry counts events discarded by the drop delivery policy
	// after retries were exhausted (or a panic was recovered). The event is
	// acknowledged and the watermark advances; the payload is not delivered
	// anywhere — there is no dead-letter sink.
	EventsDroppedAfterRetry = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "fig_events_dropped_after_retry_total",
		Help: "Total events discarded by the drop delivery-failure policy after retries were exhausted.",
	})

	// EventsDropped counts events a backend deliberately dropped, labeled by the
	// backend and the drop reason. A drop is handled (the watermark advances) but
	// not delivered, so it is counted here rather than under EventsDelivered or
	// EventsFailed.
	EventsDropped = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "fig_events_dropped_total",
		Help: "Total events deliberately dropped by a backend, labeled by backend and reason.",
	}, []string{"backend", "reason"})

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

	// PendingEvents is the number of completed-but-not-yet-committed offsets held
	// per feed. It climbs when the resume watermark stalls (an offset gap, or a
	// blocked event under the block policy) and is a leading indicator of the
	// unbounded-growth failure modes those conditions cause.
	PendingEvents = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "fig_pending_events",
		Help: "Completed-but-not-yet-committed offsets held per feed_id.",
	}, []string{"feed_id"})

	// PendingOverflow counts events that exceeded events.pending_max while the
	// watermark was stalled under the block policy, labeled by feed_id.
	PendingOverflow = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "fig_pending_overflow_total",
		Help: "Events that exceeded the per-feed pending cap under the block policy.",
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
		EventsDroppedAfterRetry,
		EventsDropped,
		QueueDepth,
		OffsetCommitted,
		PendingEvents,
		PendingOverflow,
		StreamReconnects,
		EnrichHostsFetched,
		EnrichCacheHits,
		EnrichCacheMisses,
		EnrichRTRSessions,
		EventsEnrichmentFailed,
	)
}

// Registry returns the Prometheus registry all FIG collectors are registered
// on. The metrics HTTP handler serves from this registry.
func Registry() *prometheus.Registry {
	return registry
}
