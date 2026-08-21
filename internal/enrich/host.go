package enrich

import (
	"context"

	"github.com/cenkalti/backoff/v5"

	"github.com/crowdstrike/falcon-integration-gateway/internal/common"
	"github.com/crowdstrike/falcon-integration-gateway/internal/metrics"
)

// HostDetails resolves the host behind a sensor to its normalized cloud/platform
// projection. A sensor that does not resolve to exactly one device yields a
// HostDetails with Known set to false rather than an error, so callers fall back
// to the unrecognized bucket exactly as the legacy path intended. Only a resolved
// host is cached; an unresolvable sensor and a transient fetch error are both left
// uncached, so a later event re-fetches once the sensor becomes visible.
func (e *Resolver) HostDetails(ctx context.Context, sensorID string) (*common.HostDetails, error) {
	// The load runs under the first caller's context. In the pipeline every
	// caller shares one long-lived drain context, so a follower is never bound to
	// a shorter-lived context than its own; per-caller deadlines would need
	// revisiting only if a future caller passes a distinct context.
	h, hit, err := e.hosts.get(sensorID, func() (*common.HostDetails, bool, error) {
		metrics.EnrichHostsFetched.Inc()
		devices, err := backoff.Retry(
			ctx,
			func() ([]*common.HostDetails, error) { return e.client.DeviceDetails(ctx, sensorID) },
			backoff.WithBackOff(e.newBackOff()),
			backoff.WithMaxTries(e.maxTries),
		)
		if err != nil {
			return nil, false, err
		}

		if len(devices) != 1 {
			// A sensor that resolves to zero or many devices is left uncached: a
			// freshly-enrolled sensor absent from the Hosts API today may resolve
			// once enrollment propagates, and caching the miss would suppress that
			// for the full TTL and silently drop its detections.
			return &common.HostDetails{Known: false}, false, nil
		}
		// The client builds this value per fetch and has not cached it, so setting
		// the enrichment-owned fields in place is safe.
		d := devices[0]
		d.Known = true
		d.SensorID = sensorID
		return d, true, nil
	})
	if hit {
		metrics.EnrichCacheHits.Inc()
	} else {
		metrics.EnrichCacheMisses.Inc()
	}
	if err != nil {
		return nil, err
	}
	return h, nil
}
