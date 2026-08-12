package enrich

import (
	"context"
	"fmt"

	"github.com/cenkalti/backoff/v5"

	"github.com/crowdstrike/falcon-integration-gateway/internal/events"
	"github.com/crowdstrike/falcon-integration-gateway/internal/falcon/client"
	"github.com/crowdstrike/falcon-integration-gateway/internal/metrics"
)

// HostDetails resolves the host behind a sensor to its normalized cloud/platform
// projection. A sensor that does not resolve to exactly one device yields a
// HostDetails with Known set to false rather than an error, so callers fall back
// to the unrecognized bucket exactly as the legacy path intended. Only a resolved
// host is cached; an unresolvable sensor and a transient fetch error are both left
// uncached, so a later event re-fetches once the sensor becomes visible.
func (e *Resolver) HostDetails(ctx context.Context, sensorID string) (*events.HostDetails, error) {
	if h, ok := e.hostCache.Get(sensorID); ok {
		metrics.EnrichCacheHits.Inc()
		return h, nil
	}
	metrics.EnrichCacheMisses.Inc()

	// The flight runs under the first caller's context. In the pipeline every
	// caller shares one long-lived drain context, so a follower is never bound to
	// a shorter-lived context than its own; per-caller deadlines would need
	// revisiting only if a future caller passes a distinct context.
	v, err, _ := e.hostGroup.Do(sensorID, func() (any, error) {
		// A concurrent caller may have populated the cache while this flight
		// was queued; re-check before spending a network call.
		if h, ok := e.hostCache.Get(sensorID); ok {
			return h, nil
		}

		metrics.EnrichHostsFetched.Inc()
		devices, err := backoff.Retry(
			ctx,
			func() ([]*client.Device, error) { return e.client.DeviceDetails(ctx, sensorID) },
			backoff.WithBackOff(e.newBackOff()),
			backoff.WithMaxTries(e.maxTries),
		)
		if err != nil {
			return nil, err
		}

		var h *events.HostDetails
		if len(devices) != 1 {
			// A sensor that resolves to zero or many devices is left uncached: a
			// freshly-enrolled sensor absent from the Hosts API today may resolve
			// once enrollment propagates, and caching the miss would suppress that
			// for the full TTL and silently drop its detections.
			return &events.HostDetails{Known: false}, nil
		}
		d := devices[0]
		h = &events.HostDetails{
			Known:                  true,
			SensorID:               sensorID,
			DeviceID:               d.DeviceID,
			CloudProvider:          d.ServiceProvider,
			CloudProviderAccountID: d.ServiceProviderAccountID,
			InstanceID:             d.InstanceID,
			Platform:               d.PlatformName,
		}

		e.hostCache.Add(sensorID, h)
		return h, nil
	})
	if err != nil {
		return nil, err
	}
	h, ok := v.(*events.HostDetails)
	if !ok {
		return nil, fmt.Errorf("enrich: unexpected host-detail result type %T", v)
	}
	return h, nil
}
