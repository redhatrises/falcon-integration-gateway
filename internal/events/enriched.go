package events

import (
	"context"
	"sync"
)

// HostDetails is the normalized subset of Falcon device details the pipeline
// and enrichment-consuming backends need. It mirrors the projection the Python
// gateway read from GetDeviceDetailsV2 (service_provider, service_provider_
// account_id, instance_id, platform_name), plus the device/sensor identifiers.
//
// Known distinguishes a successful lookup that resolved to a real device from
// the empty-provider fallback used when a device cannot be identified.
//
// An Enricher may cache and return the same *HostDetails to concurrent callers,
// so a value obtained from one is read-only by contract: callers must not mutate
// its fields.
type HostDetails struct {
	Known                  bool
	DeviceID               string
	SensorID               string
	CloudProvider          string
	CloudProviderAccountID string
	InstanceID             string
	Platform               string
}

// Enricher resolves host details and MDM identifiers for a sensor. It is
// declared here, on the consumer side, so this leaf package can name the
// enrichment seam without importing the concrete enrich package (which would
// create an import cycle). The concrete implementation lives in internal/enrich.
type Enricher interface {
	HostDetails(ctx context.Context, sensorID string) (*HostDetails, error)
	MDMIdentifier(ctx context.Context, sensorID, platform string) (string, error)
}

// EnrichedEvent pairs a raw Event with an Enricher and lazily resolves host
// details on first access. It embeds *Event so the raw accessors (EventType,
// Offset, SensorID, ...) promote directly, letting the pipeline gates and
// backends treat it as an Event that can also answer enrichment questions.
//
// The host-details lookup is performed at most once per event: the first field
// accessor triggers it and every subsequent accessor reuses the cached result
// (or error). This mirrors the per-event memoization of the Python FalconEvent.
//
// The error is memoized alongside the result, so all accessors on one event
// observe a single lookup outcome rather than re-fetching. This is safe because
// the enricher already bounds its own retries on transient failures: by the time
// an error reaches here it is terminal for this event. An EnrichedEvent is built
// per event and read serially within one worker, so no accessor races another.
type EnrichedEvent struct {
	*Event

	enricher Enricher

	once    sync.Once
	host    *HostDetails
	hostErr error
}

// NewEnrichedEvent wraps ev with enricher, deferring any lookup until an
// enrichment accessor is called.
func NewEnrichedEvent(ev *Event, enricher Enricher) *EnrichedEvent {
	return &EnrichedEvent{Event: ev, enricher: enricher}
}

// hostDetails performs the single memoized host-details lookup for this event,
// keyed on the event's sensor id.
func (e *EnrichedEvent) hostDetails(ctx context.Context) (*HostDetails, error) {
	e.once.Do(func() {
		e.host, e.hostErr = e.enricher.HostDetails(ctx, e.SensorID())
	})
	return e.host, e.hostErr
}

// CloudProvider returns the resolved cloud service provider ("AWS", "Azure",
// "GCP", or ""), triggering the memoized host-details lookup.
func (e *EnrichedEvent) CloudProvider(ctx context.Context) (string, error) {
	h, err := e.hostDetails(ctx)
	if err != nil {
		return "", err
	}
	return h.CloudProvider, nil
}

// Platform returns the resolved OS platform (e.g. "Windows", "Mac", "Linux"),
// triggering the memoized host-details lookup.
func (e *EnrichedEvent) Platform(ctx context.Context) (string, error) {
	h, err := e.hostDetails(ctx)
	if err != nil {
		return "", err
	}
	return h.Platform, nil
}

// CloudProviderAccountID returns the resolved cloud account identifier,
// triggering the memoized host-details lookup.
func (e *EnrichedEvent) CloudProviderAccountID(ctx context.Context) (string, error) {
	h, err := e.hostDetails(ctx)
	if err != nil {
		return "", err
	}
	return h.CloudProviderAccountID, nil
}

// InstanceID returns the resolved cloud instance identifier, triggering the
// memoized host-details lookup.
func (e *EnrichedEvent) InstanceID(ctx context.Context) (string, error) {
	h, err := e.hostDetails(ctx)
	if err != nil {
		return "", err
	}
	return h.InstanceID, nil
}

// MDMIdentifier returns the device's MDM identifier. It first resolves host
// details to learn the platform (the MDM lookup differs by OS), then delegates
// to the enricher; a host-details failure short-circuits without an MDM call.
func (e *EnrichedEvent) MDMIdentifier(ctx context.Context) (string, error) {
	h, err := e.hostDetails(ctx)
	if err != nil {
		return "", err
	}
	return e.enricher.MDMIdentifier(ctx, e.SensorID(), h.Platform)
}
