package events

import (
	"context"
	"sync"

	"github.com/crowdstrike/falcon-integration-gateway/internal/common"
)

// ArcConfig is the Azure Arc agent configuration read from a non-Azure host's
// agentconfig.json over RTR. It is the subset of identifiers the Azure backend
// attaches to a finding so an Arc-connected machine is correlated to its Azure
// resource. It mirrors the keys the Python gateway projected (AZURE_ARC_KEYS).
type ArcConfig struct {
	ResourceName   string
	ResourceGroup  string
	SubscriptionID string
	TenantID       string
	VMID           string
}

// Enricher resolves host details, MDM identifiers, and Azure Arc configuration
// for a sensor. It is declared here, on the consumer side, so this leaf package
// can name the enrichment seam without importing the concrete enrich package
// (which would create an import cycle). The concrete implementation lives in
// internal/enrich.
type Enricher interface {
	HostDetails(ctx context.Context, sensorID string) (*common.HostDetails, error)
	MDMIdentifier(ctx context.Context, sensorID, platform string) (string, error)
	ArcConfig(ctx context.Context, sensorID, platform string) (*ArcConfig, error)
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
	host    *common.HostDetails
	hostErr error

	arcOnce sync.Once
	arc     *ArcConfig
	arcErr  error
}

// NewEnrichedEvent wraps ev with enricher, deferring any lookup until an
// enrichment accessor is called.
func NewEnrichedEvent(ev *Event, enricher Enricher) *EnrichedEvent {
	return &EnrichedEvent{Event: ev, enricher: enricher}
}

// hostDetails performs the single memoized host-details lookup for this event,
// keyed on the event's sensor id.
func (e *EnrichedEvent) hostDetails(ctx context.Context) (*common.HostDetails, error) {
	e.once.Do(func() {
		e.host, e.hostErr = e.enricher.HostDetails(ctx, e.SensorID())
	})
	return e.host, e.hostErr
}

// Host returns the full resolved host details, triggering the memoized
// host-details lookup. Backends that report many host attributes (e.g. AWS
// Security Hub) read the whole projection through this accessor rather than one
// field-accessor call per attribute. The returned value is read-only by
// contract (see HostDetails).
func (e *EnrichedEvent) Host(ctx context.Context) (*common.HostDetails, error) {
	return e.hostDetails(ctx)
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

// MatchesProvider reports whether the event's resolved cloud provider satisfies
// match. When the provider cannot be resolved it fails open (returns true): the
// event proceeds to Process, which surfaces the enrichment error so the
// pipeline's delivery-failure policy governs rather than silently dropping the
// detection. Detection backends use this as their per-event relevance filter.
func MatchesProvider(ctx context.Context, ev *EnrichedEvent, match func(string) bool) bool {
	provider, err := ev.CloudProvider(ctx)
	if err != nil {
		return true
	}
	return match(provider)
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

// ArcConfig returns the device's Azure Arc configuration. It first resolves host
// details to learn the platform (the agentconfig.json path differs by OS), then
// delegates to the enricher; a host-details failure short-circuits without an
// Arc lookup. The result (or error) is memoized per event so repeated backend
// access performs the RTR fetch at most once.
func (e *EnrichedEvent) ArcConfig(ctx context.Context) (*ArcConfig, error) {
	h, err := e.hostDetails(ctx)
	if err != nil {
		return nil, err
	}
	e.arcOnce.Do(func() {
		e.arc, e.arcErr = e.enricher.ArcConfig(ctx, e.SensorID(), h.Platform)
	})
	return e.arc, e.arcErr
}
