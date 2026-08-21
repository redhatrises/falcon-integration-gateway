package testutil

import (
	"context"
	"sync"

	"github.com/crowdstrike/falcon-integration-gateway/internal/common"
	"github.com/crowdstrike/falcon-integration-gateway/internal/events"
)

// FakeEnricher is a configurable events.Enricher double for backend and pipeline
// tests. Host/HostErr drive the host-details lookup, Arc/ArcErr drive Arc-config
// autodiscovery, and the number of ArcConfig calls is recorded so tests can
// assert that the Arc lookup gate fired (or did not). It is safe for concurrent
// use.
//
// The events package cannot use this double: testutil imports events, so an
// events white-box test importing testutil would form an import cycle. Those
// tests keep their own local double.
type FakeEnricher struct {
	// Host is returned (with SensorID stamped in) when HostErr is nil. A nil
	// Host yields a nil, nil result, modelling a device that was not found.
	Host *common.HostDetails
	// HostErr, when non-nil, is returned by HostDetails without a host.
	HostErr error
	// Arc is returned by ArcConfig when ArcErr is nil.
	Arc *events.ArcConfig
	// ArcErr, when non-nil, is returned by ArcConfig without a config.
	ArcErr error

	mu       sync.Mutex
	arcCalls int
}

// HostDetails returns a copy of Host with SensorID stamped in, or HostErr when
// set. A nil Host returns nil without error.
func (f *FakeEnricher) HostDetails(_ context.Context, sensorID string) (*common.HostDetails, error) {
	if f.HostErr != nil {
		return nil, f.HostErr
	}
	if f.Host == nil {
		return nil, nil
	}
	h := *f.Host
	h.SensorID = sensorID
	return &h, nil
}

// MDMIdentifier always resolves to the empty identifier; no consumer of this
// double configures MDM lookups.
func (f *FakeEnricher) MDMIdentifier(_ context.Context, _, _ string) (string, error) {
	return "", nil
}

// ArcConfig records the call and returns Arc, or ArcErr when set.
func (f *FakeEnricher) ArcConfig(_ context.Context, _, _ string) (*events.ArcConfig, error) {
	f.mu.Lock()
	f.arcCalls++
	f.mu.Unlock()
	if f.ArcErr != nil {
		return nil, f.ArcErr
	}
	return f.Arc, nil
}

// ArcCalls reports how many times ArcConfig has been called.
func (f *FakeEnricher) ArcCalls() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.arcCalls
}
