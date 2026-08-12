package events

import (
	"context"
	"errors"
	"sync"
	"testing"
)

// fakeEnricher is a hand-written Enricher double that records how many times
// each method is called and returns configured values/errors.
type fakeEnricher struct {
	mu sync.Mutex

	host    *HostDetails
	hostErr error
	mdm     string
	mdmErr  error

	hostCalls int
	mdmCalls  int

	lastHostSensorID string
	lastMDMSensorID  string
	lastMDMPlatform  string
}

func (f *fakeEnricher) HostDetails(_ context.Context, sensorID string) (*HostDetails, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.hostCalls++
	f.lastHostSensorID = sensorID
	return f.host, f.hostErr
}

func (f *fakeEnricher) MDMIdentifier(_ context.Context, sensorID, platform string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.mdmCalls++
	f.lastMDMSensorID = sensorID
	f.lastMDMPlatform = platform
	return f.mdm, f.mdmErr
}

func (f *fakeEnricher) counts() (int, int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.hostCalls, f.mdmCalls
}

// eventWithSensor builds a bare *Event whose inner map carries the given
// SensorId, so SensorID() resolves during enrichment.
func eventWithSensor(sensorID string) *Event {
	return &Event{
		Metadata: Metadata{EventType: "EppDetectionSummaryEvent", Offset: 42},
		Event:    map[string]any{"SensorId": sensorID},
		FeedID:   "feed7",
	}
}

func TestEnrichedEvent_FieldAccessorsMemoizeSingleFetch(t *testing.T) {
	f := &fakeEnricher{host: &HostDetails{
		Known:                  true,
		DeviceID:               "dev-1",
		SensorID:               "sensor-1",
		CloudProvider:          "AWS",
		CloudProviderAccountID: "acct-1",
		InstanceID:             "i-abc",
		Platform:               "Windows",
	}}
	ee := NewEnrichedEvent(eventWithSensor("sensor-1"), f)
	ctx := context.Background()

	cp, err := ee.CloudProvider(ctx)
	if err != nil || cp != "AWS" {
		t.Fatalf("CloudProvider() = %q, %v; want AWS, nil", cp, err)
	}
	pl, err := ee.Platform(ctx)
	if err != nil || pl != "Windows" {
		t.Fatalf("Platform() = %q, %v; want Windows, nil", pl, err)
	}
	acct, err := ee.CloudProviderAccountID(ctx)
	if err != nil || acct != "acct-1" {
		t.Fatalf("CloudProviderAccountID() = %q, %v; want acct-1, nil", acct, err)
	}
	inst, err := ee.InstanceID(ctx)
	if err != nil || inst != "i-abc" {
		t.Fatalf("InstanceID() = %q, %v; want i-abc, nil", inst, err)
	}

	hostCalls, _ := f.counts()
	if hostCalls != 1 {
		t.Fatalf("HostDetails call count = %d; want exactly 1 (memoized)", hostCalls)
	}
	if f.lastHostSensorID != "sensor-1" {
		t.Fatalf("HostDetails called with sensorID %q; want sensor-1", f.lastHostSensorID)
	}
}

func TestEnrichedEvent_FieldAccessorsPropagateError(t *testing.T) {
	sentinel := errors.New("lookup boom")
	f := &fakeEnricher{hostErr: sentinel}
	ee := NewEnrichedEvent(eventWithSensor("sensor-2"), f)
	ctx := context.Background()

	for _, tc := range []struct {
		name string
		call func() (string, error)
	}{
		{"CloudProvider", func() (string, error) { return ee.CloudProvider(ctx) }},
		{"Platform", func() (string, error) { return ee.Platform(ctx) }},
		{"CloudProviderAccountID", func() (string, error) { return ee.CloudProviderAccountID(ctx) }},
		{"InstanceID", func() (string, error) { return ee.InstanceID(ctx) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := tc.call()
			if got != "" {
				t.Errorf("%s value = %q; want empty on error", tc.name, got)
			}
			if !errors.Is(err, sentinel) {
				t.Errorf("%s err = %v; want sentinel", tc.name, err)
			}
		})
	}

	// The error path is also memoized: one fetch feeds all four accessors.
	if hostCalls, _ := f.counts(); hostCalls != 1 {
		t.Fatalf("HostDetails call count = %d; want exactly 1 (error memoized)", hostCalls)
	}
}

func TestEnrichedEvent_PromotesEmbeddedEventAccessors(t *testing.T) {
	ev := eventWithSensor("sensor-3")
	ee := NewEnrichedEvent(ev, &fakeEnricher{host: &HostDetails{}})

	if ee.EventType() != "EppDetectionSummaryEvent" {
		t.Errorf("promoted EventType() = %q; want EppDetectionSummaryEvent", ee.EventType())
	}
	if ee.Offset() != 42 {
		t.Errorf("promoted Offset() = %d; want 42", ee.Offset())
	}
	if ee.SensorID() != "sensor-3" {
		t.Errorf("promoted SensorID() = %q; want sensor-3", ee.SensorID())
	}
}

func TestEnrichedEvent_MDMIdentifierFetchesPlatformFirst(t *testing.T) {
	f := &fakeEnricher{
		host: &HostDetails{Platform: "Mac"},
		mdm:  "mdm-xyz",
	}
	ee := NewEnrichedEvent(eventWithSensor("sensor-4"), f)

	got, err := ee.MDMIdentifier(context.Background())
	if err != nil {
		t.Fatalf("MDMIdentifier() error: %v", err)
	}
	if got != "mdm-xyz" {
		t.Errorf("MDMIdentifier() = %q; want mdm-xyz", got)
	}
	if f.lastMDMPlatform != "Mac" {
		t.Errorf("MDMIdentifier called with platform %q; want Mac (from HostDetails)", f.lastMDMPlatform)
	}
	if f.lastMDMSensorID != "sensor-4" {
		t.Errorf("MDMIdentifier called with sensorID %q; want sensor-4", f.lastMDMSensorID)
	}
	hostCalls, mdmCalls := f.counts()
	if hostCalls != 1 || mdmCalls != 1 {
		t.Errorf("call counts host=%d mdm=%d; want 1 and 1", hostCalls, mdmCalls)
	}
}

func TestEnrichedEvent_MDMIdentifierSkippedWhenHostDetailsFails(t *testing.T) {
	sentinel := errors.New("host boom")
	f := &fakeEnricher{hostErr: sentinel}
	ee := NewEnrichedEvent(eventWithSensor("sensor-5"), f)

	got, err := ee.MDMIdentifier(context.Background())
	if got != "" {
		t.Errorf("MDMIdentifier() = %q; want empty on host error", got)
	}
	if !errors.Is(err, sentinel) {
		t.Errorf("MDMIdentifier() err = %v; want sentinel", err)
	}
	if _, mdmCalls := f.counts(); mdmCalls != 0 {
		t.Errorf("MDMIdentifier enricher call count = %d; want 0 (skipped on host error)", mdmCalls)
	}
}
