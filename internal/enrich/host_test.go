package enrich

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/crowdstrike/falcon-integration-gateway/internal/events"
	"github.com/crowdstrike/falcon-integration-gateway/internal/falcon/client"
)

func TestHostDetails_CacheMiss_FetchesAndMaps(t *testing.T) {
	t.Parallel()

	fake := &fakeClient{
		ddDevices: []*client.Device{
			{
				DeviceID:                 "dev-1",
				PlatformName:             "Windows",
				InstanceID:               "i-abc123",
				ServiceProvider:          "AWS_EC2_V2",
				ServiceProviderAccountID: "1234567890",
			},
		},
	}
	e := newTestResolver(fake)

	h, err := e.HostDetails(context.Background(), "sensor-1")
	if err != nil {
		t.Fatalf("HostDetails() unexpected error: %v", err)
	}
	if fake.deviceDetailsCalls() != 1 {
		t.Fatalf("DeviceDetails call count = %d, want 1", fake.deviceDetailsCalls())
	}
	if !h.Known {
		t.Error("Known = false, want true for a resolved device")
	}
	if h.SensorID != "sensor-1" {
		t.Errorf("SensorID = %q, want %q", h.SensorID, "sensor-1")
	}
	if h.CloudProvider != "AWS_EC2_V2" {
		t.Errorf("CloudProvider = %q, want %q (service_provider)", h.CloudProvider, "AWS_EC2_V2")
	}
	if h.CloudProviderAccountID != "1234567890" {
		t.Errorf("CloudProviderAccountID = %q, want %q", h.CloudProviderAccountID, "1234567890")
	}
	if h.InstanceID != "i-abc123" {
		t.Errorf("InstanceID = %q, want %q", h.InstanceID, "i-abc123")
	}
	if h.Platform != "Windows" {
		t.Errorf("Platform = %q, want %q (platform_name)", h.Platform, "Windows")
	}
	if h.DeviceID != "dev-1" {
		t.Errorf("DeviceID = %q, want %q", h.DeviceID, "dev-1")
	}
}

func TestHostDetails_Unresolvable_ReturnsUnknown(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		devices []*client.Device
	}{
		{name: "no devices", devices: nil},
		{
			name: "multiple devices",
			devices: []*client.Device{
				{DeviceID: "dev-1"},
				{DeviceID: "dev-2"},
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			fake := &fakeClient{ddDevices: tc.devices}
			e := newTestResolver(fake)

			h, err := e.HostDetails(context.Background(), "sensor-x")
			if err != nil {
				t.Fatalf("HostDetails() unexpected error: %v", err)
			}
			if h.Known {
				t.Error("Known = true, want false for an unresolvable sensor")
			}
			if h.CloudProvider != "" {
				t.Errorf("CloudProvider = %q, want empty for an unresolvable sensor", h.CloudProvider)
			}
		})
	}
}

func TestHostDetails_CacheHit_NoRefetch(t *testing.T) {
	t.Parallel()

	fake := &fakeClient{
		ddDevices: []*client.Device{{DeviceID: "dev-1", ServiceProvider: "AWS_EC2_V2"}},
	}
	e := newTestResolver(fake)

	first, err := e.HostDetails(context.Background(), "sensor-1")
	if err != nil {
		t.Fatalf("first HostDetails() error: %v", err)
	}
	second, err := e.HostDetails(context.Background(), "sensor-1")
	if err != nil {
		t.Fatalf("second HostDetails() error: %v", err)
	}

	if fake.deviceDetailsCalls() != 1 {
		t.Fatalf("DeviceDetails call count = %d, want 1 (second lookup must hit cache)", fake.deviceDetailsCalls())
	}
	if first.CloudProvider != second.CloudProvider {
		t.Errorf("cached result differs: first=%q second=%q", first.CloudProvider, second.CloudProvider)
	}
}

func TestHostDetails_Unresolvable_NotCached(t *testing.T) {
	t.Parallel()

	fake := &fakeClient{ddDevices: nil} // unresolvable
	e := newTestResolver(fake)

	for i := range 3 {
		h, err := e.HostDetails(context.Background(), "sensor-x")
		if err != nil {
			t.Fatalf("HostDetails() call %d error: %v", i, err)
		}
		if h.Known {
			t.Fatalf("call %d: Known = true, want false", i)
		}
	}

	// An unresolvable outcome is not cached: a sensor absent from the Hosts API
	// today may resolve moments later once enrollment propagates, so each lookup
	// re-fetches rather than replaying a stale "unknown" for the full cache TTL.
	if fake.deviceDetailsCalls() != 3 {
		t.Fatalf("DeviceDetails call count = %d, want 3 (unresolvable must not be cached)", fake.deviceDetailsCalls())
	}
}

func TestHostDetails_Resolved_AfterUnresolvable(t *testing.T) {
	t.Parallel()

	// The first lookup finds no device (freshly-enrolled sensor not yet visible);
	// the second finds it. Because the miss was not cached, the second lookup must
	// return the resolved host rather than a stale "unknown".
	fake := &fakeClient{ddDevices: nil}
	e := newTestResolver(fake)

	first, err := e.HostDetails(context.Background(), "sensor-1")
	if err != nil {
		t.Fatalf("first HostDetails() error: %v", err)
	}
	if first.Known {
		t.Fatal("first lookup: Known = true, want false before the device is visible")
	}

	fake.mu.Lock()
	fake.ddDevices = []*client.Device{{DeviceID: "dev-1", ServiceProvider: "AWS_EC2_V2"}}
	fake.mu.Unlock()

	second, err := e.HostDetails(context.Background(), "sensor-1")
	if err != nil {
		t.Fatalf("second HostDetails() error: %v", err)
	}
	if !second.Known {
		t.Fatal("second lookup: Known = false, want true once the device is visible")
	}
	if second.CloudProvider != "AWS_EC2_V2" {
		t.Errorf("second lookup: CloudProvider = %q, want %q", second.CloudProvider, "AWS_EC2_V2")
	}
}

func TestHostDetails_TransientError_RetriesThenSucceeds(t *testing.T) {
	t.Parallel()

	fake := &fakeClient{
		ddErr:     errors.New("temporary transport failure"),
		ddErrN:    2, // first two attempts fail, third succeeds
		ddDevices: []*client.Device{{DeviceID: "dev-1", ServiceProvider: "AWS_EC2_V2"}},
	}
	e := newTestResolver(fake) // maxTries = 3

	h, err := e.HostDetails(context.Background(), "sensor-1")
	if err != nil {
		t.Fatalf("HostDetails() error after retries: %v", err)
	}
	if !h.Known {
		t.Error("Known = false, want true after a successful retry")
	}
	if fake.deviceDetailsCalls() != 3 {
		t.Fatalf("DeviceDetails call count = %d, want 3 (two failures then success)", fake.deviceDetailsCalls())
	}
}

func TestHostDetails_TransientError_NotCached(t *testing.T) {
	t.Parallel()

	fake := &fakeClient{
		ddErr:  errors.New("persistent transport failure"),
		ddErrN: 1000, // always fails
	}
	e := newTestResolver(fake) // maxTries = 3

	if _, err := e.HostDetails(context.Background(), "sensor-1"); err == nil {
		t.Fatal("first HostDetails() = nil error, want a transient failure")
	}
	if _, err := e.HostDetails(context.Background(), "sensor-1"); err == nil {
		t.Fatal("second HostDetails() = nil error, want a transient failure")
	}

	// Two lookups × three tries each: the error must never be cached, so the
	// second lookup re-fetches rather than replaying a cached failure.
	if fake.deviceDetailsCalls() != 6 {
		t.Fatalf("DeviceDetails call count = %d, want 6 (transient errors must not be cached)", fake.deviceDetailsCalls())
	}
}

func TestHostDetails_SingleflightCollapse(t *testing.T) {
	t.Parallel()

	const n = 8
	// arrived is closed once all n goroutines are parked inside DeviceDetails;
	// release unblocks them together so a non-collapsing implementation would
	// record n fetches and this test would fail.
	var wg sync.WaitGroup
	arrived := make(chan struct{}, n)
	release := make(chan struct{})

	fake := &fakeClient{
		ddDevices: []*client.Device{{DeviceID: "dev-1", ServiceProvider: "AWS_EC2_V2"}},
		ddHook: func() {
			arrived <- struct{}{}
			<-release
		},
	}
	e := newTestResolver(fake)

	results := make([]*events.HostDetails, n)
	errs := make([]error, n)
	wg.Add(n)
	for i := range n {
		go func() {
			defer wg.Done()
			results[i], errs[i] = e.HostDetails(context.Background(), "sensor-1")
		}()
	}

	// Wait until the first caller is parked in the fetch, then release everyone.
	// A singleflight-collapsed implementation only enters the hook once, so we
	// gate on a single arrival before releasing.
	<-arrived
	close(release)
	wg.Wait()

	for i := range n {
		if errs[i] != nil {
			t.Fatalf("goroutine %d: HostDetails() error: %v", i, errs[i])
		}
		if results[i] == nil || !results[i].Known {
			t.Fatalf("goroutine %d: got %+v, want a known host", i, results[i])
		}
	}
	if fake.deviceDetailsCalls() != 1 {
		t.Fatalf("DeviceDetails call count = %d, want 1 (concurrent misses must collapse)", fake.deviceDetailsCalls())
	}
}
