package enrich

import (
	"context"
	"testing"
	"time"

	"github.com/crowdstrike/falcon-integration-gateway/internal/config"
	"github.com/crowdstrike/falcon-integration-gateway/internal/falcon/client"
	"github.com/crowdstrike/falcon-integration-gateway/internal/testutil"
)

func TestNew_ReturnsUsableResolver(t *testing.T) {
	t.Parallel()

	fake := &fakeClient{
		ddDevices: []*client.Device{
			{DeviceID: "dev-1", PlatformName: "Windows", ServiceProvider: "AWS_EC2_V2"},
		},
	}
	cfg := &config.Config{Enrich: config.EnrichConfig{CacheSize: 8192, CacheTTLDuration: time.Hour}}

	e, err := New(cfg, fake, testutil.DiscardLogger())
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}
	if e == nil {
		t.Fatal("New() returned nil resolver")
	}

	// A working HostDetails lookup proves the host cache and backoff function
	// were wired: a nil cache panics on Get, a nil newBackOff panics on call.
	h, err := e.HostDetails(context.Background(), "sensor-1")
	if err != nil {
		t.Fatalf("HostDetails() error: %v", err)
	}
	if !h.Known || h.CloudProvider != "AWS_EC2_V2" {
		t.Fatalf("HostDetails() = %+v, want Known with CloudProvider AWS_EC2_V2", h)
	}
}

func TestNew_MDMTimingDefaultsAreUsable(t *testing.T) {
	t.Parallel()

	fake := &fakeClient{
		initSess: &client.RTRSession{SessionID: "sess-1"},
		execRes:  &client.RTRCommandResult{CloudRequestID: "req-1"},
		statuses: []*client.RTRCommandStatus{
			{Complete: true, Stdout: "DeviceClientId    REG_SZ = MDM-9\r\n"},
		},
	}
	cfg := &config.Config{Enrich: config.EnrichConfig{CacheSize: 8192, CacheTTLDuration: time.Hour}}

	e, err := New(cfg, fake, testutil.DiscardLogger())
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}

	// A non-zero poll interval is required or time.NewTicker panics; a non-zero
	// timeout is required or the poll deadline fires before the first check.
	id, err := e.MDMIdentifier(context.Background(), "sensor-1", "Windows")
	if err != nil {
		t.Fatalf("MDMIdentifier() error: %v", err)
	}
	if id != "MDM-9\r" {
		t.Fatalf("MDMIdentifier() = %q, want %q", id, "MDM-9\r")
	}
}

func TestNew_RejectsInvalidCacheSize(t *testing.T) {
	t.Parallel()

	for _, size := range []int{0, -1} {
		cfg := &config.Config{Enrich: config.EnrichConfig{CacheSize: size, CacheTTLDuration: time.Hour}}
		e, err := New(cfg, &fakeClient{}, testutil.DiscardLogger())
		if err == nil {
			t.Fatalf("New(cache_size=%d) error = nil, want non-nil", size)
		}
		if e != nil {
			t.Fatalf("New(cache_size=%d) enricher = %v, want nil", size, e)
		}
	}
}
