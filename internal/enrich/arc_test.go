package enrich

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/cenkalti/backoff/v5"
	"github.com/crowdstrike/falcon-integration-gateway/internal/common"
	"github.com/crowdstrike/falcon-integration-gateway/internal/events"
)

// loadFixture reads a shared 7z archive from the repo-root test/data tree; a
// read failure is a broken test setup, not a code defect, so it fails the test
// rather than the assertion.
func loadFixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile("../../test/data/" + name)
	if err != nil {
		t.Fatalf("read fixture %s: %v", name, err)
	}
	return b
}

func TestArcConfigResolvesFiveKeys(t *testing.T) {
	t.Parallel()
	f := &fakeClient{fetchBytes: loadFixture(t, "agentconfig.7z")}
	r := newTestResolver(f)

	got, err := r.ArcConfig(context.Background(), "sensor-1", "Linux")
	if err != nil {
		t.Fatalf("ArcConfig() error: %v", err)
	}
	want := &events.ArcConfig{
		ResourceName:   "fig-arc-host",
		ResourceGroup:  "fig-rg",
		SubscriptionID: "11111111-2222-3333-4444-555555555555",
		TenantID:       "66666666-7777-8888-9999-000000000000",
		VMID:           "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
	}
	if *got != *want {
		t.Errorf("ArcConfig() = %+v; want %+v", *got, *want)
	}
}

func TestArcConfigSelectsPathByPlatform(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		platform string
		wantPath string
	}{
		{"linux", "Linux", linuxArcConfigPath},
		{"windows", "Windows", windowsArcConfigPath},
		{"unknown defaults to windows", "", windowsArcConfigPath},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			f := &fakeClient{fetchBytes: loadFixture(t, "agentconfig.7z")}
			r := newTestResolver(f)

			if _, err := r.ArcConfig(context.Background(), "sensor-x", tc.platform); err != nil {
				t.Fatalf("ArcConfig() error: %v", err)
			}
			if f.lastFetchPath != tc.wantPath {
				t.Errorf("fetch path = %q; want %q", f.lastFetchPath, tc.wantPath)
			}
			if f.lastFetchID != "sensor-x" {
				t.Errorf("fetch deviceID = %q; want sensor-x", f.lastFetchID)
			}
		})
	}
}

func TestArcConfigErrorPaths(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		bytes    []byte
		keyword  string
		fetchErr error
	}{
		{"wrong password", nil, "wrongpass", nil},         // bytes set below to agentconfig
		{"non-single-file archive", nil, "infected", nil}, // bytes set below to multi
		{"fetch failure", nil, "infected", errors.New("rtr down")},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			f := &fakeClient{fetchErr: tc.fetchErr}
			switch tc.name {
			case "wrong password":
				f.fetchBytes = loadFixture(t, "agentconfig.7z")
			case "non-single-file archive":
				f.fetchBytes = loadFixture(t, "multi.7z")
			}
			r := newTestResolver(f)
			r.arcKeyword = tc.keyword

			got, err := r.ArcConfig(context.Background(), "sensor-e", "Linux")
			if err == nil {
				t.Fatalf("ArcConfig() = %+v, nil; want error", got)
			}
			if got != nil {
				t.Errorf("ArcConfig() value = %+v; want nil on error", got)
			}
		})
	}
}

func TestArcConfigCachesSuccessAndFailure(t *testing.T) {
	t.Parallel()

	t.Run("success cached", func(t *testing.T) {
		t.Parallel()
		f := &fakeClient{fetchBytes: loadFixture(t, "agentconfig.7z")}
		r := newTestResolver(f)
		for range 3 {
			if _, err := r.ArcConfig(context.Background(), "sensor-c", "Linux"); err != nil {
				t.Fatalf("ArcConfig() error: %v", err)
			}
		}
		if f.fetchCalls != 1 {
			t.Errorf("RTRFetchFile calls = %d; want 1 (result cached)", f.fetchCalls)
		}
	})

	t.Run("failure negatively cached", func(t *testing.T) {
		t.Parallel()
		f := &fakeClient{fetchErr: errors.New("rtr down")}
		r := newTestResolver(f)
		for range 3 {
			if _, err := r.ArcConfig(context.Background(), "sensor-n", "Linux"); err == nil {
				t.Fatal("ArcConfig() = nil error; want error")
			}
		}
		if f.fetchCalls != 1 {
			t.Errorf("RTRFetchFile calls = %d; want 1 (failure negatively cached)", f.fetchCalls)
		}
	})
}

func TestArcConfigBoundsFetchWithDeadline(t *testing.T) {
	t.Parallel()
	f := &fakeClient{fetchBytes: loadFixture(t, "agentconfig.7z")}
	r := newTestResolver(f)

	// The pipeline delivers on a long-lived context with no deadline, so the arc
	// fetch must impose its own bound rather than rely on the caller: a dead
	// sensor's RTR poll would otherwise wedge a worker indefinitely.
	if _, err := r.ArcConfig(context.Background(), "sensor-d", "Linux"); err != nil {
		t.Fatalf("ArcConfig() error: %v", err)
	}
	if !f.lastFetchHasDeadline {
		t.Error("RTRFetchFile ctx had no deadline; arc fetch must bound the RTR poll")
	}
}

func TestArcConfigNeverLogsKeyword(t *testing.T) {
	t.Parallel()
	const secret = "sup3r-s3cret-keyword"
	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))

	// A non-single-file archive forces the decode-failure log path.
	f := &fakeClient{fetchBytes: loadFixture(t, "multi.7z")}
	r := &Resolver{
		client:       f,
		logger:       logger,
		hosts:        newSingleflightCache[*common.HostDetails](128, time.Hour),
		mdm:          newSingleflightCache[string](128, time.Hour),
		arc:          newSingleflightCache[arcResult](128, time.Hour),
		arcKeyword:   secret,
		newBackOff:   func() backoff.BackOff { return &backoff.ZeroBackOff{} },
		maxTries:     3,
		pollInterval: time.Millisecond,
		mdmTimeout:   50 * time.Millisecond,
		arcTimeout:   50 * time.Millisecond,
	}

	if _, err := r.ArcConfig(context.Background(), "sensor-l", "Linux"); err == nil {
		t.Fatal("ArcConfig() = nil error; want error")
	}
	if strings.Contains(buf.String(), secret) {
		t.Errorf("log output leaked the quarantine keyword: %s", buf.String())
	}
}
