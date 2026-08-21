package enrich

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/cenkalti/backoff/v5"

	"github.com/crowdstrike/falcon-integration-gateway/internal/common"
	"github.com/crowdstrike/falcon-integration-gateway/internal/config"
	"github.com/crowdstrike/falcon-integration-gateway/internal/falcon/client"
	"github.com/crowdstrike/falcon-integration-gateway/internal/testutil"
)

func TestNew_ReturnsUsableResolver(t *testing.T) {
	t.Parallel()

	fake := &fakeClient{
		ddDevices: []*common.HostDetails{
			{DeviceID: "dev-1", Platform: "Windows", CloudProvider: "AWS_EC2_V2"},
		},
	}
	cfg := &config.Config{Cache: config.CacheConfig{Size: 8192, TTLDuration: time.Hour}}

	e, err := New(Params{Config: cfg, Client: fake, Logger: testutil.DiscardLogger()})
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
	cfg := &config.Config{Cache: config.CacheConfig{Size: 8192, TTLDuration: time.Hour}}

	e, err := New(Params{Config: cfg, Client: fake, Logger: testutil.DiscardLogger()})
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
		cfg := &config.Config{Cache: config.CacheConfig{Size: size, TTLDuration: time.Hour}}
		e, err := New(Params{Config: cfg, Client: &fakeClient{}, Logger: testutil.DiscardLogger()})
		if err == nil {
			t.Fatalf("New(size=%d) error = nil, want non-nil", size)
		}
		if e != nil {
			t.Fatalf("New(size=%d) enricher = %v, want nil", size, e)
		}
	}
}

// fakeClient is a hermetic, call-recording implementation of the HostRTRClient
// seam. It lets tests drive the enricher without any network access, asserting
// on call counts (cache/singleflight behavior) and on the exact RTR command
// issued (MDM parity).
type fakeClient struct {
	mu sync.Mutex

	// DeviceDetails control.
	ddCalls   int
	ddHook    func()                // called at entry, before locking, for gating concurrency
	ddErr     error                 // error returned while ddErrN > 0
	ddErrN    int                   // number of leading calls that return ddErr
	ddDevices []*common.HostDetails // returned once ddErrN is exhausted

	// RTR control.
	initCalls, execCalls, statusCalls, deleteCalls int
	initHook                                       func() // called at entry, before locking, for gating concurrency
	statusHook                                     func() // called at entry of CheckRTRCommandStatus
	initSess                                       *client.RTRSession
	initErr                                        error
	execRes                                        *client.RTRCommandResult
	execErr                                        error
	statuses                                       []*client.RTRCommandStatus // returned in order; last repeats
	statusErr                                      error
	deleteErr                                      error
	deleteCtxErr                                   error // ctx.Err() captured at DeleteRTRSession call time
	lastCmd                                        client.RTRCommand

	// RTRFetchFile control.
	fetchCalls           int
	lastFetchID          string // deviceID passed to the most recent RTRFetchFile
	lastFetchPath        string // filepath passed to the most recent RTRFetchFile
	lastFetchHasDeadline bool   // whether the ctx passed to RTRFetchFile carried a deadline
	fetchBytes           []byte // raw archive bytes returned when fetchErr is nil
	fetchErr             error
}

func (f *fakeClient) DeviceDetails(_ context.Context, _ string) ([]*common.HostDetails, error) {
	if f.ddHook != nil {
		f.ddHook()
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.ddCalls++
	if f.ddErrN > 0 {
		f.ddErrN--
		return nil, f.ddErr
	}
	return f.ddDevices, nil
}

func (f *fakeClient) InitRTRSession(_ context.Context, _ string) (*client.RTRSession, error) {
	if f.initHook != nil {
		f.initHook()
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.initCalls++
	if f.initErr != nil {
		return nil, f.initErr
	}
	return f.initSess, nil
}

func (f *fakeClient) ExecuteRTRCommand(_ context.Context, cmd client.RTRCommand) (*client.RTRCommandResult, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.execCalls++
	f.lastCmd = cmd
	if f.execErr != nil {
		return nil, f.execErr
	}
	return f.execRes, nil
}

func (f *fakeClient) CheckRTRCommandStatus(_ context.Context, _ string, _ int) (*client.RTRCommandStatus, error) {
	if f.statusHook != nil {
		f.statusHook()
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.statusCalls++
	if f.statusErr != nil {
		return nil, f.statusErr
	}
	i := f.statusCalls - 1
	if i >= len(f.statuses) {
		i = len(f.statuses) - 1
	}
	return f.statuses[i], nil
}

func (f *fakeClient) DeleteRTRSession(ctx context.Context, _ string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.deleteCalls++
	f.deleteCtxErr = ctx.Err()
	return f.deleteErr
}

func (f *fakeClient) deviceDetailsCalls() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.ddCalls
}

func (f *fakeClient) RTRFetchFile(ctx context.Context, deviceID, filepath string) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.fetchCalls++
	f.lastFetchID = deviceID
	f.lastFetchPath = filepath
	_, f.lastFetchHasDeadline = ctx.Deadline()
	if f.fetchErr != nil {
		return nil, f.fetchErr
	}
	return f.fetchBytes, nil
}

// newTestResolver builds a Resolver wired to a hermetic fake with a sleepless
// backoff, tiny poll interval, and short MDM timeout so tests stay fast and
// deterministic.
func newTestResolver(c HostRTRClient) *Resolver {
	return &Resolver{
		client:       c,
		logger:       testutil.DiscardLogger(),
		hosts:        newSingleflightCache[*common.HostDetails](128, time.Hour),
		mdm:          newSingleflightCache[string](128, time.Hour),
		arc:          newSingleflightCache[arcResult](128, time.Hour),
		arcKeyword:   "infected",
		newBackOff:   func() backoff.BackOff { return &backoff.ZeroBackOff{} },
		maxTries:     3,
		pollInterval: time.Millisecond,
		mdmTimeout:   50 * time.Millisecond,
		arcTimeout:   50 * time.Millisecond,
	}
}
