package enrich

import (
	"context"
	"sync"
	"time"

	"github.com/cenkalti/backoff/v5"
	"github.com/hashicorp/golang-lru/v2/expirable"

	"github.com/crowdstrike/falcon-integration-gateway/internal/events"
	"github.com/crowdstrike/falcon-integration-gateway/internal/falcon/client"
	"github.com/crowdstrike/falcon-integration-gateway/internal/testutil"
)

// fakeClient is a hermetic, call-recording implementation of the HostRTRClient
// seam. It lets tests drive the enricher without any network access, asserting
// on call counts (cache/singleflight behavior) and on the exact RTR command
// issued (MDM parity).
type fakeClient struct {
	mu sync.Mutex

	// DeviceDetails control.
	ddCalls   int
	ddHook    func()           // called at entry, before locking, for gating concurrency
	ddErr     error            // error returned while ddErrN > 0
	ddErrN    int              // number of leading calls that return ddErr
	ddDevices []*client.Device // returned once ddErrN is exhausted

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
}

func (f *fakeClient) DeviceDetails(_ context.Context, _ string) ([]*client.Device, error) {
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

// newTestResolver builds a Resolver wired to a hermetic fake with a sleepless
// backoff, tiny poll interval, and short MDM timeout so tests stay fast and
// deterministic.
func newTestResolver(c HostRTRClient) *Resolver {
	return &Resolver{
		client:       c,
		logger:       testutil.DiscardLogger(),
		hostCache:    expirable.NewLRU[string, *events.HostDetails](128, nil, time.Hour),
		mdmCache:     expirable.NewLRU[string, string](128, nil, time.Hour),
		newBackOff:   func() backoff.BackOff { return &backoff.ZeroBackOff{} },
		maxTries:     3,
		pollInterval: time.Millisecond,
		mdmTimeout:   50 * time.Millisecond,
	}
}
