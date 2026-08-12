package enrich

import (
	"context"
	"sync"
	"testing"

	"github.com/crowdstrike/falcon-integration-gateway/internal/falcon/client"
)

// RTR command strings the MDM parity tests assert against.
const (
	wantWinCommand = `reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Provisioning\OMADM\MDMDeviceID" DeviceClientId`
	wantMacCommand = "runscript -Raw=```system_profiler SPHardwareDataType | awk '/UUID/ { print $3; }'```"
)

func TestMDMIdentifier_SingleflightCollapse(t *testing.T) {
	t.Parallel()

	const n = 8
	// arrived signals a goroutine has parked inside InitRTRSession; release
	// unblocks them together so a non-collapsing implementation would open n
	// sessions and this test would fail.
	var wg sync.WaitGroup
	arrived := make(chan struct{}, n)
	release := make(chan struct{})

	fake := &fakeClient{
		initSess: &client.RTRSession{SessionID: "sess-1"},
		execRes:  &client.RTRCommandResult{CloudRequestID: "req-1"},
		statuses: []*client.RTRCommandStatus{{Complete: true, Stdout: "X = MDM-42\n"}},
		initHook: func() {
			arrived <- struct{}{}
			<-release
		},
	}
	e := newTestResolver(fake)

	ids := make([]string, n)
	errs := make([]error, n)
	wg.Add(n)
	for i := range n {
		go func() {
			defer wg.Done()
			ids[i], errs[i] = e.MDMIdentifier(context.Background(), "sensor-1", "Windows")
		}()
	}

	// A collapsed implementation only enters InitRTRSession once, so gate on a
	// single arrival before releasing everyone.
	<-arrived
	close(release)
	wg.Wait()

	for i := range n {
		if errs[i] != nil {
			t.Fatalf("goroutine %d: MDMIdentifier() error: %v", i, errs[i])
		}
		if ids[i] != "MDM-42" {
			t.Fatalf("goroutine %d: id = %q, want %q", i, ids[i], "MDM-42")
		}
	}
	if fake.initCalls != 1 {
		t.Fatalf("InitRTRSession calls = %d, want 1 (concurrent MDM lookups must collapse)", fake.initCalls)
	}
}

func TestMDMIdentifier_HappyPath(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		platform    string
		stdout      string
		wantCommand string
		wantBase    string
		wantAdmin   bool
		wantID      string
	}{
		{
			name:        "windows",
			platform:    "Windows",
			stdout:      "    DeviceClientId    REG_SZ = ABC-123-DEF\r\ntrailing junk",
			wantCommand: wantWinCommand,
			wantBase:    "reg query",
			wantAdmin:   false,
			wantID:      "ABC-123-DEF\r", // split(' = ')[1] then split('\n')[0], matching legacy parse
		},
		{
			name:        "mac",
			platform:    "Mac",
			stdout:      "11111111-2222-3333-4444-555555555555\nother line",
			wantCommand: wantMacCommand,
			wantBase:    "runscript",
			wantAdmin:   true,
			wantID:      "11111111-2222-3333-4444-555555555555",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			fake := &fakeClient{
				initSess: &client.RTRSession{SessionID: "sess-1"},
				execRes:  &client.RTRCommandResult{CloudRequestID: "cr-1", SessionID: "sess-1"},
				statuses: []*client.RTRCommandStatus{{Complete: true, Stdout: tc.stdout}},
			}
			e := newTestResolver(fake)

			id, err := e.MDMIdentifier(context.Background(), "sensor-1", tc.platform)
			if err != nil {
				t.Fatalf("MDMIdentifier() error: %v", err)
			}
			if id != tc.wantID {
				t.Errorf("id = %q, want %q", id, tc.wantID)
			}
			if fake.lastCmd.CommandString != tc.wantCommand {
				t.Errorf("command string = %q, want %q", fake.lastCmd.CommandString, tc.wantCommand)
			}
			if fake.lastCmd.BaseCommand != tc.wantBase {
				t.Errorf("base command = %q, want %q", fake.lastCmd.BaseCommand, tc.wantBase)
			}
			if fake.lastCmd.Admin != tc.wantAdmin {
				t.Errorf("admin = %v, want %v", fake.lastCmd.Admin, tc.wantAdmin)
			}
			if fake.deleteCalls != 1 {
				t.Errorf("DeleteRTRSession calls = %d, want 1 (session must always be closed)", fake.deleteCalls)
			}
		})
	}
}

func TestMDMIdentifier_PollsUntilComplete(t *testing.T) {
	t.Parallel()

	fake := &fakeClient{
		initSess: &client.RTRSession{SessionID: "sess-1"},
		execRes:  &client.RTRCommandResult{CloudRequestID: "cr-1"},
		statuses: []*client.RTRCommandStatus{
			{Complete: false},
			{Complete: false},
			{Complete: true, Stdout: "  X  REG_SZ = FINAL-ID\n"},
		},
	}
	e := newTestResolver(fake)

	id, err := e.MDMIdentifier(context.Background(), "sensor-1", "Windows")
	if err != nil {
		t.Fatalf("MDMIdentifier() error: %v", err)
	}
	if id != "FINAL-ID" {
		t.Errorf("id = %q, want %q (must wait for the completed status)", id, "FINAL-ID")
	}
	if fake.statusCalls != 3 {
		t.Errorf("CheckRTRCommandStatus calls = %d, want 3 (must poll until complete)", fake.statusCalls)
	}
	if fake.deleteCalls != 1 {
		t.Errorf("DeleteRTRSession calls = %d, want 1", fake.deleteCalls)
	}
}

func TestMDMIdentifier_PollTimeout_Errors(t *testing.T) {
	t.Parallel()

	fake := &fakeClient{
		initSess: &client.RTRSession{SessionID: "sess-1"},
		execRes:  &client.RTRCommandResult{CloudRequestID: "cr-1"},
		statuses: []*client.RTRCommandStatus{{Complete: false}}, // never completes
	}
	e := newTestResolver(fake) // mdmTimeout = 50ms, pollInterval = 1ms

	_, err := e.MDMIdentifier(context.Background(), "sensor-1", "Windows")
	if err == nil {
		t.Fatal("MDMIdentifier() = nil error, want a timeout error when the command never completes")
	}
	if fake.deleteCalls != 1 {
		t.Errorf("DeleteRTRSession calls = %d, want 1 (session must close even on timeout)", fake.deleteCalls)
	}
}

func TestMDMIdentifier_Stderr_YieldsEmpty(t *testing.T) {
	t.Parallel()

	fake := &fakeClient{
		initSess: &client.RTRSession{SessionID: "sess-1"},
		execRes:  &client.RTRCommandResult{CloudRequestID: "cr-1"},
		statuses: []*client.RTRCommandStatus{
			{Complete: true, Stdout: "X = SHOULD-BE-IGNORED", Stderr: "access denied"},
		},
	}
	e := newTestResolver(fake)

	id, err := e.MDMIdentifier(context.Background(), "sensor-1", "Windows")
	if err != nil {
		t.Fatalf("MDMIdentifier() error: %v", err)
	}
	if id != "" {
		t.Errorf("id = %q, want empty when the command wrote to stderr", id)
	}
}

func TestMDMIdentifier_Unsupported_NoSession(t *testing.T) {
	t.Parallel()

	fake := &fakeClient{}
	e := newTestResolver(fake)

	id, err := e.MDMIdentifier(context.Background(), "sensor-1", "Linux")
	if err != nil {
		t.Fatalf("MDMIdentifier() error: %v", err)
	}
	if id != "" {
		t.Errorf("id = %q, want empty for an unsupported platform", id)
	}
	if fake.initCalls != 0 {
		t.Errorf("InitRTRSession calls = %d, want 0 (no session for unsupported platform)", fake.initCalls)
	}
}

func TestMDMIdentifier_Cached_NoRerun(t *testing.T) {
	t.Parallel()

	fake := &fakeClient{
		initSess: &client.RTRSession{SessionID: "sess-1"},
		execRes:  &client.RTRCommandResult{CloudRequestID: "cr-1"},
		statuses: []*client.RTRCommandStatus{{Complete: true, Stdout: "X = CACHED-ID\n"}},
	}
	e := newTestResolver(fake)

	for i := range 3 {
		id, err := e.MDMIdentifier(context.Background(), "sensor-1", "Windows")
		if err != nil {
			t.Fatalf("call %d: MDMIdentifier() error: %v", i, err)
		}
		if id != "CACHED-ID" {
			t.Fatalf("call %d: id = %q, want %q", i, id, "CACHED-ID")
		}
	}
	if fake.initCalls != 1 {
		t.Errorf("InitRTRSession calls = %d, want 1 (result must be cached)", fake.initCalls)
	}
}

func TestMDMIdentifier_CtxCancelled_SessionStillClosed(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())

	fake := &fakeClient{
		initSess: &client.RTRSession{SessionID: "sess-1"},
		execRes:  &client.RTRCommandResult{CloudRequestID: "cr-1"},
		statuses: []*client.RTRCommandStatus{{Complete: false}}, // never completes
	}
	// Cancel the caller's context on the first status poll, simulating a shutdown
	// mid-lookup. The command never completes, so the poll then observes the
	// cancellation and returns an error.
	fake.statusHook = func() { cancel() }
	e := newTestResolver(fake)

	_, err := e.MDMIdentifier(ctx, "sensor-1", "Windows")
	if err == nil {
		t.Fatal("MDMIdentifier() = nil error, want a cancellation error")
	}
	if fake.deleteCalls != 1 {
		t.Fatalf("DeleteRTRSession calls = %d, want 1 (session must close on cancellation)", fake.deleteCalls)
	}
	// The session cleanup must run under a fresh context, not the caller's
	// cancelled one — otherwise a real client would short-circuit the delete and
	// leak the RTR session server-side.
	if fake.deleteCtxErr != nil {
		t.Errorf("DeleteRTRSession context error = %v, want nil (cleanup must use a live context)", fake.deleteCtxErr)
	}
}
