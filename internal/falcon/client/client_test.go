package client

import (
	"context"
	"errors"
	"sync"
	"testing"

	apiclient "github.com/crowdstrike/gofalcon/falcon/client"
	"github.com/crowdstrike/gofalcon/falcon/client/hosts"
	"github.com/crowdstrike/gofalcon/falcon/client/real_time_response"
	"github.com/crowdstrike/gofalcon/falcon/client/real_time_response_admin"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"

	"github.com/crowdstrike/falcon-integration-gateway/internal/testutil"
)

// fakeTransport is a runtime.ClientTransport that returns a canned typed
// response (or error) per Submit call, recording every ClientOperation it
// receives so tests can assert on operation IDs and params. It replaces the
// real HTTP transport so the generated gofalcon methods run against in-memory
// responses without touching the network.
type fakeTransport struct {
	mu        sync.Mutex
	ops       []*runtime.ClientOperation
	responder func(op *runtime.ClientOperation) (any, error)
}

func (f *fakeTransport) Submit(op *runtime.ClientOperation) (any, error) {
	f.mu.Lock()
	f.ops = append(f.ops, op)
	f.mu.Unlock()
	return f.responder(op)
}

// opIDs returns the recorded operation IDs in call order.
func (f *fakeTransport) opIDs() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	ids := make([]string, len(f.ops))
	for i, op := range f.ops {
		ids[i] = op.ID
	}
	return ids
}

// newTestClient builds a Client whose gofalcon API is driven by ft, bypassing
// NewClient's OAuth flow so the enrichment methods can be exercised hermetically.
func newTestClient(ft *fakeTransport) *Client {
	return &Client{
		api:    apiclient.New(ft, strfmt.Default),
		logger: testutil.DiscardLogger(),
	}
}

func TestStreamAccessors(t *testing.T) {
	t.Parallel()

	s := Stream{
		token:           "tok-123",
		url:             "https://firehose.example.com/sensors/entities/datafeed/v1/abc123XYZ?appId=fig",
		refreshInterval: 1800,
		refreshURL:      "https://firehose.example.com/sensors/entities/datafeed-actions/v1/42?action_name=refresh_active_stream_session&appId=fig",
	}

	if s.Token() != "tok-123" {
		t.Errorf("Token() = %q, want %q", s.Token(), "tok-123")
	}
	if s.RefreshInterval() != 1800 {
		t.Errorf("RefreshInterval() = %d, want 1800", s.RefreshInterval())
	}

	feedID, err := s.FeedID()
	if err != nil {
		t.Fatalf("FeedID() unexpected error: %v", err)
	}
	if feedID != "abc123XYZ" {
		t.Errorf("FeedID() = %q, want %q", feedID, "abc123XYZ")
	}

	part, err := s.Partition()
	if err != nil {
		t.Fatalf("Partition() unexpected error: %v", err)
	}
	if part != 42 {
		t.Errorf("Partition() = %d, want 42", part)
	}
}

func TestStreamPartitionParseErrors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		refreshURL string
	}{
		{"no match", "https://example.com/wrong/path?x=1"},
		{"empty", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			s := Stream{refreshURL: tt.refreshURL}
			if _, err := s.Partition(); err == nil {
				t.Errorf("Partition() expected error for %q, got nil", tt.refreshURL)
			}
		})
	}
}

func TestStreamFeedIDParseErrors(t *testing.T) {
	t.Parallel()

	s := Stream{url: "https://example.com/no/feed/here?x=1"}
	if _, err := s.FeedID(); err == nil {
		t.Error("FeedID() expected error, got nil")
	}
}

func TestNoStreamsError(t *testing.T) {
	t.Parallel()

	err := &NoStreamsError{AppID: "fig-app"}
	var target *NoStreamsError
	if !errors.As(error(err), &target) {
		t.Fatal("errors.As did not match *NoStreamsError")
	}
	if target.AppID != "fig-app" {
		t.Errorf("AppID = %q, want %q", target.AppID, "fig-app")
	}
}

func strptr(s string) *string { return &s }

func TestDeviceDetailsMapsResources(t *testing.T) {
	t.Parallel()

	ft := &fakeTransport{responder: func(op *runtime.ClientOperation) (any, error) {
		return &hosts.GetDeviceDetailsV2OK{
			Payload: &models.DeviceapiDeviceDetailsResponseSwagger{
				Resources: []*models.DeviceapiDeviceSwagger{
					{
						DeviceID:                 strptr("dev-1"),
						Hostname:                 "host-1",
						PlatformName:             "Windows",
						InstanceID:               "i-abc123",
						ServiceProvider:          "AWS_EC2_V2",
						ServiceProviderAccountID: "1234567890",
					},
				},
			},
		}, nil
	}}
	c := newTestClient(ft)

	devices, err := c.DeviceDetails(context.Background(), "dev-1")
	if err != nil {
		t.Fatalf("DeviceDetails() unexpected error: %v", err)
	}
	if got := ft.opIDs(); len(got) != 1 || got[0] != "GetDeviceDetailsV2" {
		t.Fatalf("expected one GetDeviceDetailsV2 call, got %v", got)
	}
	if len(devices) != 1 {
		t.Fatalf("DeviceDetails() returned %d devices, want 1", len(devices))
	}
	d := devices[0]
	if d.DeviceID != "dev-1" {
		t.Errorf("DeviceID = %q, want %q", d.DeviceID, "dev-1")
	}
	if d.PlatformName != "Windows" {
		t.Errorf("PlatformName = %q, want %q", d.PlatformName, "Windows")
	}
	if d.InstanceID != "i-abc123" {
		t.Errorf("InstanceID = %q, want %q", d.InstanceID, "i-abc123")
	}
	if d.ServiceProvider != "AWS_EC2_V2" {
		t.Errorf("ServiceProvider = %q, want %q", d.ServiceProvider, "AWS_EC2_V2")
	}
	if d.ServiceProviderAccountID != "1234567890" {
		t.Errorf("ServiceProviderAccountID = %q, want %q", d.ServiceProviderAccountID, "1234567890")
	}
}

func TestDeviceDetailsEmptyResources(t *testing.T) {
	t.Parallel()

	ft := &fakeTransport{responder: func(op *runtime.ClientOperation) (any, error) {
		return &hosts.GetDeviceDetailsV2OK{
			Payload: &models.DeviceapiDeviceDetailsResponseSwagger{Resources: nil},
		}, nil
	}}
	c := newTestClient(ft)

	devices, err := c.DeviceDetails(context.Background(), "missing")
	if err != nil {
		t.Fatalf("DeviceDetails() unexpected error: %v", err)
	}
	if len(devices) != 0 {
		t.Fatalf("DeviceDetails() returned %d devices, want 0", len(devices))
	}
}

func TestDeviceDetailsPayloadErrorsBecomeError(t *testing.T) {
	t.Parallel()

	// A 2xx HTTP response whose JSON body carries a non-empty errors array is
	// returned by gofalcon as a successful typed response; the wrapper must
	// surface it as a Go error anyway.
	ft := &fakeTransport{responder: func(op *runtime.ClientOperation) (any, error) {
		return &hosts.GetDeviceDetailsV2OK{
			Payload: &models.DeviceapiDeviceDetailsResponseSwagger{
				Errors: []*models.MsaAPIError{
					{Code: int32ptr(403), Message: strptr("access denied")},
				},
			},
		}, nil
	}}
	c := newTestClient(ft)

	if _, err := c.DeviceDetails(context.Background(), "dev-1"); err == nil {
		t.Fatal("DeviceDetails() expected error for non-empty payload errors, got nil")
	}
}

func int32ptr(i int32) *int32 { return &i }

func TestInitRTRSessionMapsResource(t *testing.T) {
	t.Parallel()

	ft := &fakeTransport{responder: func(op *runtime.ClientOperation) (any, error) {
		return &real_time_response.RTRInitSessionCreated{
			Payload: &models.DomainInitResponseWrapper{
				Resources: []*models.DomainInitResponse{
					{SessionID: strptr("sess-1"), Platform: "Windows", DeviceID: "dev-1"},
				},
			},
		}, nil
	}}
	c := newTestClient(ft)

	sess, err := c.InitRTRSession(context.Background(), "dev-1")
	if err != nil {
		t.Fatalf("InitRTRSession() unexpected error: %v", err)
	}
	if got := ft.opIDs(); len(got) != 1 || got[0] != "RTR-InitSession" {
		t.Fatalf("expected one RTR-InitSession call, got %v", got)
	}
	if sess.SessionID != "sess-1" {
		t.Errorf("SessionID = %q, want %q", sess.SessionID, "sess-1")
	}
	if sess.Platform != "Windows" {
		t.Errorf("Platform = %q, want %q", sess.Platform, "Windows")
	}
}

func TestInitRTRSessionNoResource(t *testing.T) {
	t.Parallel()

	ft := &fakeTransport{responder: func(op *runtime.ClientOperation) (any, error) {
		return &real_time_response.RTRInitSessionCreated{
			Payload: &models.DomainInitResponseWrapper{Resources: nil},
		}, nil
	}}
	c := newTestClient(ft)

	if _, err := c.InitRTRSession(context.Background(), "dev-1"); err == nil {
		t.Fatal("InitRTRSession() expected error when no session resource returned, got nil")
	}
}

func TestInitRTRSessionPayloadErrorsBecomeError(t *testing.T) {
	t.Parallel()

	ft := &fakeTransport{responder: func(op *runtime.ClientOperation) (any, error) {
		return &real_time_response.RTRInitSessionCreated{
			Payload: &models.DomainInitResponseWrapper{
				Errors: []*models.MsaAPIError{{Code: int32ptr(500), Message: strptr("boom")}},
			},
		}, nil
	}}
	c := newTestClient(ft)

	if _, err := c.InitRTRSession(context.Background(), "dev-1"); err == nil {
		t.Fatal("InitRTRSession() expected error for non-empty payload errors, got nil")
	}
}

func TestExecuteRTRCommandNonAdmin(t *testing.T) {
	t.Parallel()

	ft := &fakeTransport{responder: func(op *runtime.ClientOperation) (any, error) {
		return &real_time_response.RTRExecuteCommandCreated{
			Payload: &models.DomainCommandExecuteResponseWrapper{
				Resources: []*models.DomainCommandExecuteResponse{
					{CloudRequestID: strptr("crid-1"), SessionID: strptr("sess-1")},
				},
			},
		}, nil
	}}
	c := newTestClient(ft)

	res, err := c.ExecuteRTRCommand(context.Background(), RTRCommand{
		SessionID:     "sess-1",
		BaseCommand:   "reg query",
		CommandString: `reg query "HKLM\..." DeviceClientId`,
	})
	if err != nil {
		t.Fatalf("ExecuteRTRCommand() unexpected error: %v", err)
	}
	if got := ft.opIDs(); len(got) != 1 || got[0] != "RTR-ExecuteCommand" {
		t.Fatalf("expected one RTR-ExecuteCommand call, got %v", got)
	}
	if res.CloudRequestID != "crid-1" {
		t.Errorf("CloudRequestID = %q, want %q", res.CloudRequestID, "crid-1")
	}
}

func TestExecuteRTRCommandAdmin(t *testing.T) {
	t.Parallel()

	ft := &fakeTransport{responder: func(op *runtime.ClientOperation) (any, error) {
		return &real_time_response_admin.RTRExecuteAdminCommandCreated{
			Payload: &models.DomainCommandExecuteResponseWrapper{
				Resources: []*models.DomainCommandExecuteResponse{
					{CloudRequestID: strptr("crid-admin"), SessionID: strptr("sess-1")},
				},
			},
		}, nil
	}}
	c := newTestClient(ft)

	res, err := c.ExecuteRTRCommand(context.Background(), RTRCommand{
		SessionID:     "sess-1",
		BaseCommand:   "runscript",
		CommandString: "runscript -Raw=```...```",
		Admin:         true,
	})
	if err != nil {
		t.Fatalf("ExecuteRTRCommand() unexpected error: %v", err)
	}
	if got := ft.opIDs(); len(got) != 1 || got[0] != "RTR-ExecuteAdminCommand" {
		t.Fatalf("expected one RTR-ExecuteAdminCommand call, got %v", got)
	}
	if res.CloudRequestID != "crid-admin" {
		t.Errorf("CloudRequestID = %q, want %q", res.CloudRequestID, "crid-admin")
	}
}

func TestExecuteRTRCommandNoResource(t *testing.T) {
	t.Parallel()

	ft := &fakeTransport{responder: func(op *runtime.ClientOperation) (any, error) {
		return &real_time_response.RTRExecuteCommandCreated{
			Payload: &models.DomainCommandExecuteResponseWrapper{Resources: nil},
		}, nil
	}}
	c := newTestClient(ft)

	if _, err := c.ExecuteRTRCommand(context.Background(), RTRCommand{SessionID: "sess-1", BaseCommand: "ls"}); err == nil {
		t.Fatal("ExecuteRTRCommand() expected error when no command resource returned, got nil")
	}
}

func TestExecuteRTRCommandPayloadErrorsBecomeError(t *testing.T) {
	t.Parallel()

	ft := &fakeTransport{responder: func(op *runtime.ClientOperation) (any, error) {
		return &real_time_response.RTRExecuteCommandCreated{
			Payload: &models.DomainCommandExecuteResponseWrapper{
				Errors: []*models.MsaAPIError{{Code: int32ptr(400), Message: strptr("bad command")}},
			},
		}, nil
	}}
	c := newTestClient(ft)

	if _, err := c.ExecuteRTRCommand(context.Background(), RTRCommand{SessionID: "sess-1", BaseCommand: "ls"}); err == nil {
		t.Fatal("ExecuteRTRCommand() expected error for non-empty payload errors, got nil")
	}
}

func TestCheckRTRCommandStatusMapsResource(t *testing.T) {
	t.Parallel()

	complete := true
	ft := &fakeTransport{responder: func(op *runtime.ClientOperation) (any, error) {
		return &real_time_response.RTRCheckCommandStatusOK{
			Payload: &models.DomainStatusResponseWrapper{
				Resources: []*models.DomainStatusResponse{
					{
						Complete:   &complete,
						Stdout:     strptr("MDMDeviceID    REG_SZ    abc-123\n"),
						Stderr:     strptr(""),
						SequenceID: 0,
					},
				},
			},
		}, nil
	}}
	c := newTestClient(ft)

	st, err := c.CheckRTRCommandStatus(context.Background(), "crid-1", 0)
	if err != nil {
		t.Fatalf("CheckRTRCommandStatus() unexpected error: %v", err)
	}
	if got := ft.opIDs(); len(got) != 1 || got[0] != "RTR-CheckCommandStatus" {
		t.Fatalf("expected one RTR-CheckCommandStatus call, got %v", got)
	}
	if !st.Complete {
		t.Errorf("Complete = false, want true")
	}
	if st.Stdout != "MDMDeviceID    REG_SZ    abc-123\n" {
		t.Errorf("Stdout = %q, want the reg-query output", st.Stdout)
	}
	if st.Stderr != "" {
		t.Errorf("Stderr = %q, want empty", st.Stderr)
	}
}

func TestCheckRTRCommandStatusNoResource(t *testing.T) {
	t.Parallel()

	ft := &fakeTransport{responder: func(op *runtime.ClientOperation) (any, error) {
		return &real_time_response.RTRCheckCommandStatusOK{
			Payload: &models.DomainStatusResponseWrapper{Resources: nil},
		}, nil
	}}
	c := newTestClient(ft)

	if _, err := c.CheckRTRCommandStatus(context.Background(), "crid-1", 0); err == nil {
		t.Fatal("CheckRTRCommandStatus() expected error when no status resource returned, got nil")
	}
}

func TestCheckRTRCommandStatusPayloadErrorsBecomeError(t *testing.T) {
	t.Parallel()

	ft := &fakeTransport{responder: func(op *runtime.ClientOperation) (any, error) {
		return &real_time_response.RTRCheckCommandStatusOK{
			Payload: &models.DomainStatusResponseWrapper{
				Errors: []*models.MsaAPIError{{Code: int32ptr(404), Message: strptr("no such request")}},
			},
		}, nil
	}}
	c := newTestClient(ft)

	if _, err := c.CheckRTRCommandStatus(context.Background(), "crid-1", 0); err == nil {
		t.Fatal("CheckRTRCommandStatus() expected error for non-empty payload errors, got nil")
	}
}

func TestDeleteRTRSessionSuccess(t *testing.T) {
	t.Parallel()

	ft := &fakeTransport{responder: func(op *runtime.ClientOperation) (any, error) {
		return &real_time_response.RTRDeleteSessionNoContent{
			Payload: &models.MsaReplyMetaOnly{},
		}, nil
	}}
	c := newTestClient(ft)

	if err := c.DeleteRTRSession(context.Background(), "sess-1"); err != nil {
		t.Fatalf("DeleteRTRSession() unexpected error: %v", err)
	}
	if got := ft.opIDs(); len(got) != 1 || got[0] != "RTR-DeleteSession" {
		t.Fatalf("expected one RTR-DeleteSession call, got %v", got)
	}
}

func TestDeleteRTRSessionPayloadErrorsBecomeError(t *testing.T) {
	t.Parallel()

	// The 204 wrapper still carries an errors array; a populated one must
	// surface as a Go error rather than a silent success.
	ft := &fakeTransport{responder: func(op *runtime.ClientOperation) (any, error) {
		return &real_time_response.RTRDeleteSessionNoContent{
			Payload: &models.MsaReplyMetaOnly{
				Errors: []*models.MsaAPIError{{Code: int32ptr(500), Message: strptr("cannot close")}},
			},
		}, nil
	}}
	c := newTestClient(ft)

	if err := c.DeleteRTRSession(context.Background(), "sess-1"); err == nil {
		t.Fatal("DeleteRTRSession() expected error for non-empty payload errors, got nil")
	}
}

func TestFirstResource(t *testing.T) {
	t.Parallel()

	r1, r2 := 1, 2
	apiErr := []*models.MsaAPIError{{Code: int32ptr(400), Message: strptr("bad")}}

	tests := []struct {
		name      string
		errs      []*models.MsaAPIError
		resources []*int
		wantErr   bool
		wantVal   int
	}{
		{name: "clean single resource", resources: []*int{&r1}, wantVal: 1},
		{name: "ignores later resources", resources: []*int{&r1, &r2}, wantVal: 1},
		{name: "payload errors surface", errs: apiErr, resources: []*int{&r1}, wantErr: true},
		{name: "empty resources", resources: []*int{}, wantErr: true},
		{name: "nil resource slice", resources: nil, wantErr: true},
		{name: "first resource nil", resources: []*int{nil}, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := firstResource("op", tt.errs, tt.resources)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("firstResource() expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("firstResource() unexpected error: %v", err)
			}
			if got == nil || *got != tt.wantVal {
				t.Fatalf("firstResource() = %v, want %d", got, tt.wantVal)
			}
		})
	}
}
