package client

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"sync"
	"testing"
	"time"

	apiclient "github.com/crowdstrike/gofalcon/falcon/client"
	"github.com/crowdstrike/gofalcon/falcon/client/hosts"
	"github.com/crowdstrike/gofalcon/falcon/client/real_time_response"
	"github.com/crowdstrike/gofalcon/falcon/client/real_time_response_admin"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"

	"github.com/crowdstrike/falcon-integration-gateway/internal/testutil"
	"github.com/crowdstrike/falcon-integration-gateway/internal/version"
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

// TestUserAgent pins the User-Agent format: the base token
// "falcon-integration-gateway/<version>" followed by " <NAME>-Backend" for each
// backend, blanks skipped, whole string trimmed.
func TestUserAgent(t *testing.T) {
	t.Parallel()

	base := "falcon-integration-gateway/" + version.Version
	tests := []struct {
		name     string
		backends []string
		want     string
	}{
		{"no backends is the bare base token", nil, base},
		{"single backend appends one suffix", []string{"GENERIC"}, base + " GENERIC-Backend"},
		{
			"multiple backends append in given order",
			[]string{"AWS_SQS", "AZURE"},
			base + " AWS_SQS-Backend AZURE-Backend",
		},
		{"blank backend names are skipped", []string{"", "  ", "GENERIC"}, base + " GENERIC-Backend"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := userAgent(tc.backends); got != tc.want {
				t.Errorf("userAgent(%v) = %q, want %q", tc.backends, got, tc.want)
			}
		})
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
						MacAddress:               "aa-bb-cc-dd-ee-ff",
						ExternalIP:               "203.0.113.7",
						LocalIP:                  "10.0.0.5",
						MachineDomain:            "corp.example.com",
						AgentVersion:             "7.10.0",
						LastSeen:                 "2026-08-13T00:00:00Z",
						OsVersion:                "Windows Server 2022",
						SiteName:                 "us-east",
						Ou:                       []string{"Servers", "Prod"},
						Tags:                     []string{"SensorGroupingTags/web", "role/api"},
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
	if d.Platform != "Windows" {
		t.Errorf("Platform = %q, want %q", d.Platform, "Windows")
	}
	if d.InstanceID != "i-abc123" {
		t.Errorf("InstanceID = %q, want %q", d.InstanceID, "i-abc123")
	}
	if d.CloudProvider != "AWS_EC2_V2" {
		t.Errorf("CloudProvider = %q, want %q", d.CloudProvider, "AWS_EC2_V2")
	}
	if d.CloudProviderAccountID != "1234567890" {
		t.Errorf("CloudProviderAccountID = %q, want %q", d.CloudProviderAccountID, "1234567890")
	}
	if d.MACAddress != "aa-bb-cc-dd-ee-ff" {
		t.Errorf("MACAddress = %q, want %q", d.MACAddress, "aa-bb-cc-dd-ee-ff")
	}
	if d.ExternalIP != "203.0.113.7" {
		t.Errorf("ExternalIP = %q, want %q", d.ExternalIP, "203.0.113.7")
	}
	if d.LocalIP != "10.0.0.5" {
		t.Errorf("LocalIP = %q, want %q", d.LocalIP, "10.0.0.5")
	}
	if d.MachineDomain != "corp.example.com" {
		t.Errorf("MachineDomain = %q, want %q", d.MachineDomain, "corp.example.com")
	}
	if d.AgentVersion != "7.10.0" {
		t.Errorf("AgentVersion = %q, want %q", d.AgentVersion, "7.10.0")
	}
	if d.LastSeen != "2026-08-13T00:00:00Z" {
		t.Errorf("LastSeen = %q, want %q", d.LastSeen, "2026-08-13T00:00:00Z")
	}
	if d.OSVersion != "Windows Server 2022" {
		t.Errorf("OSVersion = %q, want %q", d.OSVersion, "Windows Server 2022")
	}
	if d.SiteName != "us-east" {
		t.Errorf("SiteName = %q, want %q", d.SiteName, "us-east")
	}
	if len(d.OU) != 2 || d.OU[0] != "Servers" || d.OU[1] != "Prod" {
		t.Errorf("OU = %v, want [Servers Prod]", d.OU)
	}
	if len(d.Tags) != 2 || d.Tags[0] != "SensorGroupingTags/web" || d.Tags[1] != "role/api" {
		t.Errorf("Tags = %v, want [SensorGroupingTags/web role/api]", d.Tags)
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

// fakeClientResponse is a minimal runtime.ClientResponse over an in-memory body.
// fakeTransport.Submit short-circuits before op.Reader runs, so the
// extracted-file-contents responder invokes the Reader itself against this to
// exercise the raw-byte passthrough that keeps a binary 7z blob intact.
type fakeClientResponse struct {
	code int
	body []byte
}

func (r *fakeClientResponse) Code() int                  { return r.code }
func (r *fakeClientResponse) Message() string            { return http.StatusText(r.code) }
func (r *fakeClientResponse) GetHeader(string) string    { return "" }
func (r *fakeClientResponse) GetHeaders(string) []string { return nil }
func (r *fakeClientResponse) Body() io.ReadCloser        { return io.NopCloser(bytes.NewReader(r.body)) }

// rtrFetchStubs drives the multi-call RTRFetchFile flow: init → active-responder
// get → status poll → list files → get extracted contents → delete. Each field
// shapes one stage's canned response.
type rtrFetchStubs struct {
	cloudRequestID string
	complete       bool
	stderr         string
	files          []*models.ModelFile
	fileBytes      []byte
}

func (s rtrFetchStubs) responder(t *testing.T) func(op *runtime.ClientOperation) (any, error) {
	t.Helper()
	return func(op *runtime.ClientOperation) (any, error) {
		switch op.ID {
		case "RTR-InitSession":
			return &real_time_response.RTRInitSessionCreated{
				Payload: &models.DomainInitResponseWrapper{
					Resources: []*models.DomainInitResponse{
						{SessionID: strptr("sess-1"), Platform: "Linux", DeviceID: "dev-1"},
					},
				},
			}, nil
		case "RTR-ExecuteActiveResponderCommand":
			return &real_time_response.RTRExecuteActiveResponderCommandCreated{
				Payload: &models.DomainCommandExecuteResponseWrapper{
					Resources: []*models.DomainCommandExecuteResponse{
						{CloudRequestID: strptr(s.cloudRequestID), SessionID: strptr("sess-1")},
					},
				},
			}, nil
		case "RTR-CheckCommandStatus":
			complete := s.complete
			stderr := s.stderr
			return &real_time_response.RTRCheckCommandStatusOK{
				Payload: &models.DomainStatusResponseWrapper{
					Resources: []*models.DomainStatusResponse{
						{Complete: &complete, Stdout: strptr(""), Stderr: &stderr},
					},
				},
			}, nil
		case "RTR-ListFiles":
			return &real_time_response.RTRListFilesOK{
				Payload: &models.DomainListFilesResponseWrapper{Resources: s.files},
			}, nil
		case "RTR-GetExtractedFileContents":
			resp := &fakeClientResponse{code: http.StatusOK, body: s.fileBytes}
			return op.Reader.ReadResponse(resp, nil)
		case "RTR-DeleteSession":
			return &real_time_response.RTRDeleteSessionNoContent{Payload: &models.MsaReplyMetaOnly{}}, nil
		default:
			t.Errorf("unexpected op %q", op.ID)
			return nil, errors.New("unexpected op " + op.ID)
		}
	}
}

func opsEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func containsOp(ids []string, want string) bool {
	for _, id := range ids {
		if id == want {
			return true
		}
	}
	return false
}

func TestRTRFetchFileSuccess(t *testing.T) {
	t.Parallel()

	// 7z magic bytes plus embedded nulls and a high byte: a JSON consumer would
	// corrupt these, so an exact match proves the raw-byte Reader passthrough.
	raw := []byte{0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c, 0x00, 0x01, 0xff, 0x00, 0x7d}
	stubs := rtrFetchStubs{
		cloudRequestID: "crid-get",
		complete:       true,
		files: []*models.ModelFile{
			{CloudRequestID: strptr("other-crid"), Sha256: strptr("sha-other")},
			{CloudRequestID: strptr("crid-get"), Sha256: strptr("sha-match")},
		},
		fileBytes: raw,
	}
	ft := &fakeTransport{responder: stubs.responder(t)}
	c := newTestClient(ft)

	got, err := c.RTRFetchFile(context.Background(), "dev-1", "/opt/azure/agentconfig.json")
	if err != nil {
		t.Fatalf("RTRFetchFile() unexpected error: %v", err)
	}
	if !bytes.Equal(got, raw) {
		t.Errorf("RTRFetchFile() bytes = %v, want %v", got, raw)
	}
	want := []string{
		"RTR-InitSession",
		"RTR-ExecuteActiveResponderCommand",
		"RTR-CheckCommandStatus",
		"RTR-ListFiles",
		"RTR-GetExtractedFileContents",
		"RTR-DeleteSession",
	}
	if ids := ft.opIDs(); !opsEqual(ids, want) {
		t.Errorf("op IDs = %v, want %v", ids, want)
	}
}

func TestRTRFetchFileNoMatchingFile(t *testing.T) {
	t.Parallel()

	stubs := rtrFetchStubs{
		cloudRequestID: "crid-get",
		complete:       true,
		files: []*models.ModelFile{
			{CloudRequestID: strptr("different-crid"), Sha256: strptr("sha-x")},
		},
	}
	ft := &fakeTransport{responder: stubs.responder(t)}
	c := newTestClient(ft)

	if _, err := c.RTRFetchFile(context.Background(), "dev-1", "/p"); err == nil {
		t.Fatal("RTRFetchFile() expected error when no file matches the get command, got nil")
	}
	ids := ft.opIDs()
	if len(ids) == 0 || ids[len(ids)-1] != "RTR-DeleteSession" {
		t.Fatalf("expected session closed (last op RTR-DeleteSession), got %v", ids)
	}
	if containsOp(ids, "RTR-GetExtractedFileContents") {
		t.Errorf("did not expect RTR-GetExtractedFileContents when no file matched, got %v", ids)
	}
}

func TestRTRFetchFileStderrIsError(t *testing.T) {
	t.Parallel()

	stubs := rtrFetchStubs{
		cloudRequestID: "crid-get",
		complete:       true,
		stderr:         "get: permission denied",
	}
	ft := &fakeTransport{responder: stubs.responder(t)}
	c := newTestClient(ft)

	if _, err := c.RTRFetchFile(context.Background(), "dev-1", "/p"); err == nil {
		t.Fatal("RTRFetchFile() expected error for non-empty stderr, got nil")
	}
	ids := ft.opIDs()
	if len(ids) == 0 || ids[len(ids)-1] != "RTR-DeleteSession" {
		t.Fatalf("expected session closed (last op RTR-DeleteSession), got %v", ids)
	}
	if containsOp(ids, "RTR-ListFiles") {
		t.Errorf("did not expect RTR-ListFiles after a stderr failure, got %v", ids)
	}
}

func TestRTRFetchFilePollTimeout(t *testing.T) {
	t.Parallel()

	// A command that never completes must be bounded by the caller's context
	// deadline, not busy-loop forever.
	stubs := rtrFetchStubs{cloudRequestID: "crid-get", complete: false}
	ft := &fakeTransport{responder: stubs.responder(t)}
	c := newTestClient(ft)

	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Millisecond)
	defer cancel()

	_, err := c.RTRFetchFile(ctx, "dev-1", "/p")
	if err == nil {
		t.Fatal("RTRFetchFile() expected timeout error, got nil")
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("RTRFetchFile() error = %v, want context.DeadlineExceeded", err)
	}
	ids := ft.opIDs()
	if len(ids) == 0 || ids[len(ids)-1] != "RTR-DeleteSession" {
		t.Fatalf("expected session closed (last op RTR-DeleteSession), got %v", ids)
	}
	if containsOp(ids, "RTR-ListFiles") || containsOp(ids, "RTR-GetExtractedFileContents") {
		t.Errorf("did not expect list/get ops after poll timeout, got %v", ids)
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
