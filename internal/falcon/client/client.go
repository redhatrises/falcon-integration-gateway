// Package client is a thin wrapper over the gofalcon (CrowdStrike) control
// plane. It ports fig/falcon/api.py (the FalconAPI class) and the Stream model
// from fig/falcon/models.py:92-121.
//
// It covers authentication and region selection, the Event Streams
// control-plane calls (list + refresh), the Stream value type with its
// regex-derived accessors, and the host-detail and RTR (init/execute/status/
// fetch-file) enrichment lookups.
//
// The long-poll data feed itself is NOT handled here; a dedicated net/http
// client in internal/falcon/stream consumes the URL/Token this package
// surfaces.
package client

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/crowdstrike/gofalcon/falcon"
	"github.com/crowdstrike/gofalcon/falcon/client"
	"github.com/crowdstrike/gofalcon/falcon/client/event_streams"
	"github.com/crowdstrike/gofalcon/falcon/client/hosts"
	"github.com/crowdstrike/gofalcon/falcon/client/real_time_response"
	"github.com/crowdstrike/gofalcon/falcon/client/real_time_response_admin"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/go-openapi/runtime"

	"github.com/crowdstrike/falcon-integration-gateway/internal/common"
	"github.com/crowdstrike/falcon-integration-gateway/internal/config"
	"github.com/crowdstrike/falcon-integration-gateway/internal/utils"
	"github.com/crowdstrike/falcon-integration-gateway/internal/version"
)

// NoStreamsError is returned by ListStreams when the Falcon platform reports no
// available event streams for the given application ID. Ported from
// fig/falcon/errors.py NoStreamsError, raised in fig/falcon/api.py:36.
type NoStreamsError struct {
	AppID string
}

func (e *NoStreamsError) Error() string {
	return fmt.Sprintf("no event streams available for application id %q", e.AppID)
}

// Client wraps the gofalcon generated API client plus the resolved config and a
// scoped logger. Port of the FalconAPI class in fig/falcon/api.py.
type Client struct {
	api    *client.CrowdStrikeAPISpecification
	cfg    *config.Config
	logger *slog.Logger
}

// NewClient constructs a Client. It authenticates with the client_id /
// client_secret from config, selects the Falcon cloud from cloud_region (via
// config.FalconCloud, which maps us-1/us-2/eu-1/us-gov-1 to the gofalcon Cloud
// constants), and sets the User-Agent from version.UserAgent(cfg.Backends).
//
// ctx is captured by the underlying gofalcon client and reused for the initial
// OAuth token fetch and every automatic token refresh for the client's whole
// lifetime. Passing the daemon's cancellable context (rather than a background
// one) is what lets a shutdown signal abort a hung token endpoint instead of
// blocking on it for the full HTTP timeout.
//
// Port of FalconAPI.__init__ (fig/falcon/api.py:17-30).
func NewClient(ctx context.Context, cfg *config.Config, logger *slog.Logger) (*Client, error) {
	if cfg == nil {
		return nil, errors.New("falcon/client: nil config")
	}
	if logger == nil {
		logger = slog.Default()
	}

	apiCfg := &falcon.ApiConfig{
		ClientId:          cfg.Falcon.ClientID,
		ClientSecret:      cfg.Falcon.ClientSecret,
		Cloud:             cfg.FalconCloud(),
		UserAgentOverride: userAgent(cfg.Backends),
		Context:           ctx,
	}

	api, err := falcon.NewClient(apiCfg)
	if err != nil {
		return nil, fmt.Errorf("client: authenticate: %w", err)
	}

	return &Client{api: api, cfg: cfg, logger: logger}, nil
}

// UserAgent builds the Falcon API User-Agent string.
//
// Port of fig/falcon/api.py:24-25: the base token is
// "falcon-integration-gateway/<version>" followed by, for each backend, a
// space and "<BACKEND>-Backend". The whole result is trimmed.
//
// Example: UserAgent([]string{"GENERIC"}) -> "falcon-integration-gateway/dev GENERIC-Backend".
func userAgent(backends []string) string {
	var b strings.Builder
	b.WriteString("falcon-integration-gateway/")
	b.WriteString(version.Version)
	for _, backend := range backends {
		name := strings.TrimSpace(backend)
		if name == "" {
			continue
		}
		b.WriteByte(' ')
		b.WriteString(name)
		b.WriteString("-Backend")
	}
	return strings.TrimSpace(b.String())
}

// streamPartitionRe extracts the partition from a stream's
// refreshActiveSessionURL. Ported EXACTLY from fig/falcon/models.py:107-108.
var streamPartitionRe = regexp.MustCompile(`.*/sensors/entities/datafeed-actions/v1/([0-9a-zA-Z]+)\?`)

// streamFeedIDRe extracts the feed ID from a stream's dataFeedURL. Ported
// EXACTLY from fig/falcon/models.py:116-117.
var streamFeedIDRe = regexp.MustCompile(`.*/sensors/entities/datafeed/v1/([0-9a-zA-Z]+)\?`)

// Stream is a resolved event-stream descriptor returned by ListStreams. Port of
// the Stream class in fig/falcon/models.py:92-121. The accessors mirror the
// Python properties (token, url, refresh_interval, partition, feed_id).
type Stream struct {
	token           string
	url             string
	refreshInterval int64
	refreshURL      string
}

// Token returns the session token used to authorize the long-poll data feed.
// Port of Stream.token (models.py:93-95).
func (s Stream) Token() string { return s.token }

// URL returns the dataFeedURL to long-poll. Port of Stream.url (models.py:97-99).
func (s Stream) URL() string { return s.url }

// RefreshInterval returns refreshActiveSessionInterval in seconds. Port of
// Stream.refresh_interval (models.py:101-103).
func (s Stream) RefreshInterval() int64 { return s.refreshInterval }

// Partition parses and returns the numeric partition from refreshActiveSessionURL.
// Port of Stream.partition (models.py:105-111): the regex is applied on each
// call and an error is returned when it does not match.
func (s Stream) Partition() (int64, error) {
	m := streamPartitionRe.FindStringSubmatch(s.refreshURL)
	if len(m) < 2 || m[1] == "" {
		return 0, fmt.Errorf("client: cannot parse stream partition from %q", s.refreshURL)
	}
	p, err := strconv.ParseInt(m[1], 10, 64)
	if err != nil {
		return 0, fmt.Errorf("client: partition %q is not numeric: %w", m[1], err)
	}
	return p, nil
}

// FeedID parses and returns the feed ID from dataFeedURL. Port of Stream.feed_id
// (models.py:113-121).
func (s Stream) FeedID() (string, error) {
	m := streamFeedIDRe.FindStringSubmatch(s.url)
	if len(m) < 2 || m[1] == "" {
		return "", fmt.Errorf("client: cannot parse feed id from %q", s.url)
	}
	return m[1], nil
}

// StreamFields carries the resolved descriptor fields of a Stream. It is the
// input to NewStream for callers that already hold the raw values (production
// code obtains Streams from ListStreams).
type StreamFields struct {
	Token           string
	URL             string
	RefreshInterval int64
	RefreshURL      string
}

// NewStream builds a Stream from explicit descriptor fields. It is the exported
// counterpart to ListStreams for callers that construct a descriptor directly
// rather than resolving it from the platform response.
func NewStream(f StreamFields) Stream {
	return Stream{
		token:           f.Token,
		url:             f.URL,
		refreshInterval: f.RefreshInterval,
		refreshURL:      f.RefreshURL,
	}
}

// ListStreams lists the event streams available for appID and returns them as
// typed Stream values. When the platform returns no resources, a *NoStreamsError
// is returned. Port of FalconAPI.streams (fig/falcon/api.py:32-37).
//
// gofalcon operation used: EventStreams.ListAvailableStreamsOAuth2.
func (c *Client) ListStreams(ctx context.Context, appID string) ([]Stream, error) {
	params := event_streams.NewListAvailableStreamsOAuth2ParamsWithContext(ctx).
		WithAppID(appID)

	resp, err := c.api.EventStreams.ListAvailableStreamsOAuth2(params)
	if err != nil {
		return nil, fmt.Errorf("client: list streams: %w", err)
	}

	payload := resp.GetPayload()
	if payload == nil || len(payload.Resources) == 0 {
		return nil, &NoStreamsError{AppID: appID}
	}

	streams := make([]Stream, 0, len(payload.Resources))
	for _, r := range payload.Resources {
		if r == nil {
			continue
		}
		s := Stream{}
		if r.SessionToken != nil && r.SessionToken.Token != nil {
			s.token = *r.SessionToken.Token
		}
		if r.DataFeedURL != nil {
			s.url = *r.DataFeedURL
		}
		if r.RefreshActiveSessionInterval != nil {
			s.refreshInterval = *r.RefreshActiveSessionInterval
		}
		if r.RefreshActiveSessionURL != nil {
			s.refreshURL = *r.RefreshActiveSessionURL
		}
		streams = append(streams, s)
	}
	return streams, nil
}

// Refresh re-ups an active streaming session for the given partition. Port of
// FalconAPI.refresh_streaming_session (fig/falcon/api.py:39-45): action_name is
// the fixed "refresh_active_stream_session".
//
// gofalcon operation used: EventStreams.RefreshActiveStreamSession.
func (c *Client) Refresh(ctx context.Context, appID string, partition int64) error {
	params := event_streams.NewRefreshActiveStreamSessionParamsWithContext(ctx).
		WithActionName("refresh_active_stream_session").
		WithAppID(appID).
		WithPartition(partition)

	if _, err := c.api.EventStreams.RefreshActiveStreamSession(params); err != nil {
		return fmt.Errorf("falcon/client: refresh stream session (partition %d): %w", partition, err)
	}
	return nil
}

// API exposes the underlying gofalcon client for packages (e.g. enrich) that
// need direct access to Hosts / RTR services not yet wrapped here.
func (c *Client) API() *client.CrowdStrikeAPISpecification { return c.api }

// apiError mirrors FalconAPI._command (fig/falcon/api.py:99-113): the generated
// gofalcon reader only turns a non-2xx HTTP status into a Go error, so a 2xx
// response whose JSON body carries a populated errors array reaches us as a
// "successful" typed response. We convert that array into an error here so
// every wrapped call fails loudly. Returns nil when errs is empty.
func apiError(op string, errs []*models.MsaAPIError) error {
	if len(errs) == 0 {
		return nil
	}
	msgs := make([]string, 0, len(errs))
	for _, e := range errs {
		if e == nil {
			continue
		}
		var code int32
		if e.Code != nil {
			code = *e.Code
		}
		var msg string
		if e.Message != nil {
			msg = *e.Message
		}
		msgs = append(msgs, fmt.Sprintf("%d: %s", code, msg))
	}
	return fmt.Errorf("falcon client: %s: error from Falcon platform: %s", op, strings.Join(msgs, "; "))
}

// firstResource applies the single-resource response contract shared by the RTR
// endpoints: surface any payload errors array via apiError, then require exactly
// one non-nil resource. It returns the first resource or an error describing op.
func firstResource[T any](op string, errs []*models.MsaAPIError, resources []*T) (*T, error) {
	if err := apiError(op, errs); err != nil {
		return nil, err
	}
	if len(resources) == 0 || resources[0] == nil {
		return nil, fmt.Errorf("falcon/client: %s: no resources returned", op)
	}
	return resources[0], nil
}

// DeviceDetails fetches host details for a device ID via Hosts.GetDeviceDetailsV2
// and returns the resource list (empty when the platform knows no such device).
// Port of FalconAPI.device_details (fig/falcon/api.py:47-48), including the
// _command errors-array check that device_details inherits via _resources.
func (c *Client) DeviceDetails(ctx context.Context, deviceID string) ([]*common.HostDetails, error) {
	params := hosts.NewGetDeviceDetailsV2ParamsWithContext(ctx).WithIds([]string{deviceID})

	resp, err := c.api.Hosts.GetDeviceDetailsV2(params)
	if err != nil {
		return nil, fmt.Errorf("falcon/client: device details: %w", err)
	}
	payload := resp.GetPayload()
	if payload == nil {
		return nil, nil
	}
	if err := apiError("device details", payload.Errors); err != nil {
		return nil, err
	}

	devices := make([]*common.HostDetails, 0, len(payload.Resources))
	for _, r := range payload.Resources {
		if r == nil {
			continue
		}
		// Known and SensorID are left zero here; the enricher sets them once it
		// confirms the sensor resolves to exactly one device.
		d := &common.HostDetails{
			Hostname:               r.Hostname,
			Platform:               r.PlatformName,
			InstanceID:             r.InstanceID,
			CloudProvider:          r.ServiceProvider,
			CloudProviderAccountID: r.ServiceProviderAccountID,
			MACAddress:             r.MacAddress,
			ExternalIP:             r.ExternalIP,
			LocalIP:                r.LocalIP,
			MachineDomain:          r.MachineDomain,
			AgentVersion:           r.AgentVersion,
			LastSeen:               r.LastSeen,
			OSVersion:              r.OsVersion,
			SiteName:               r.SiteName,
			OU:                     r.Ou,
			Tags:                   r.Tags,
			ProductTypeDesc:        r.ProductTypeDesc,
			ZoneGroup:              r.ZoneGroup,
		}
		if r.DeviceID != nil {
			d.DeviceID = *r.DeviceID
		}
		devices = append(devices, d)
	}
	return devices, nil
}

// RTRSession is an opened Real Time Response session returned by InitRTRSession.
// Port of the DomainInitResponse fields fig/falcon_data.py consumes (session_id,
// plus platform which the MDM path branches on).
type RTRSession struct {
	SessionID string
	Platform  string
	DeviceID  string
}

// InitRTRSession opens an RTR session on a device via RealTimeResponse.RTRInitSession
// and returns the first session resource. Port of FalconAPI.init_rtr_session
// (fig/falcon/api.py:50-56): device_id is the sole body field, and the caller
// treats a missing session resource as a failure.
func (c *Client) InitRTRSession(ctx context.Context, deviceID string) (*RTRSession, error) {
	body := &models.DomainInitRequest{DeviceID: &deviceID}
	params := real_time_response.NewRTRInitSessionParamsWithContext(ctx).WithBody(body)

	resp, err := c.api.RealTimeResponse.RTRInitSession(params)
	if err != nil {
		return nil, fmt.Errorf("falcon/client: init rtr session: %w", err)
	}
	payload := resp.GetPayload()
	if payload == nil {
		return nil, fmt.Errorf("falcon/client: init rtr session: empty response")
	}
	r, err := firstResource("init rtr session", payload.Errors, payload.Resources)
	if err != nil {
		return nil, err
	}
	s := &RTRSession{Platform: r.Platform, DeviceID: r.DeviceID}
	if r.SessionID != nil {
		s.SessionID = *r.SessionID
	}
	return s, nil
}

// RTRCommand describes a Real Time Response command to run in an open session.
// Admin selects the privileged command endpoint: fig/falcon_data.py's MDM lookup
// runs the Windows registry query as a regular command and the macOS
// system_profiler script as an admin command (fig/falcon_data.py:69-88), which
// Python passes as the 'RTR_ExecuteCommand' vs 'RTR_ExecuteAdminCommand' action.
type RTRCommand struct {
	SessionID     string
	BaseCommand   string
	CommandString string
	Admin         bool
}

// RTRCommandResult is the queued-command handle returned by ExecuteRTRCommand.
// CloudRequestID is polled by CheckRTRCommandStatus for the command's output.
type RTRCommandResult struct {
	CloudRequestID string
	SessionID      string
}

// ExecuteRTRCommand runs an RTR command in a session and returns the queued
// command handle. Port of FalconAPI.execute_rtr_command (fig/falcon/api.py:58-66):
// cmd.Admin dispatches to RealTimeResponseAdmin.RTRExecuteAdminCommand, otherwise
// RealTimeResponse.RTRExecuteCommand. Both endpoints share the request/response
// shape, so the errors-array and resource checks are identical.
func (c *Client) ExecuteRTRCommand(ctx context.Context, cmd RTRCommand) (*RTRCommandResult, error) {
	body := &models.DomainCommandExecuteRequest{
		BaseCommand:   &cmd.BaseCommand,
		CommandString: &cmd.CommandString,
		SessionID:     &cmd.SessionID,
	}

	var payload *models.DomainCommandExecuteResponseWrapper
	if cmd.Admin {
		params := real_time_response_admin.NewRTRExecuteAdminCommandParamsWithContext(ctx).WithBody(body)
		resp, err := c.api.RealTimeResponseAdmin.RTRExecuteAdminCommand(params)
		if err != nil {
			return nil, fmt.Errorf("falcon/client: execute rtr admin command: %w", err)
		}
		payload = resp.GetPayload()
	} else {
		params := real_time_response.NewRTRExecuteCommandParamsWithContext(ctx).WithBody(body)
		resp, err := c.api.RealTimeResponse.RTRExecuteCommand(params)
		if err != nil {
			return nil, fmt.Errorf("falcon/client: execute rtr command: %w", err)
		}
		payload = resp.GetPayload()
	}

	if payload == nil {
		return nil, fmt.Errorf("falcon/client: execute rtr command: empty response")
	}
	r, err := firstResource("execute rtr command", payload.Errors, payload.Resources)
	if err != nil {
		return nil, err
	}
	res := &RTRCommandResult{}
	if r.CloudRequestID != nil {
		res.CloudRequestID = *r.CloudRequestID
	}
	if r.SessionID != nil {
		res.SessionID = *r.SessionID
	}
	return res, nil
}

// RTRCommandStatus is the polled state of a queued RTR command. Complete gates
// the poll loop; Stdout/Stderr carry the command output the MDM parser consumes
// (fig/falcon_data.py:75-95: a non-empty Stderr means "no identifier", otherwise
// Stdout is parsed).
type RTRCommandStatus struct {
	Complete   bool
	Stdout     string
	Stderr     string
	SequenceID int64
}

// CheckRTRCommandStatus polls the status of a queued RTR command by cloud request
// ID. Port of FalconAPI.check_rtr_command_status (fig/falcon/api.py:68-75). The
// caller re-polls while Complete is false.
func (c *Client) CheckRTRCommandStatus(ctx context.Context, cloudRequestID string, sequenceID int) (*RTRCommandStatus, error) {
	params := real_time_response.NewRTRCheckCommandStatusParamsWithContext(ctx).
		WithCloudRequestID(cloudRequestID).
		WithSequenceID(int64(sequenceID))

	resp, err := c.api.RealTimeResponse.RTRCheckCommandStatus(params)
	if err != nil {
		return nil, fmt.Errorf("falcon/client: check rtr command status: %w", err)
	}
	payload := resp.GetPayload()
	if payload == nil {
		return nil, fmt.Errorf("falcon/client: check rtr command status: empty response")
	}
	r, err := firstResource("check rtr command status", payload.Errors, payload.Resources)
	if err != nil {
		return nil, err
	}
	st := &RTRCommandStatus{SequenceID: r.SequenceID}
	if r.Complete != nil {
		st.Complete = *r.Complete
	}
	if r.Stdout != nil {
		st.Stdout = *r.Stdout
	}
	if r.Stderr != nil {
		st.Stderr = *r.Stderr
	}
	return st, nil
}

// DeleteRTRSession closes an open RTR session. It has no Python analogue in
// fig/falcon/api.py (the Python RTRSession.close lives in fig/falcon/rtr.py); the
// enrichment layer defers it after opening a session so the MDM lookup never
// leaks a session. The 204 response still carries an errors array, so a populated
// one is surfaced as an error rather than treated as success.
func (c *Client) DeleteRTRSession(ctx context.Context, sessionID string) error {
	params := real_time_response.NewRTRDeleteSessionParamsWithContext(ctx).WithSessionID(sessionID)

	resp, err := c.api.RealTimeResponse.RTRDeleteSession(params)
	if err != nil {
		return fmt.Errorf("falcon/client: delete rtr session: %w", err)
	}
	if payload := resp.GetPayload(); payload != nil {
		if err := apiError("delete rtr session", payload.Errors); err != nil {
			return err
		}
	}
	return nil
}

// RTRCleanupTimeout bounds the deferred session-close call so it still runs
// (under a fresh context) when the caller's context is already cancelled. It is
// exported so callers that open sessions through this client (for example the
// enrichment layer's own deferred close) bound their cleanup identically.
const RTRCleanupTimeout = 5 * time.Second

// rtrPollInterval is the delay between command-status polls while waiting for
// the active-responder get to complete. The wait itself is bounded by the
// caller's context deadline, not this interval.
const rtrPollInterval = 2 * time.Second

// RTRFetchFile fetches a quarantined file over RTR and returns the raw extracted
// bytes (an AES-encrypted 7z blob). Port of FalconAPI.rtr_fetch_file
// (fig/falcon/api.py:77-97) and RTRSession.get_file (fig/falcon/rtr.py:34-67):
// open a session, run the active-responder "get <path>", poll to completion,
// list the session files, match the entry whose cloud request id equals the get
// command's, and download its extracted contents by sha256. The session is
// always closed on return.
//
// Decryption is deliberately left to the caller: this transport client holds no
// config and no secrets, so the 7z password never reaches it.
func (c *Client) RTRFetchFile(ctx context.Context, deviceID, filepath string) ([]byte, error) {
	sess, err := c.InitRTRSession(ctx, deviceID)
	if err != nil {
		return nil, err
	}
	defer func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), RTRCleanupTimeout)
		defer cancel()
		if derr := c.DeleteRTRSession(cleanupCtx, sess.SessionID); derr != nil {
			c.logger.WarnContext(ctx, "failed to close RTR session after file fetch", "device_id", deviceID)
		}
	}()

	cloudRequestID, err := c.rtrExecuteActiveResponder(ctx, sess.SessionID, "get", "get "+filepath)
	if err != nil {
		return nil, err
	}

	status, err := c.pollRTRComplete(ctx, cloudRequestID)
	if err != nil {
		return nil, err
	}
	if status.Stderr != "" {
		return nil, fmt.Errorf("falcon/client: rtr fetch file %q on device %s: %s", filepath, deviceID, status.Stderr)
	}

	files, err := c.rtrListFiles(ctx, sess.SessionID)
	if err != nil {
		return nil, err
	}
	for _, f := range files {
		if f == nil || f.CloudRequestID == nil || *f.CloudRequestID != cloudRequestID {
			continue
		}
		if f.Sha256 == nil || *f.Sha256 == "" {
			return nil, fmt.Errorf("falcon/client: rtr fetch file %q on device %s: matched file has no sha256", filepath, deviceID)
		}
		return c.rtrGetExtractedFileContents(ctx, sess.SessionID, *f.Sha256)
	}
	return nil, fmt.Errorf("falcon/client: rtr fetch file %q on device %s: no extracted file for cloud request %s", filepath, deviceID, cloudRequestID)
}

// rtrExecuteActiveResponder runs an active-responder command in an open session
// and returns its cloud request id. Wraps RealTimeResponse.RTRExecuteActiveResponderCommand,
// the endpoint fig/falcon/api.py uses for the file "get".
func (c *Client) rtrExecuteActiveResponder(ctx context.Context, sessionID, baseCommand, commandString string) (string, error) {
	body := &models.DomainCommandExecuteRequest{
		BaseCommand:   &baseCommand,
		CommandString: &commandString,
		SessionID:     &sessionID,
	}
	params := real_time_response.NewRTRExecuteActiveResponderCommandParamsWithContext(ctx).WithBody(body)

	resp, err := c.api.RealTimeResponse.RTRExecuteActiveResponderCommand(params)
	if err != nil {
		return "", fmt.Errorf("falcon/client: rtr execute active responder command: %w", err)
	}
	payload := resp.GetPayload()
	if payload == nil {
		return "", fmt.Errorf("falcon/client: rtr execute active responder command: empty response")
	}
	r, err := firstResource("rtr execute active responder command", payload.Errors, payload.Resources)
	if err != nil {
		return "", err
	}
	if r.CloudRequestID == nil || *r.CloudRequestID == "" {
		return "", fmt.Errorf("falcon/client: rtr execute active responder command: missing cloud request id")
	}
	return *r.CloudRequestID, nil
}

// pollRTRComplete polls a queued command by cloud request id until it reports
// complete, honoring the caller's context deadline between polls. Python's
// _rtr_wait (fig/falcon/rtr.py) busy-loops without a bound; the poll here is
// bounded and cancellable by the caller's context.
func (c *Client) pollRTRComplete(ctx context.Context, cloudRequestID string) (*RTRCommandStatus, error) {
	var status *RTRCommandStatus
	err := utils.PollUntil(ctx, rtrPollInterval, func(ctx context.Context) (bool, error) {
		var err error
		status, err = c.CheckRTRCommandStatus(ctx, cloudRequestID, 0)
		if err != nil {
			return false, err
		}
		return status.Complete, nil
	})
	switch {
	case utils.IsCanceled(err):
		return nil, fmt.Errorf("falcon/client: rtr poll command %s: %w", cloudRequestID, err)
	case err != nil:
		return nil, err
	default:
		return status, nil
	}
}

// rtrListFiles lists the files captured in an open session. Wraps
// RealTimeResponse.RTRListFiles.
func (c *Client) rtrListFiles(ctx context.Context, sessionID string) ([]*models.ModelFile, error) {
	params := real_time_response.NewRTRListFilesParamsWithContext(ctx).WithSessionID(sessionID)

	resp, err := c.api.RealTimeResponse.RTRListFiles(params)
	if err != nil {
		return nil, fmt.Errorf("falcon/client: rtr list files: %w", err)
	}
	payload := resp.GetPayload()
	if payload == nil {
		return nil, fmt.Errorf("falcon/client: rtr list files: empty response")
	}
	if err := apiError("rtr list files", payload.Errors); err != nil {
		return nil, err
	}
	return payload.Resources, nil
}

// rawFileReader is a runtime ClientResponseReader that copies the response body
// verbatim into w, bypassing the media-type consumer. The generated reader for
// RTRGetExtractedFileContents runs the body through a consumer that would corrupt
// a binary 7z blob; copying the raw bytes preserves them regardless of the
// declared content type.
type rawFileReader struct {
	w io.Writer
}

func (r rawFileReader) ReadResponse(resp runtime.ClientResponse, _ runtime.Consumer) (any, error) {
	if resp.Code() != http.StatusOK {
		body, _ := io.ReadAll(resp.Body())
		return nil, fmt.Errorf("falcon/client: rtr get extracted file contents: status %d: %s", resp.Code(), string(body))
	}
	if _, err := io.Copy(r.w, resp.Body()); err != nil {
		return nil, fmt.Errorf("falcon/client: rtr get extracted file contents: read body: %w", err)
	}
	return real_time_response.NewRTRGetExtractedFileContentsOK(r.w), nil
}

// rtrGetExtractedFileContents downloads the extracted file identified by sha256
// from an open session and returns its raw bytes. Wraps
// RealTimeResponse.RTRGetExtractedFileContents with a raw-byte Reader override so
// the encrypted 7z blob is returned intact.
func (c *Client) rtrGetExtractedFileContents(ctx context.Context, sessionID, sha256 string) ([]byte, error) {
	params := real_time_response.NewRTRGetExtractedFileContentsParamsWithContext(ctx).
		WithSessionID(sessionID).
		WithSha256(sha256)

	var buf bytes.Buffer
	_, err := c.api.RealTimeResponse.RTRGetExtractedFileContents(params, &buf, func(op *runtime.ClientOperation) {
		op.Reader = rawFileReader{w: &buf}
	})
	if err != nil {
		return nil, fmt.Errorf("falcon/client: rtr get extracted file contents: %w", err)
	}
	return buf.Bytes(), nil
}
