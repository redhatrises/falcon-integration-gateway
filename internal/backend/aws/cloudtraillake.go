package aws

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/arn"
	"github.com/aws/aws-sdk-go-v2/service/cloudtraildata"
	cloudtraildatatypes "github.com/aws/aws-sdk-go-v2/service/cloudtraildata/types"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	ssmtypes "github.com/aws/aws-sdk-go-v2/service/ssm/types"

	"github.com/crowdstrike/falcon-integration-gateway/internal/backend"
	"github.com/crowdstrike/falcon-integration-gateway/internal/config"
	"github.com/crowdstrike/falcon-integration-gateway/internal/events"
	"github.com/crowdstrike/falcon-integration-gateway/internal/offset"
)

// defaultLastSeenParam is the SSM parameter name that holds the CloudTrail Lake
// dedup guard's per-feed offset watermarks.
const defaultLastSeenParam = "last_seen_offsets"

// guardSSMAPI is the subset of the SSM client the dedup guard needs.
type guardSSMAPI interface {
	GetParameter(ctx context.Context, in *ssm.GetParameterInput, optFns ...func(*ssm.Options)) (*ssm.GetParameterOutput, error)
	PutParameter(ctx context.Context, in *ssm.PutParameterInput, optFns ...func(*ssm.Options)) (*ssm.PutParameterOutput, error)
}

// lastSeenOffsets is a backend-private, monotonic dedup guard: a per-feed offset
// watermark held in memory and mirrored to a single SSM parameter as JSON. It
// prevents re-forwarding audit events already ingested across restarts.
//
// Durable writes are coalesced by an embedded offset.BufferedStore: the
// in-memory watermark advances synchronously on every accepted update so dedup
// within a run is exact, while the SSM PutParameter is throttled to at most one
// per flush interval and flushed on Close. This bounds the cross-restart
// re-admission window to a flush interval instead of writing SSM on every event.
type lastSeenOffsets struct {
	client guardSSMAPI
	logger *slog.Logger
	param  string
	buf    *offset.BufferedStore
}

// newLastSeenOffsets builds the guard and hydrates it from the SSM parameter. A
// missing parameter is created empty so the first run has a stable store to
// write back to.
func newLastSeenOffsets(ctx context.Context, client guardSSMAPI, logger *slog.Logger, param string) (*lastSeenOffsets, error) {
	g := &lastSeenOffsets{client: client, logger: logger, param: param}
	seen, err := g.hydrate(ctx)
	if err != nil {
		return nil, err
	}
	g.buf = offset.NewBufferedStore(offset.BufferedStoreConfig{
		Initial:  seen,
		Interval: offset.DefaultFlushInterval,
		Persist:  g.put,
	})
	return g, nil
}

// hydrate loads the watermark map from SSM, creating the parameter empty when it
// does not yet exist. It returns the map the BufferedStore should be seeded with.
func (g *lastSeenOffsets) hydrate(ctx context.Context) (map[string]uint64, error) {
	out, err := g.client.GetParameter(ctx, &ssm.GetParameterInput{Name: awssdk.String(g.param)})
	if err != nil {
		if _, ok := errors.AsType[*ssmtypes.ParameterNotFound](err); ok {
			if err := g.put(ctx, map[string]uint64{}); err != nil {
				return nil, err
			}
			return map[string]uint64{}, nil
		}
		return nil, fmt.Errorf("aws cloudtrail lake: reading offset guard %q: %w", g.param, err)
	}
	if out.Parameter == nil {
		return map[string]uint64{}, nil
	}
	val := awssdk.ToString(out.Parameter.Value)
	if val == "" {
		return map[string]uint64{}, nil
	}
	seen := map[string]uint64{}
	if err := json.Unmarshal([]byte(val), &seen); err != nil {
		// A prior gateway build (the Python daemon) persisted this parameter as
		// a Python dict repr, e.g. {'feed1': 42}, rather than JSON. Migrate it in
		// place so an upgrade preserves the watermark instead of re-admitting a
		// window of already-ingested audit events; the next put rewrites the
		// parameter as JSON, so the migration self-heals after the first write.
		if migrated, ok := parsePythonReprOffsets(val); ok {
			return migrated, nil
		}
		// The value is neither JSON nor a recognized legacy encoding. Rather than
		// refuse to start, discard it and begin from an empty watermark: at worst
		// a bounded set of already-ingested audit events is re-admitted once.
		g.logger.Warn("offset guard value is unreadable; starting from an empty watermark", "param", g.param)
		return map[string]uint64{}, nil //nolint:nilerr // unreadable persisted value is deliberately recovered, not propagated
	}
	return seen, nil
}

// parsePythonReprOffsets decodes a watermark map written by the legacy Python
// gateway, which persisted this parameter as a Python dict repr such as
// {'feed1': 42} rather than JSON. Feed-id keys are a safe [0-9a-zA-Z] charset
// and values are integers, so swapping single quotes for double quotes yields
// valid JSON. The second result is false when the value is not a Python repr
// this migration understands.
func parsePythonReprOffsets(val string) (map[string]uint64, bool) {
	converted := strings.ReplaceAll(val, "'", `"`)
	seen := map[string]uint64{}
	if err := json.Unmarshal([]byte(converted), &seen); err != nil {
		return nil, false
	}
	return seen, true
}

// seen returns the highest offset recorded for feedID, or 0 if none.
func (g *lastSeenOffsets) seen(feedID string) uint64 {
	return g.buf.Load(feedID)
}

// update advances the watermark for feedID to offset. A non-advancing update is
// a no-op that never writes; an advancing one advances the in-memory watermark
// immediately and coalesces the durable SSM write through the BufferedStore.
func (g *lastSeenOffsets) update(ctx context.Context, feedID string, offset uint64) error {
	return g.buf.Commit(ctx, feedID, offset)
}

// close flushes any pending watermark to SSM and marks the guard closed.
func (g *lastSeenOffsets) close(ctx context.Context) error {
	return g.buf.Close(ctx)
}

// put serializes the watermark map to JSON and writes it to the SSM parameter.
// It is the BufferedStore's PersistFunc and is also used once at hydrate time to
// create a missing parameter.
func (g *lastSeenOffsets) put(ctx context.Context, m map[string]uint64) error {
	data, err := json.Marshal(m)
	if err != nil {
		return fmt.Errorf("aws cloudtrail lake: encoding offset guard: %w", err)
	}
	_, err = g.client.PutParameter(ctx, &ssm.PutParameterInput{
		Name:      awssdk.String(g.param),
		Value:     awssdk.String(string(data)),
		Type:      ssmtypes.ParameterTypeString,
		Overwrite: awssdk.Bool(true),
	})
	if err != nil {
		return fmt.Errorf("aws cloudtrail lake: writing offset guard %q: %w", g.param, err)
	}
	return nil
}

// cloudTrailAPI is the subset of the CloudTrail Lake data client the backend
// needs.
type cloudTrailAPI interface {
	PutAuditEvents(ctx context.Context, in *cloudtraildata.PutAuditEventsInput, optFns ...func(*cloudtraildata.Options)) (*cloudtraildata.PutAuditEventsOutput, error)
}

// cloudTrailLake forwards Falcon authentication audit events into a CloudTrail
// Lake channel.
type cloudTrailLake struct {
	logger     *slog.Logger
	client     cloudTrailAPI
	channelARN string
	accountID  string
	offsets    *lastSeenOffsets
}

// newCloudTrailLake is the backend.Constructor. It parses the recipient account
// id from the channel ARN, builds the data and SSM clients from the ambient AWS
// config, and hydrates the dedup guard. The one-time startup work uses a
// background context because the constructor signature has no context to thread.
func newCloudTrailLake(cfg *config.Config, logger *slog.Logger) (backend.Backend, error) {
	ctx := context.Background()
	accountID, err := accountIDFromARN(cfg.CloudTrailLake.ChannelARN)
	if err != nil {
		return nil, err
	}
	awsCfg, err := loadConfig(ctx, cfg.CloudTrailLake.Region)
	if err != nil {
		return nil, err
	}
	guard, err := newLastSeenOffsets(ctx, ssm.NewFromConfig(awsCfg), logger, defaultLastSeenParam)
	if err != nil {
		return nil, err
	}
	logger.Info("AWS CloudTrail Lake Backend is enabled.", "channel_arn", cfg.CloudTrailLake.ChannelARN)
	return &cloudTrailLake{
		logger:     logger,
		client:     cloudtraildata.NewFromConfig(awsCfg),
		channelARN: cfg.CloudTrailLake.ChannelARN,
		accountID:  accountID,
		offsets:    guard,
	}, nil
}

// Name returns the backend registry name.
func (c *cloudTrailLake) Name() string {
	return "CLOUDTRAIL_LAKE"
}

// RelevantEventTypes narrows the stream to authentication audit events.
func (c *cloudTrailLake) RelevantEventTypes() []string {
	return []string{"AuthActivityAuditEvent"}
}

// IsRelevant accepts CrowdStrike authentication events whose offset is beyond
// the per-feed watermark. It is a pure in-memory check and never errors.
func (c *cloudTrailLake) IsRelevant(_ context.Context, ev *events.EnrichedEvent) bool {
	return strings.EqualFold(ev.ServiceName(), "crowdstrike authentication") &&
		ev.Offset() > c.offsets.seen(ev.FeedID)
}

// Process submits the event as a CloudTrail Lake audit event and, only after a
// successful ingestion, advances the dedup guard. A guard-persistence failure is
// logged but not fatal: the event was delivered, and the in-memory watermark
// still advanced, so at worst a restart re-reads a slightly stale watermark.
func (c *cloudTrailLake) Process(ctx context.Context, ev *events.EnrichedEvent) error {
	data, err := c.buildEventData(ev)
	if err != nil {
		return err
	}
	out, err := c.client.PutAuditEvents(ctx, &cloudtraildata.PutAuditEventsInput{
		ChannelArn: awssdk.String(c.channelARN),
		AuditEvents: []cloudtraildatatypes.AuditEvent{{
			Id:        awssdk.String(ev.UID()),
			EventData: awssdk.String(string(data)),
		}},
	})
	if err != nil {
		return fmt.Errorf("aws cloudtrail lake: putting audit event: %w", err)
	}
	if len(out.Failed) > 0 {
		f := out.Failed[0]
		return fmt.Errorf("aws cloudtrail lake: ingestion failed for %q: %s %s",
			awssdk.ToString(f.Id), awssdk.ToString(f.ErrorCode), awssdk.ToString(f.ErrorMessage))
	}
	if err := c.offsets.update(ctx, ev.FeedID, ev.Offset()); err != nil {
		c.logger.Warn("failed to persist CloudTrail Lake offset guard", "error", err, "feed", ev.FeedID)
	}
	return nil
}

// Close flushes the dedup guard's pending watermark to SSM. It satisfies
// backend.Closer, so the run loop invokes it on graceful shutdown to reconcile
// the debounced durable write and minimize the cross-restart re-admission
// window.
func (c *cloudTrailLake) Close(ctx context.Context) error {
	return c.offsets.close(ctx)
}

// auditEventData is the CloudTrail Lake eventData payload.
type auditEventData struct {
	Version             string         `json:"version"`
	UserIdentity        userIdentity   `json:"userIdentity"`
	UserAgent           string         `json:"userAgent"`
	EventSource         string         `json:"eventSource"`
	EventName           string         `json:"eventName"`
	EventTime           string         `json:"eventTime"`
	UID                 string         `json:"UID"`
	SourceIPAddress     string         `json:"sourceIPAddress"`
	RecipientAccountID  string         `json:"recipientAccountId"`
	AdditionalEventData additionalData `json:"additionalEventData"`
}

type userIdentity struct {
	Type        string          `json:"type"`
	PrincipalID string          `json:"principalId"`
	Details     identityDetails `json:"details"`
}

type identityDetails struct {
	AuditKeyValues any `json:"AuditKeyValues"`
}

type additionalData struct {
	Raw json.RawMessage `json:"raw"`
}

// buildEventData renders the audit-event JSON payload for one event.
//
// An audit record whose principal (UserId), operation (OperationName), or
// source address (UserIp) is missing is dropped rather than forwarded: the
// reference gateway read these with subscript access, so a missing key raised
// and discarded the event, and a compliance audit record with a blank principal
// is worse than no record. The drop advances the resume watermark, so the event
// is not retried; other backends still receive it independently.
func (c *cloudTrailLake) buildEventData(ev *events.EnrichedEvent) ([]byte, error) {
	fields := ev.Event.Event
	principalID := mapString(fields, "UserId")
	eventName := mapString(fields, "OperationName")
	sourceIP := mapString(fields, "UserIp")
	if principalID == "" || eventName == "" || sourceIP == "" {
		return nil, backend.Dropped("cloudtrail_missing_principal")
	}
	var auditKeyValues any = "n/a"
	if v, ok := fields["AuditKeyValues"]; ok {
		auditKeyValues = v
	}
	raw := ev.Raw
	if len(raw) == 0 {
		raw = []byte("null")
	}
	payload := auditEventData{
		Version: ev.Metadata.Version,
		UserIdentity: userIdentity{
			Type:        ev.EventType(),
			PrincipalID: principalID,
			Details:     identityDetails{AuditKeyValues: auditKeyValues},
		},
		UserAgent:           "falcon-integration-gateway",
		EventSource:         "crowdstrike",
		EventName:           eventName,
		EventTime:           ev.CreationTime().UTC().Format("2006-01-02T15:04:05Z"),
		UID:                 ev.UID(),
		SourceIPAddress:     sourceIP,
		RecipientAccountID:  c.accountID,
		AdditionalEventData: additionalData{Raw: json.RawMessage(raw)},
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("aws cloudtrail lake: encoding audit event: %w", err)
	}
	return data, nil
}

// accountIDFromARN extracts the account id from a channel ARN. The account id
// becomes the RecipientAccountId stamped on every forwarded audit event.
func accountIDFromARN(channelARN string) (string, error) {
	parsed, err := arn.Parse(channelARN)
	if err != nil {
		return "", fmt.Errorf("aws cloudtrail lake: cannot parse account id from channel arn %q: %w", channelARN, err)
	}
	return parsed.AccountID, nil
}

// mapString returns the string value at key in m, or "" when absent or not a
// string.
func mapString(m map[string]any, key string) string {
	if m == nil {
		return ""
	}
	s, _ := m[key].(string)
	return s
}

func init() {
	backend.Register("CLOUDTRAIL_LAKE", newCloudTrailLake)
}
