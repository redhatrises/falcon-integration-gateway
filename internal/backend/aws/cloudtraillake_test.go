package aws

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"maps"
	"sync"
	"testing"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudtraildata"
	cloudtraildatatypes "github.com/aws/aws-sdk-go-v2/service/cloudtraildata/types"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	ssmtypes "github.com/aws/aws-sdk-go-v2/service/ssm/types"

	"github.com/crowdstrike/falcon-integration-gateway/internal/backend"
	"github.com/crowdstrike/falcon-integration-gateway/internal/events"
)

// fakeCloudTrail records PutAuditEvents calls and can simulate transport errors
// or per-event ingestion failures.
type fakeCloudTrail struct {
	inputs []*cloudtraildata.PutAuditEventsInput
	err    error
	failed []cloudtraildatatypes.ResultErrorEntry
}

func (f *fakeCloudTrail) PutAuditEvents(_ context.Context, in *cloudtraildata.PutAuditEventsInput, _ ...func(*cloudtraildata.Options)) (*cloudtraildata.PutAuditEventsOutput, error) {
	f.inputs = append(f.inputs, in)
	if f.err != nil {
		return nil, f.err
	}
	return &cloudtraildata.PutAuditEventsOutput{Failed: f.failed}, nil
}

// fakeGuardSSM is an in-memory SSM stand-in for the dedup guard. A missing
// parameter returns ParameterNotFound so the guard exercises its create path.
type fakeGuardSSM struct {
	mu     sync.Mutex
	params map[string]string
	puts   int
	getErr error
	putErr error
}

func (f *fakeGuardSSM) GetParameter(_ context.Context, in *ssm.GetParameterInput, _ ...func(*ssm.Options)) (*ssm.GetParameterOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.getErr != nil {
		return nil, f.getErr
	}
	v, ok := f.params[awssdk.ToString(in.Name)]
	if !ok {
		return nil, &ssmtypes.ParameterNotFound{}
	}
	return &ssm.GetParameterOutput{Parameter: &ssmtypes.Parameter{Value: awssdk.String(v)}}, nil
}

func (f *fakeGuardSSM) PutParameter(_ context.Context, in *ssm.PutParameterInput, _ ...func(*ssm.Options)) (*ssm.PutParameterOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.putErr != nil {
		return nil, f.putErr
	}
	if f.params == nil {
		f.params = map[string]string{}
	}
	f.params[awssdk.ToString(in.Name)] = awssdk.ToString(in.Value)
	f.puts++
	return &ssm.PutParameterOutput{}, nil
}

func newTestGuard(t *testing.T, ssmClient guardSSMAPI) *lastSeenOffsets {
	t.Helper()
	g, err := newLastSeenOffsets(context.Background(), ssmClient, slog.New(slog.DiscardHandler), "last_seen_offsets")
	if err != nil {
		t.Fatalf("newLastSeenOffsets: %v", err)
	}
	return g
}

func authEvent(offset uint64) *events.EnrichedEvent {
	return events.NewEnrichedEvent(&events.Event{
		Metadata: events.Metadata{
			Offset:    offset,
			EventType: "AuthActivityAuditEvent",
			Version:   "1.0",
		},
		FeedID: "feed1",
		Raw:    []byte(`{"metadata":{},"event":{}}`),
		Event: map[string]any{
			"ServiceName":   "CrowdStrike Authentication",
			"UserId":        "user@example.com",
			"UserIp":        "1.2.3.4",
			"OperationName": "userAuthenticate",
		},
	}, nil)
}

func newTestCloudTrail(logger *slog.Logger, client cloudTrailAPI, guard *lastSeenOffsets) *cloudTrailLake {
	return &cloudTrailLake{
		logger:     logger,
		client:     client,
		channelARN: "arn:aws:cloudtrail:us-east-1:123456789012:channel/abc",
		accountID:  "123456789012",
		offsets:    guard,
	}
}

func TestAccountIDFromARN(t *testing.T) {
	t.Parallel()
	got, err := accountIDFromARN("arn:aws:cloudtrail:us-east-1:123456789012:channel/abc")
	if err != nil {
		t.Fatalf("accountIDFromARN: %v", err)
	}
	if got != "123456789012" {
		t.Errorf("accountID = %q, want 123456789012", got)
	}
	if _, err := accountIDFromARN("too:short"); err == nil {
		t.Error("malformed ARN = nil error, want error")
	}
}

// TestCloudTrailEventTimeIsUTC locks the eventTime projection: the CloudTrail
// Lake schema requires a UTC, Z-suffixed timestamp, so an event whose creation
// instant falls in a non-UTC zone must still be rendered in UTC. Here noon PDT
// (UTC-7) must serialize as 19:34:56Z.
func TestCloudTrailEventTimeIsUTC(t *testing.T) {
	t.Parallel()
	rt := newTestCloudTrail(slog.New(slog.DiscardHandler), &fakeCloudTrail{}, nil)

	pdt := time.FixedZone("PDT", -7*3600)
	ev := events.NewEnrichedEvent(&events.Event{
		Metadata: events.Metadata{
			EventType:         "AuthActivityAuditEvent",
			Version:           "1.0",
			EventCreationTime: time.Date(2026, 8, 14, 12, 34, 56, 0, pdt).UnixMilli(),
		},
		FeedID: "feed1",
		Raw:    []byte(`{"metadata":{},"event":{}}`),
		Event:  map[string]any{"OperationName": "userAuthenticate", "UserId": "user@example.com", "UserIp": "1.2.3.4"},
	}, nil)

	data, err := rt.buildEventData(ev)
	if err != nil {
		t.Fatalf("buildEventData: %v", err)
	}
	var got map[string]any
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("eventData is not valid JSON: %v", err)
	}
	if got["eventTime"] != "2026-08-14T19:34:56Z" {
		t.Errorf("eventTime = %v, want 2026-08-14T19:34:56Z (UTC, Z-suffixed)", got["eventTime"])
	}
}

// TestCloudTrailDropsMissingPrincipalFields locks the audit-critical drop: an
// event missing any of UserId, OperationName, or UserIp must be dropped (a
// backend.DropError) rather than forwarded with a blank field, while a complete
// event is forwarded. This mirrors the reference gateway, which read these keys
// with subscript access and discarded events lacking any of them.
func TestCloudTrailDropsMissingPrincipalFields(t *testing.T) {
	t.Parallel()

	base := map[string]any{
		"UserId":        "user@example.com",
		"UserIp":        "1.2.3.4",
		"OperationName": "userAuthenticate",
	}
	tests := []struct {
		name    string
		omit    string
		empty   string
		wantErr bool
	}{
		{name: "complete event forwarded", wantErr: false},
		{name: "missing UserId dropped", omit: "UserId", wantErr: true},
		{name: "missing OperationName dropped", omit: "OperationName", wantErr: true},
		{name: "missing UserIp dropped", omit: "UserIp", wantErr: true},
		{name: "empty UserId dropped", empty: "UserId", wantErr: true},
		{name: "empty OperationName dropped", empty: "OperationName", wantErr: true},
		{name: "empty UserIp dropped", empty: "UserIp", wantErr: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			fields := map[string]any{}
			maps.Copy(fields, base)
			if tc.omit != "" {
				delete(fields, tc.omit)
			}
			if tc.empty != "" {
				fields[tc.empty] = ""
			}
			rt := newTestCloudTrail(slog.New(slog.DiscardHandler), &fakeCloudTrail{}, nil)
			ev := events.NewEnrichedEvent(&events.Event{
				Metadata: events.Metadata{EventType: "AuthActivityAuditEvent", Version: "1.0"},
				FeedID:   "feed1",
				Raw:      []byte(`{"metadata":{},"event":{}}`),
				Event:    fields,
			}, nil)

			_, err := rt.buildEventData(ev)
			if tc.wantErr {
				var drop *backend.DropError
				if !errors.As(err, &drop) {
					t.Fatalf("buildEventData error = %v, want a *backend.DropError", err)
				}
				if drop.Reason != "cloudtrail_missing_principal" {
					t.Errorf("drop reason = %q, want cloudtrail_missing_principal", drop.Reason)
				}
				return
			}
			if err != nil {
				t.Fatalf("buildEventData: unexpected error %v", err)
			}
		})
	}
}

func TestCloudTrailIsRelevant(t *testing.T) {
	t.Parallel()
	guard := newTestGuard(t, &fakeGuardSSM{params: map[string]string{"last_seen_offsets": `{"feed1":3}`}})
	rt := newTestCloudTrail(slog.New(slog.DiscardHandler), &fakeCloudTrail{}, guard)

	tests := []struct {
		name    string
		service string
		feedID  string
		offset  uint64
		want    bool
	}{
		{"new offset on known feed", "CrowdStrike Authentication", "feed1", 5, true},
		{"offset not greater than last seen", "CrowdStrike Authentication", "feed1", 3, false},
		{"unknown feed starts at zero", "CrowdStrike Authentication", "feed2", 1, true},
		{"wrong service name", "detection service", "feed1", 100, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ev := events.NewEnrichedEvent(&events.Event{
				Metadata: events.Metadata{Offset: tc.offset},
				FeedID:   tc.feedID,
				Event:    map[string]any{"ServiceName": tc.service},
			}, nil)
			if got := rt.IsRelevant(context.Background(), ev); got != tc.want {
				t.Errorf("IsRelevant = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestCloudTrailProcessPutsAndUpdatesGuard(t *testing.T) {
	t.Parallel()
	ct := &fakeCloudTrail{}
	guardSSM := &fakeGuardSSM{params: map[string]string{"last_seen_offsets": `{}`}}
	guard := newTestGuard(t, guardSSM)
	rt := newTestCloudTrail(slog.New(slog.DiscardHandler), ct, guard)

	ev := authEvent(7)
	if err := rt.Process(context.Background(), ev); err != nil {
		t.Fatalf("Process: %v", err)
	}
	if len(ct.inputs) != 1 {
		t.Fatalf("PutAuditEvents called %d times, want 1", len(ct.inputs))
	}
	in := ct.inputs[0]
	if awssdk.ToString(in.ChannelArn) != "arn:aws:cloudtrail:us-east-1:123456789012:channel/abc" {
		t.Errorf("ChannelArn = %q", awssdk.ToString(in.ChannelArn))
	}
	if len(in.AuditEvents) != 1 {
		t.Fatalf("AuditEvents len = %d, want 1", len(in.AuditEvents))
	}
	if awssdk.ToString(in.AuditEvents[0].Id) != ev.UID() {
		t.Errorf("audit event Id = %q, want %q", awssdk.ToString(in.AuditEvents[0].Id), ev.UID())
	}

	var data map[string]any
	if err := json.Unmarshal([]byte(awssdk.ToString(in.AuditEvents[0].EventData)), &data); err != nil {
		t.Fatalf("eventData is not valid JSON: %v", err)
	}
	if data["eventName"] != "userAuthenticate" {
		t.Errorf("eventData.eventName = %v, want userAuthenticate", data["eventName"])
	}
	if data["recipientAccountId"] != "123456789012" {
		t.Errorf("eventData.recipientAccountId = %v", data["recipientAccountId"])
	}

	if got := guard.seen("feed1"); got != 7 {
		t.Errorf("guard.seen(feed1) = %d, want 7 after successful put", got)
	}
}

func TestCloudTrailProcessPutErrorDoesNotAdvanceGuard(t *testing.T) {
	t.Parallel()
	sentinel := errors.New("boom")
	ct := &fakeCloudTrail{err: sentinel}
	guard := newTestGuard(t, &fakeGuardSSM{params: map[string]string{"last_seen_offsets": `{}`}})
	rt := newTestCloudTrail(slog.New(slog.DiscardHandler), ct, guard)

	err := rt.Process(context.Background(), authEvent(7))
	if !errors.Is(err, sentinel) {
		t.Fatalf("Process error = %v, want it to wrap the PutAuditEvents failure", err)
	}
	if got := guard.seen("feed1"); got != 0 {
		t.Errorf("guard.seen(feed1) = %d, want 0 after failed put", got)
	}
}

func TestCloudTrailProcessFailedEntries(t *testing.T) {
	t.Parallel()
	ct := &fakeCloudTrail{failed: []cloudtraildatatypes.ResultErrorEntry{{
		ErrorCode:    awssdk.String("InvalidData"),
		ErrorMessage: awssdk.String("bad"),
		Id:           awssdk.String("feed1_7"),
	}}}
	guard := newTestGuard(t, &fakeGuardSSM{params: map[string]string{"last_seen_offsets": `{}`}})
	rt := newTestCloudTrail(slog.New(slog.DiscardHandler), ct, guard)

	if err := rt.Process(context.Background(), authEvent(7)); err == nil {
		t.Fatal("Process with failed entries = nil error, want error")
	}
	if got := guard.seen("feed1"); got != 0 {
		t.Errorf("guard.seen(feed1) = %d, want 0 after failed ingestion", got)
	}
}

func TestLastSeenOffsetsMonotonic(t *testing.T) {
	t.Parallel()
	guardSSM := &fakeGuardSSM{params: map[string]string{"last_seen_offsets": `{}`}}
	guard := newTestGuard(t, guardSSM)

	guardSSM.mu.Lock()
	putsAfterHydrate := guardSSM.puts
	guardSSM.mu.Unlock()

	if err := guard.update(context.Background(), "feed1", 5); err != nil {
		t.Fatalf("update: %v", err)
	}
	if got := guard.seen("feed1"); got != 5 {
		t.Errorf("seen after update to 5 = %d, want 5", got)
	}

	// A lower offset must not move the watermark or write to SSM.
	if err := guard.update(context.Background(), "feed1", 3); err != nil {
		t.Fatalf("update: %v", err)
	}
	if got := guard.seen("feed1"); got != 5 {
		t.Errorf("seen after non-monotonic update = %d, want 5", got)
	}

	guardSSM.mu.Lock()
	defer guardSSM.mu.Unlock()
	if guardSSM.puts != putsAfterHydrate+1 {
		t.Errorf("SSM writes = %d, want exactly one for the monotonic increase", guardSSM.puts-putsAfterHydrate)
	}
}

func TestNewLastSeenOffsetsCreatesMissingParam(t *testing.T) {
	t.Parallel()
	guardSSM := &fakeGuardSSM{}
	guard := newTestGuard(t, guardSSM)

	if got := guard.seen("feed1"); got != 0 {
		t.Errorf("seen on fresh guard = %d, want 0", got)
	}
	guardSSM.mu.Lock()
	defer guardSSM.mu.Unlock()
	if _, ok := guardSSM.params["last_seen_offsets"]; !ok {
		t.Error("guard did not create the missing SSM parameter")
	}
}

// TestNewLastSeenOffsetsMigratesLegacyRepr covers the upgrade path from the
// legacy gateway, which persisted this parameter as a single-quoted dict repr
// rather than JSON. The guard must migrate it in place so the watermark
// is preserved and already-ingested audit events are not re-admitted.
func TestNewLastSeenOffsetsMigratesLegacyRepr(t *testing.T) {
	t.Parallel()
	guardSSM := &fakeGuardSSM{params: map[string]string{"last_seen_offsets": "{'feed1': 42, 'feed2': 7}"}}
	guard := newTestGuard(t, guardSSM)

	if got := guard.seen("feed1"); got != 42 {
		t.Errorf("seen(feed1) after legacy-repr migration = %d, want 42", got)
	}
	if got := guard.seen("feed2"); got != 7 {
		t.Errorf("seen(feed2) after legacy-repr migration = %d, want 7", got)
	}
}

// TestNewLastSeenOffsetsToleratesUnparseableValue covers the upgrade path where
// the persisted parameter is neither JSON nor a recognized legacy encoding: the
// guard must start from an empty watermark instead of refusing to boot.
func TestNewLastSeenOffsetsToleratesUnparseableValue(t *testing.T) {
	t.Parallel()
	guardSSM := &fakeGuardSSM{params: map[string]string{"last_seen_offsets": "not json or repr"}}
	guard := newTestGuard(t, guardSSM)

	if got := guard.seen("feed1"); got != 0 {
		t.Errorf("seen after unreadable hydrate = %d, want 0 (empty watermark)", got)
	}
}

// TestParseLegacyReprOffsets pins the repr→JSON migration helper directly: a
// well-formed single-quoted dict repr converts, while inputs the migration does
// not understand report false so the caller falls back to an empty watermark.
func TestParseLegacyReprOffsets(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		in     string
		wantOK bool
		want   map[string]uint64
	}{
		{"legacy repr", "{'feed1': 42, 'feed2': 7}", true, map[string]uint64{"feed1": 42, "feed2": 7}},
		{"empty legacy dict", "{}", true, map[string]uint64{}},
		{"already json is also accepted", `{"feed1":42}`, true, map[string]uint64{"feed1": 42}},
		{"garbage", "not json or repr", false, nil},
		{"partial", "{'feed1':", false, nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, ok := parseLegacyReprOffsets(tc.in)
			if ok != tc.wantOK {
				t.Fatalf("parseLegacyReprOffsets(%q) ok = %v, want %v", tc.in, ok, tc.wantOK)
			}
			if !tc.wantOK {
				return
			}
			if len(got) != len(tc.want) {
				t.Fatalf("parseLegacyReprOffsets(%q) = %v, want %v", tc.in, got, tc.want)
			}
			for k, v := range tc.want {
				if got[k] != v {
					t.Errorf("offset[%q] = %d, want %d", k, got[k], v)
				}
			}
		})
	}
}

// TestLastSeenOffsetsConcurrentPersistConsistent verifies the debounced guard
// contract under concurrent workers: the in-memory watermark advances to the
// highest observed offset synchronously, and after Close the persisted SSM value
// is reconciled to that same watermark. Durable writes are coalesced during the
// run, so the persisted value is only guaranteed to match the watermark once
// Close flushes the final pending write.
func TestLastSeenOffsetsConcurrentPersistConsistent(t *testing.T) {
	t.Parallel()
	guardSSM := &fakeGuardSSM{params: map[string]string{"last_seen_offsets": `{}`}}
	guard := newTestGuard(t, guardSSM)

	const workers = 8
	const perWorker = 50
	var wg sync.WaitGroup
	for range workers {
		wg.Go(func() {
			for i := 1; i <= perWorker; i++ {
				if err := guard.update(context.Background(), "feed1", uint64(i)); err != nil {
					t.Errorf("update: %v", err)
					return
				}
			}
		})
	}
	wg.Wait()

	const want = uint64(perWorker)
	if got := guard.seen("feed1"); got != want {
		t.Errorf("seen after concurrent updates = %d, want %d", got, want)
	}

	// Close reconciles the coalesced durable write to the in-memory watermark.
	if err := guard.close(context.Background()); err != nil {
		t.Fatalf("close: %v", err)
	}

	guardSSM.mu.Lock()
	stored := guardSSM.params["last_seen_offsets"]
	guardSSM.mu.Unlock()
	var persisted map[string]uint64
	if err := json.Unmarshal([]byte(stored), &persisted); err != nil {
		t.Fatalf("persisted value not valid JSON: %v", err)
	}
	if persisted["feed1"] != want {
		t.Errorf("persisted feed1 = %d, want %d after Close", persisted["feed1"], want)
	}
}

// TestLastSeenOffsetsCoalescesBurst proves the F-04 debounce: a burst of
// advancing updates within the flush interval writes SSM once (the immediate
// first flush), coalescing the rest, and Close flushes the final watermark. This
// is what bounds the per-event PutParameter storm the pre-debounce guard caused.
func TestLastSeenOffsetsCoalescesBurst(t *testing.T) {
	t.Parallel()
	guardSSM := &fakeGuardSSM{params: map[string]string{"last_seen_offsets": `{}`}}
	guard := newTestGuard(t, guardSSM)

	guardSSM.mu.Lock()
	putsAfterHydrate := guardSSM.puts
	guardSSM.mu.Unlock()

	const burst = 20
	for i := 1; i <= burst; i++ {
		if err := guard.update(context.Background(), "feed1", uint64(i)); err != nil {
			t.Fatalf("update(%d): %v", i, err)
		}
	}

	// The first advancing commit flushes immediately (lastFlush is zero); the
	// remaining 19 land within the interval and are coalesced.
	guardSSM.mu.Lock()
	putsDuringBurst := guardSSM.puts - putsAfterHydrate
	guardSSM.mu.Unlock()
	if putsDuringBurst != 1 {
		t.Fatalf("SSM writes during burst = %d, want 1 (first flush, rest coalesced)", putsDuringBurst)
	}
	if got := guard.seen("feed1"); got != burst {
		t.Errorf("seen during burst = %d, want %d (in-memory advances synchronously)", got, burst)
	}

	if err := guard.close(context.Background()); err != nil {
		t.Fatalf("close: %v", err)
	}
	guardSSM.mu.Lock()
	putsAfterClose := guardSSM.puts - putsAfterHydrate
	stored := guardSSM.params["last_seen_offsets"]
	guardSSM.mu.Unlock()
	if putsAfterClose != 2 {
		t.Errorf("SSM writes after Close = %d, want 2 (burst flush + Close flush)", putsAfterClose)
	}
	var persisted map[string]uint64
	if err := json.Unmarshal([]byte(stored), &persisted); err != nil {
		t.Fatalf("persisted value not valid JSON: %v", err)
	}
	if persisted["feed1"] != burst {
		t.Errorf("persisted feed1 = %d, want %d after Close", persisted["feed1"], burst)
	}
}

// TestCloudTrailCloseFlushesGuard exercises the backend.Closer wiring: two
// events on one feed advance the guard, but only the first is persisted
// immediately (the second is coalesced), and cloudTrailLake.Close reconciles the
// durable watermark to the latest offset.
func TestCloudTrailCloseFlushesGuard(t *testing.T) {
	t.Parallel()
	ct := &fakeCloudTrail{}
	guardSSM := &fakeGuardSSM{params: map[string]string{"last_seen_offsets": `{}`}}
	guard := newTestGuard(t, guardSSM)
	rt := newTestCloudTrail(slog.New(slog.DiscardHandler), ct, guard)

	ctx := context.Background()
	if err := rt.Process(ctx, authEvent(5)); err != nil {
		t.Fatalf("Process(5): %v", err)
	}
	if err := rt.Process(ctx, authEvent(6)); err != nil {
		t.Fatalf("Process(6): %v", err)
	}

	// The second Process is coalesced, so SSM still holds 5 while memory holds 6.
	guardSSM.mu.Lock()
	beforeClose := guardSSM.params["last_seen_offsets"]
	guardSSM.mu.Unlock()
	var mid map[string]uint64
	if err := json.Unmarshal([]byte(beforeClose), &mid); err != nil {
		t.Fatalf("pre-Close value not valid JSON: %v", err)
	}
	if mid["feed1"] != 5 {
		t.Errorf("persisted feed1 before Close = %d, want 5 (second write coalesced)", mid["feed1"])
	}

	if err := rt.Close(ctx); err != nil {
		t.Fatalf("Close: %v", err)
	}
	guardSSM.mu.Lock()
	afterClose := guardSSM.params["last_seen_offsets"]
	guardSSM.mu.Unlock()
	var final map[string]uint64
	if err := json.Unmarshal([]byte(afterClose), &final); err != nil {
		t.Fatalf("post-Close value not valid JSON: %v", err)
	}
	if final["feed1"] != 6 {
		t.Errorf("persisted feed1 after Close = %d, want 6", final["feed1"])
	}
}
