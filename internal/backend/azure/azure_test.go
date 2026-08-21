package azure

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"strings"
	"testing"

	"github.com/crowdstrike/falcon-integration-gateway/internal/backend"
	"github.com/crowdstrike/falcon-integration-gateway/internal/common"
	"github.com/crowdstrike/falcon-integration-gateway/internal/config"
	"github.com/crowdstrike/falcon-integration-gateway/internal/events"
	"github.com/crowdstrike/falcon-integration-gateway/internal/testutil"
)

func newTestEvent(fields map[string]any, enr events.Enricher) *events.EnrichedEvent {
	ev := &events.Event{Event: fields}
	return events.NewEnrichedEvent(ev, enr)
}

func TestBuildRecordMapsAllFields(t *testing.T) {
	t.Parallel()

	enr := &testutil.FakeEnricher{Host: &common.HostDetails{
		Known:                  true,
		CloudProvider:          "AWS",
		CloudProviderAccountID: "acct-123",
		InstanceID:             "i-0abc",
		Platform:               "Linux",
		ZoneGroup:              "us-east-1a",
	}}
	ev := events.NewEnrichedEvent(&events.Event{
		Metadata: events.Metadata{Offset: 1},
		FeedID:   "feed1",
		Event: map[string]any{
			"DetectId":          "ldt:abc:1",
			"FalconHostLink":    "https://falcon.example/detect/1",
			"SeverityName":      "High",
			"Severity":          float64(70),
			"DetectDescription": "a detection",
			"DetectName":        "SuspiciousActivity",
			"ComputerName":      "host-1",
			"FileName":          "malware.exe",
			"FilePath":          `\Device\HarddiskVolume2`,
			"CommandLine":       "malware.exe --evil",
		},
	}, enr)

	r := &Runtime{logger: testutil.DiscardLogger()}
	rec, err := r.buildRecord(context.Background(), ev)
	if err != nil {
		t.Fatalf("buildRecord: %v", err)
	}

	want := record{
		ExternalURI:        "https://falcon.example/detect/1",
		FalconEventID:      "ldt:abc:1",
		FigDeduplicationID: "feed1_1",
		ComputerName:       "host-1",
		Description:        "a detection",
		Severity:           "High",
		Title:              "Falcon Alert. Instance i-0abc",
		ProcessName:        "malware.exe",
		ProcessPath:        `\Device\HarddiskVolume2`,
		CommandLine:        "malware.exe --evil",
		DetectName:         "SuspiciousActivity",
		AccountID:          "acct-123",
		InstanceID:         "i-0abc",
		CloudProvider:      "AWS",
		ResourceGroup:      "us-east-1a",
	}
	if *rec != want {
		t.Errorf("record = %+v, want %+v", *rec, want)
	}
	if rec.Arc != nil {
		t.Errorf("record must not carry arc when autodiscovery is disabled: %+v", rec.Arc)
	}
}

func TestBuildRecordUnrecognizedCloud(t *testing.T) {
	t.Parallel()

	enr := &testutil.FakeEnricher{Host: &common.HostDetails{Known: true, CloudProvider: ""}}
	ev := newTestEvent(map[string]any{"DetectId": "x"}, enr)

	r := &Runtime{logger: testutil.DiscardLogger()}
	rec, err := r.buildRecord(context.Background(), ev)
	if err != nil {
		t.Fatalf("buildRecord: %v", err)
	}
	if rec.CloudProvider != "Unrecognized" {
		t.Errorf("CloudProvider = %v, want Unrecognized when host has no provider", rec.CloudProvider)
	}
}

// TestBuildRecordIdentityFields proves the two identity fields are populated
// independently: FalconEventId carries the real detection id (empty here, since
// the event has neither DetectId nor CompositeId) while FigDeduplicationId
// always carries the UID (<feedID>_<offset>), the value unique per stream event
// and stable across a crash-restart redelivery.
func TestBuildRecordIdentityFields(t *testing.T) {
	t.Parallel()

	enr := &testutil.FakeEnricher{Host: &common.HostDetails{Known: true, CloudProvider: "AWS"}}
	ev := events.NewEnrichedEvent(&events.Event{
		Metadata: events.Metadata{Offset: 42},
		FeedID:   "feed9",
		Event:    map[string]any{"DetectName": "NoIdEvent"},
	}, enr)

	r := &Runtime{logger: testutil.DiscardLogger()}
	rec, err := r.buildRecord(context.Background(), ev)
	if err != nil {
		t.Fatalf("buildRecord: %v", err)
	}
	if rec.FalconEventID != "" {
		t.Errorf("FalconEventId = %q, want empty (no detection id present)", rec.FalconEventID)
	}
	if rec.FigDeduplicationID != "feed9_42" {
		t.Errorf("FigDeduplicationId = %q, want feed9_42 (UID is the dedup key)", rec.FigDeduplicationID)
	}
}

func TestBuildRecordHostErrorPropagates(t *testing.T) {
	t.Parallel()

	sentinel := errors.New("enrichment down")
	enr := &testutil.FakeEnricher{HostErr: sentinel}
	ev := newTestEvent(map[string]any{"DetectId": "x"}, enr)

	r := &Runtime{logger: testutil.DiscardLogger()}
	if _, err := r.buildRecord(context.Background(), ev); !errors.Is(err, sentinel) {
		t.Fatalf("buildRecord error = %v, want wrapped %v", err, sentinel)
	}
}

func TestBuildRecordAttachesArc(t *testing.T) {
	t.Parallel()

	enr := &testutil.FakeEnricher{
		Host: &common.HostDetails{Known: true, CloudProvider: "AWS", Platform: "Linux"},
		Arc: &events.ArcConfig{
			ResourceName:   "fig-arc-host",
			ResourceGroup:  "fig-rg",
			SubscriptionID: "sub-1",
			TenantID:       "tenant-1",
			VMID:           "vm-1",
		},
	}
	ev := newTestEvent(map[string]any{"DetectId": "x"}, enr)

	r := &Runtime{logger: testutil.DiscardLogger(), arcAutodiscovery: true}
	rec, err := r.buildRecord(context.Background(), ev)
	if err != nil {
		t.Fatalf("buildRecord: %v", err)
	}
	if rec.Arc == nil {
		t.Fatalf("record.Arc = nil, want arc identifiers")
	}
	want := arcRecord{
		ResourceName:   "fig-arc-host",
		ResourceGroup:  "fig-rg",
		SubscriptionID: "sub-1",
		TenantID:       "tenant-1",
		VMID:           "vm-1",
	}
	if *rec.Arc != want {
		t.Errorf("record.Arc = %+v, want %+v", *rec.Arc, want)
	}
}

func TestAutodiscoverGate(t *testing.T) {
	t.Parallel()

	arc := &events.ArcConfig{ResourceName: "r"}
	tests := []struct {
		name             string
		arcAutodiscovery bool
		host             *common.HostDetails
		wantArc          bool
		wantArcCall      bool
	}{
		{
			name:             "disabled returns nil",
			arcAutodiscovery: false,
			host:             &common.HostDetails{CloudProvider: "AWS", Platform: "Linux"},
			wantArc:          false,
			wantArcCall:      false,
		},
		{
			name:             "azure host skipped",
			arcAutodiscovery: true,
			host:             &common.HostDetails{CloudProvider: "AZURE", Platform: "Linux"},
			wantArc:          false,
			wantArcCall:      false,
		},
		{
			name:             "unsupported platform skipped",
			arcAutodiscovery: true,
			host:             &common.HostDetails{CloudProvider: "AWS", Platform: "Mac"},
			wantArc:          false,
			wantArcCall:      false,
		},
		{
			name:             "k8s pod skipped",
			arcAutodiscovery: true,
			host:             &common.HostDetails{CloudProvider: "AWS", Platform: "Linux", ProductTypeDesc: "Pod"},
			wantArc:          false,
			wantArcCall:      false,
		},
		{
			name:             "linux non-azure fetches arc",
			arcAutodiscovery: true,
			host:             &common.HostDetails{CloudProvider: "AWS", Platform: "Linux"},
			wantArc:          true,
			wantArcCall:      true,
		},
		{
			name:             "windows non-azure fetches arc",
			arcAutodiscovery: true,
			host:             &common.HostDetails{CloudProvider: "AWS", Platform: "Windows"},
			wantArc:          true,
			wantArcCall:      true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			enr := &testutil.FakeEnricher{Host: tc.host, Arc: arc}
			ev := newTestEvent(map[string]any{"DetectId": "x"}, enr)
			r := &Runtime{logger: testutil.DiscardLogger(), arcAutodiscovery: tc.arcAutodiscovery}

			got := r.autodiscover(context.Background(), ev, tc.host)
			if tc.wantArc && got == nil {
				t.Errorf("autodiscover = nil, want arc config")
			}
			if !tc.wantArc && got != nil {
				t.Errorf("autodiscover = %+v, want nil", got)
			}
			if tc.wantArcCall && enr.ArcCalls() == 0 {
				t.Errorf("expected ArcConfig to be fetched, arcCalls=0")
			}
			if !tc.wantArcCall && enr.ArcCalls() != 0 {
				t.Errorf("expected no ArcConfig fetch, arcCalls=%d", enr.ArcCalls())
			}
		})
	}
}

func TestAutodiscoverFetchErrorFailsOpen(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	enr := &testutil.FakeEnricher{
		Host:   &common.HostDetails{CloudProvider: "AWS", Platform: "Linux"},
		ArcErr: errors.New("rtr down"),
	}
	ev := newTestEvent(map[string]any{"DetectId": "x"}, enr)
	r := &Runtime{logger: logger, arcAutodiscovery: true}

	if got := r.autodiscover(context.Background(), ev, enr.Host); got != nil {
		t.Errorf("autodiscover = %+v, want nil on fetch error (fail-open)", got)
	}
	if !strings.Contains(buf.String(), "sensor") {
		t.Errorf("expected a warning mentioning the sensor, got: %s", buf.String())
	}
}

// TestRecordMarshalGolden locks the wire shape of the Azure record through the
// JSON marshaller: the exact field names and ordering the custom-log table is
// keyed on, encoding/json's default HTML-escaping of <, >, and & (the payload
// carries a <script> tag and query-string ampersands), literal preservation of
// non-ASCII bytes, backslash escaping, and the "arc" object's omitempty. A drift
// here silently renames a column or changes escaping for every forwarded row.
func TestRecordMarshalGolden(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		rec  record
		want string
	}{
		{
			name: "no arc omits the nested object and html-escapes the payload",
			rec: record{
				ExternalURI:        "https://falcon.example/detect/1?a=1&b=2",
				FalconEventID:      "ldt:abc:1",
				FigDeduplicationID: "feed1_1",
				ComputerName:       "café-01",
				Description:        "<script>alert(1)</script>",
				Severity:           "High",
				Title:              "Falcon Alert. Instance i-0abc",
				ProcessName:        "malware.exe",
				ProcessPath:        `\Device\HarddiskVolume2`,
				CommandLine:        `malware.exe --url="http://x?y&z"`,
				DetectName:         "SuspiciousActivity",
				AccountID:          "acct-123",
				InstanceID:         "i-0abc",
				CloudProvider:      "AWS",
				ResourceGroup:      "us-east-1a",
			},
			want: `{"ExternalUri":"https://falcon.example/detect/1?a=1\u0026b=2",` +
				`"FalconEventId":"ldt:abc:1","FigDeduplicationId":"feed1_1","ComputerName":"café-01",` +
				`"Description":"\u003cscript\u003ealert(1)\u003c/script\u003e",` +
				`"Severity":"High","Title":"Falcon Alert. Instance i-0abc",` +
				`"ProcessName":"malware.exe","ProcessPath":"\\Device\\HarddiskVolume2",` +
				`"CommandLine":"malware.exe --url=\"http://x?y\u0026z\"",` +
				`"DetectName":"SuspiciousActivity","AccountId":"acct-123",` +
				`"InstanceId":"i-0abc","CloudProvider":"AWS","ResourceGroup":"us-east-1a"}`,
		},
		{
			name: "arc nested object uses lower-camel tags",
			rec: record{
				FalconEventID:      "ldt:abc:9",
				FigDeduplicationID: "feed9_42",
				CloudProvider:      "AWS",
				Arc: &arcRecord{
					ResourceName:   "fig-arc-host",
					ResourceGroup:  "fig-rg",
					SubscriptionID: "sub-1",
					TenantID:       "tenant-1",
					VMID:           "vm-1",
				},
			},
			want: `{"ExternalUri":"","FalconEventId":"ldt:abc:9","FigDeduplicationId":"feed9_42","ComputerName":"",` +
				`"Description":"","Severity":"","Title":"","ProcessName":"","ProcessPath":"",` +
				`"CommandLine":"","DetectName":"","AccountId":"","InstanceId":"",` +
				`"CloudProvider":"AWS","ResourceGroup":"",` +
				`"arc":{"resourceName":"fig-arc-host","resourceGroup":"fig-rg",` +
				`"subscriptionId":"sub-1","tenantId":"tenant-1","vmId":"vm-1"}}`,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := json.Marshal(tc.rec)
			if err != nil {
				t.Fatalf("Marshal: %v", err)
			}
			if string(got) != tc.want {
				t.Errorf("Marshal mismatch\n got: %s\nwant: %s", got, tc.want)
			}
		})
	}
}

// fakeUploader is an uploader double capturing the records handed to it.
type fakeUploader struct {
	records []record
	err     error
	calls   int
}

func (f *fakeUploader) upload(_ context.Context, records []record) error {
	f.calls++
	f.records = records
	return f.err
}

func TestName(t *testing.T) {
	t.Parallel()

	r := &Runtime{logger: testutil.DiscardLogger()}
	if got := r.Name(); got != "AZURE" {
		t.Errorf("Name() = %q, want AZURE", got)
	}
}

func TestRelevantEventTypes(t *testing.T) {
	t.Parallel()

	r := &Runtime{logger: testutil.DiscardLogger()}
	got := r.RelevantEventTypes()
	if len(got) != 1 || got[0] != "EppDetectionSummaryEvent" {
		t.Errorf("RelevantEventTypes() = %v, want [EppDetectionSummaryEvent]", got)
	}
}

func TestIsRelevantAlwaysTrue(t *testing.T) {
	t.Parallel()

	enr := &testutil.FakeEnricher{HostErr: errors.New("enrichment down")}
	ev := newTestEvent(map[string]any{"DetectId": "x"}, enr)
	r := &Runtime{logger: testutil.DiscardLogger()}

	if !r.IsRelevant(context.Background(), ev) {
		t.Error("IsRelevant() = false, want true even when enrichment fails")
	}
}

func TestProcessUploadsRecord(t *testing.T) {
	t.Parallel()

	up := &fakeUploader{}
	enr := &testutil.FakeEnricher{Host: &common.HostDetails{
		Known:         true,
		CloudProvider: "AWS",
		InstanceID:    "i-0abc",
		Platform:      "Linux",
	}}
	ev := events.NewEnrichedEvent(&events.Event{
		Metadata: events.Metadata{Offset: 1},
		FeedID:   "feed1",
		Event: map[string]any{
			"DetectId":   "ldt:abc:1",
			"DetectName": "SuspiciousActivity",
		},
	}, enr)

	r := &Runtime{up: up, logger: testutil.DiscardLogger()}
	if err := r.Process(context.Background(), ev); err != nil {
		t.Fatalf("Process: %v", err)
	}
	if up.calls != 1 {
		t.Fatalf("upload calls = %d, want 1", up.calls)
	}
	if len(up.records) != 1 {
		t.Fatalf("uploaded %d records, want 1", len(up.records))
	}
	if up.records[0].FalconEventID != "ldt:abc:1" {
		t.Errorf("record FalconEventId = %v, want ldt:abc:1 (detection id)", up.records[0].FalconEventID)
	}
	if up.records[0].FigDeduplicationID != "feed1_1" {
		t.Errorf("record FigDeduplicationId = %v, want feed1_1 (UID)", up.records[0].FigDeduplicationID)
	}
	if up.records[0].InstanceID != "i-0abc" {
		t.Errorf("record InstanceId = %v, want i-0abc", up.records[0].InstanceID)
	}
}

func TestProcessHostErrorPropagates(t *testing.T) {
	t.Parallel()

	sentinel := errors.New("enrichment down")
	up := &fakeUploader{}
	enr := &testutil.FakeEnricher{HostErr: sentinel}
	ev := newTestEvent(map[string]any{"DetectId": "x"}, enr)

	r := &Runtime{up: up, logger: testutil.DiscardLogger()}
	if err := r.Process(context.Background(), ev); !errors.Is(err, sentinel) {
		t.Fatalf("Process error = %v, want wrapped %v", err, sentinel)
	}
	if up.calls != 0 {
		t.Errorf("upload called %d times, want 0 when record building fails", up.calls)
	}
}

func TestProcessUploadErrorPropagates(t *testing.T) {
	t.Parallel()

	sentinel := errors.New("ingestion rejected")
	up := &fakeUploader{err: sentinel}
	enr := &testutil.FakeEnricher{Host: &common.HostDetails{Known: true, CloudProvider: "AWS"}}
	ev := newTestEvent(map[string]any{"DetectId": "x"}, enr)

	r := &Runtime{up: up, logger: testutil.DiscardLogger()}
	if err := r.Process(context.Background(), ev); !errors.Is(err, sentinel) {
		t.Fatalf("Process error = %v, want wrapped %v", err, sentinel)
	}
}

func TestBuildRecordUnknownHostSkipped(t *testing.T) {
	t.Parallel()

	enr := &testutil.FakeEnricher{Host: &common.HostDetails{Known: false}}
	ev := newTestEvent(map[string]any{"DetectId": "x"}, enr)

	r := &Runtime{logger: testutil.DiscardLogger()}
	rec, err := r.buildRecord(context.Background(), ev)
	if err != nil {
		t.Fatalf("buildRecord: %v", err)
	}
	if rec != nil {
		t.Errorf("buildRecord = %v, want nil for an unresolvable host", rec)
	}
}

func TestProcessSkipsUnresolvableHost(t *testing.T) {
	t.Parallel()

	up := &fakeUploader{}
	enr := &testutil.FakeEnricher{Host: &common.HostDetails{Known: false}}
	ev := newTestEvent(map[string]any{"DetectId": "x", "SensorId": "s-1"}, enr)

	r := &Runtime{up: up, logger: testutil.DiscardLogger()}
	err := r.Process(context.Background(), ev)
	var drop *backend.DropError
	if !errors.As(err, &drop) {
		t.Fatalf("Process error = %v, want a *backend.DropError", err)
	}
	if drop.Reason != "host_unresolved" {
		t.Errorf("drop reason = %q, want %q", drop.Reason, "host_unresolved")
	}
	if up.calls != 0 {
		t.Errorf("upload called %d times, want 0 for an unresolvable host", up.calls)
	}
}

func TestNewBuildsLegacyRuntime(t *testing.T) {
	t.Parallel()

	cfg := &config.Config{}
	cfg.Azure = config.AzureConfig{
		AuthMethod:       "legacy",
		WorkspaceID:      "ws",
		PrimaryKey:       "key",
		ArcAutodiscovery: true,
	}

	b, err := New(cfg, testutil.DiscardLogger())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	r, ok := b.(*Runtime)
	if !ok {
		t.Fatalf("New returned %T, want *Runtime", b)
	}
	if !r.arcAutodiscovery {
		t.Error("arcAutodiscovery not wired from config")
	}
	if r.up == nil {
		t.Error("uploader not constructed")
	}
}
