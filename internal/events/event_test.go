package events

import (
	"encoding/json"
	"testing"
	"time"
)

func TestMappedSeverity(t *testing.T) {
	tests := []struct {
		name  string
		event map[string]any
		want  int
	}{
		{"informational", map[string]any{"SeverityName": "Informational"}, 1},
		{"low", map[string]any{"SeverityName": "Low"}, 2},
		{"medium", map[string]any{"SeverityName": "Medium"}, 3},
		{"high", map[string]any{"SeverityName": "High"}, 4},
		{"critical", map[string]any{"SeverityName": "Critical"}, 5},
		{"missing defaults to 5", map[string]any{}, 5},
		{"nil map defaults to 5", nil, 5},
		{"unknown value defaults to 5", map[string]any{"SeverityName": "Bogus"}, 5},
		{"empty string defaults to 5", map[string]any{"SeverityName": ""}, 5},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := &Event{Event: tt.event}
			if got := e.MappedSeverity(); got != tt.want {
				t.Fatalf("MappedSeverity() = %d, want %d", got, tt.want)
			}
		})
	}
}

func TestSensorIDAndComputerName(t *testing.T) {
	tests := []struct {
		name             string
		event            map[string]any
		wantSensor       string
		wantComputerName string
	}{
		{"SensorId preferred", map[string]any{"SensorId": "s1", "AgentId": "a1"}, "s1", ""},
		{"falls back to AgentId", map[string]any{"AgentId": "a1"}, "a1", ""},
		{"neither present", map[string]any{}, "", ""},
		{"ComputerName preferred", map[string]any{"ComputerName": "c1", "Hostname": "h1"}, "", "c1"},
		{"falls back to Hostname", map[string]any{"Hostname": "h1"}, "", "h1"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := &Event{Event: tt.event}
			if got := e.SensorID(); got != tt.wantSensor {
				t.Errorf("SensorID() = %q, want %q", got, tt.wantSensor)
			}
			if got := e.ComputerName(); got != tt.wantComputerName {
				t.Errorf("ComputerName() = %q, want %q", got, tt.wantComputerName)
			}
		})
	}
}

func TestCreationTimeIsUTC(t *testing.T) {
	// 2021-01-01T00:00:00Z in epoch millis.
	millis := int64(1609459200000)
	e := &Event{Metadata: Metadata{EventCreationTime: millis}}
	got := e.CreationTime()
	if got.Location() != time.UTC {
		t.Fatalf("CreationTime location = %v, want UTC", got.Location())
	}
	want := time.Date(2021, 1, 1, 0, 0, 0, 0, time.UTC)
	if !got.Equal(want) {
		t.Fatalf("CreationTime() = %v, want %v", got, want)
	}
}

func TestCutoff(t *testing.T) {
	now := time.Date(2026, 8, 6, 12, 0, 0, 0, time.UTC)
	got := Cutoff(now, 21)
	want := time.Date(2026, 7, 16, 12, 0, 0, 0, time.UTC)
	if !got.Equal(want) {
		t.Fatalf("Cutoff() = %v, want %v", got, want)
	}
	if got.Location() != time.UTC {
		t.Fatalf("Cutoff location = %v, want UTC", got.Location())
	}
}

// TestIsFilteredOut is the regression test for the timezone bug: the cutoff is
// UTC and we construct events whose creation time lands just inside and just
// outside the cutoff window.
func TestIsFilteredOut(t *testing.T) {
	now := time.Date(2026, 8, 6, 12, 0, 0, 0, time.UTC)
	cutoff := Cutoff(now, 21) // 2026-07-16T12:00:00Z

	// Just AFTER the cutoff (one hour newer) -> not filtered by age.
	insideMillis := cutoff.Add(time.Hour).UnixMilli()
	// Just BEFORE the cutoff (one hour older) -> filtered by age.
	outsideMillis := cutoff.Add(-time.Hour).UnixMilli()

	tests := []struct {
		name         string
		severityName string
		creationMS   int64
		sevThreshold int
		want         bool
	}{
		{"severity above threshold and recent", "High", insideMillis, 2, false},
		{"severity below threshold", "Informational", insideMillis, 2, true},
		{"severity equal to threshold", "Low", insideMillis, 2, false},
		{"too old (just outside cutoff)", "High", outsideMillis, 2, true},
		{"just inside cutoff, passes", "High", insideMillis, 2, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := &Event{
				Metadata: Metadata{EventCreationTime: tt.creationMS},
				Event:    map[string]any{"SeverityName": tt.severityName},
			}
			if got := e.IsFilteredOut(tt.sevThreshold, cutoff); got != tt.want {
				t.Fatalf("IsFilteredOut() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestParseLineRoundTrip(t *testing.T) {
	line := []byte(`{"metadata":{"eventType":"EppDetectionSummaryEvent","offset":42,"eventCreationTime":1609459200000,"customerIDString":"cid-1"},"event":{"SeverityName":"High","SensorId":"sensor-abc","ComputerName":"HOST-1"}}`)
	ev, err := ParseLine(line, "feed99")
	if err != nil {
		t.Fatalf("ParseLine error: %v", err)
	}
	if ev.EventType() != "EppDetectionSummaryEvent" {
		t.Errorf("EventType() = %q", ev.EventType())
	}
	if ev.Offset() != 42 {
		t.Errorf("Offset() = %d, want 42", ev.Offset())
	}
	if ev.FeedID != "feed99" {
		t.Errorf("FeedID = %q, want feed99", ev.FeedID)
	}
	if ev.UID() != "feed99_42" {
		t.Errorf("UID() = %q, want feed99_42", ev.UID())
	}
	if ev.Metadata.CustomerIDString != "cid-1" {
		t.Errorf("CustomerIDString = %q", ev.Metadata.CustomerIDString)
	}
	if ev.MappedSeverity() != 4 {
		t.Errorf("MappedSeverity() = %d, want 4", ev.MappedSeverity())
	}
	if ev.SensorID() != "sensor-abc" {
		t.Errorf("SensorID() = %q", ev.SensorID())
	}
	if ev.ComputerName() != "HOST-1" {
		t.Errorf("ComputerName() = %q", ev.ComputerName())
	}
	if string(ev.Raw) != string(line) {
		t.Errorf("Raw not preserved")
	}
	// Raw must be a copy, not an alias of the input slice.
	line[0] = 'X'
	if ev.Raw[0] == 'X' {
		t.Errorf("Raw aliases input slice; expected a copy")
	}
}

func TestParseLineInvalidJSON(t *testing.T) {
	if _, err := ParseLine([]byte("{not json"), "f1"); err == nil {
		t.Fatalf("expected error for invalid JSON")
	}
}

func TestDetectionAccessorsPreferDetectionKeys(t *testing.T) {
	t.Parallel()
	ev := &Event{
		Metadata: Metadata{CustomerIDString: "cid-123", Version: "1.0"},
		Event: map[string]any{
			"DetectId":          "ldt:abc:1",
			"FalconHostLink":    "https://falcon.example/detect/1",
			"SeverityName":      "High",
			"Severity":          float64(70),
			"DetectDescription": "a detection",
			"DetectName":        "SuspiciousActivity",
			"ServiceName":       "Prevention Policy",
		},
	}

	if got := ev.EventID(); got != "ldt:abc:1" {
		t.Errorf("EventID = %q, want ldt:abc:1", got)
	}
	if got := ev.FalconLink(); got != "https://falcon.example/detect/1" {
		t.Errorf("FalconLink = %q", got)
	}
	if got := ev.CID(); got != "cid-123" {
		t.Errorf("CID = %q, want cid-123", got)
	}
	if got := ev.SeverityName(); got != "High" {
		t.Errorf("SeverityName = %q, want High", got)
	}
	if got := ev.Severity(); got != 70 {
		t.Errorf("Severity = %d, want 70", got)
	}
	if got := ev.DetectDescription(); got != "a detection" {
		t.Errorf("DetectDescription = %q", got)
	}
	if got := ev.DetectName(); got != "SuspiciousActivity" {
		t.Errorf("DetectName = %q", got)
	}
	if got := ev.ServiceName(); got != "Prevention Policy" {
		t.Errorf("ServiceName = %q", got)
	}
}

func TestDetectionAccessorsFallBackToAuditKeys(t *testing.T) {
	t.Parallel()
	ev := &Event{
		Event: map[string]any{
			"CompositeId": "aud:xyz:2",
			"Description": "an audit event",
			"Name":        "UserActivityAuditEvent",
		},
	}

	if got := ev.EventID(); got != "aud:xyz:2" {
		t.Errorf("EventID = %q, want aud:xyz:2", got)
	}
	if got := ev.DetectDescription(); got != "an audit event" {
		t.Errorf("DetectDescription = %q", got)
	}
	if got := ev.DetectName(); got != "UserActivityAuditEvent" {
		t.Errorf("DetectName = %q", got)
	}
}

// TestDedupKey pins the dedup-key contract every sink relies on: the key is the
// UID (<feedID>_<offset>), so distinct offsets yield distinct keys, the same
// offset always yields the same key across a redelivery, and a present
// detection/audit id does not change it.
func TestDedupKey(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		ev   *Event
		want string
	}{
		{
			name: "detection event uses UID, not DetectId",
			ev: &Event{
				Metadata: Metadata{Offset: 42},
				FeedID:   "feed1",
				Event:    map[string]any{"DetectId": "ldt:abc:1"},
			},
			want: "feed1_42",
		},
		{
			name: "audit event uses UID, not CompositeId",
			ev: &Event{
				Metadata: Metadata{Offset: 7},
				FeedID:   "feed1",
				Event:    map[string]any{"CompositeId": "aud:xyz:2"},
			},
			want: "feed1_7",
		},
		{
			name: "distinct offset yields distinct key",
			ev: &Event{
				Metadata: Metadata{Offset: 43},
				FeedID:   "feed1",
				Event:    map[string]any{"DetectId": "ldt:abc:1"},
			},
			want: "feed1_43",
		},
		{
			name: "no event body still yields a non-empty key",
			ev:   &Event{Metadata: Metadata{Offset: 5}, FeedID: "feed2"},
			want: "feed2_5",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := tt.ev.DedupKey(); got != tt.want {
				t.Errorf("DedupKey() = %q, want %q", got, tt.want)
			}
			if got := tt.ev.DedupKey(); got != tt.ev.UID() {
				t.Errorf("DedupKey() = %q, want it to equal UID() = %q", got, tt.ev.UID())
			}
		})
	}
}

func TestParseLinePreservesLargeIntegers(t *testing.T) {
	t.Parallel()
	// 2^53 + 1 is the smallest integer float64 cannot represent exactly.
	const big = "9007199254740993"
	line := []byte(`{"metadata":{"eventType":"EppDetectionSummaryEvent","offset":1},"event":{"ProcessId":` + big + `}}`)
	ev, err := ParseLine(line, "feed1")
	if err != nil {
		t.Fatalf("ParseLine: %v", err)
	}
	got, ok := ev.Event["ProcessId"].(json.Number)
	if !ok {
		t.Fatalf("ProcessId decoded as %T, want json.Number (UseNumber)", ev.Event["ProcessId"])
	}
	if got.String() != big {
		t.Errorf("ProcessId = %s, want %s (no float64 rounding)", got.String(), big)
	}
}

func TestSeverityMissingDefaultsToFive(t *testing.T) {
	t.Parallel()
	ev := &Event{Event: map[string]any{}}
	if got := ev.Severity(); got != 5 {
		t.Errorf("Severity = %d, want 5 when absent (fig/falcon/models.py:66-68)", got)
	}
	if got := ev.SeverityName(); got != "" {
		t.Errorf("SeverityName = %q, want empty when absent", got)
	}
}

func TestProcessAccessors(t *testing.T) {
	t.Parallel()
	ev := &Event{
		Event: map[string]any{
			"FileName":    "malware.exe",
			"FilePath":    `\Device\HarddiskVolume2\Users\admin`,
			"CommandLine": "malware.exe --do-evil",
		},
	}
	if got := ev.FileName(); got != "malware.exe" {
		t.Errorf("FileName = %q, want malware.exe", got)
	}
	if got := ev.FilePath(); got != `\Device\HarddiskVolume2\Users\admin` {
		t.Errorf("FilePath = %q", got)
	}
	if got := ev.CommandLine(); got != "malware.exe --do-evil" {
		t.Errorf("CommandLine = %q, want malware.exe --do-evil", got)
	}
}

func TestProcessAccessorsAbsentAreEmpty(t *testing.T) {
	t.Parallel()
	ev := &Event{Event: map[string]any{}}
	if got := ev.FileName(); got != "" {
		t.Errorf("FileName = %q, want empty when absent", got)
	}
	if got := ev.FilePath(); got != "" {
		t.Errorf("FilePath = %q, want empty when absent", got)
	}
	if got := ev.CommandLine(); got != "" {
		t.Errorf("CommandLine = %q, want empty when absent", got)
	}
}
