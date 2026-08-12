package events

import (
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
