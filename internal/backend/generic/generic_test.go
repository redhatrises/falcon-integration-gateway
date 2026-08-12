package generic

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"

	"github.com/crowdstrike/falcon-integration-gateway/internal/backend"
	"github.com/crowdstrike/falcon-integration-gateway/internal/config"
	"github.com/crowdstrike/falcon-integration-gateway/internal/events"
)

// newTestRuntime builds a Runtime with the given event_types config, writing
// logs to buf via a JSON slog handler.
func newTestRuntime(t *testing.T, eventTypes string, buf *bytes.Buffer) *Runtime {
	t.Helper()
	logger := slog.New(slog.NewJSONHandler(buf, nil))
	cfg := &config.Config{Generic: config.GenericConfig{EventTypes: eventTypes}}
	b, err := New(cfg, logger)
	if err != nil {
		t.Fatalf("New returned error: %v", err)
	}
	r, ok := b.(*Runtime)
	if !ok {
		t.Fatalf("New returned %T, want *Runtime", b)
	}
	return r
}

func TestRelevantEventTypes(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		eventTypes string
		want       []string
	}{
		{name: "ALL keyword", eventTypes: "ALL", want: backend.AllEventTypes},
		{name: "ALL mixed case with spaces", eventTypes: "  all  ", want: backend.AllEventTypes},
		{name: "CSV list", eventTypes: "EppDetectionSummaryEvent, AuthActivityAuditEvent", want: []string{"EppDetectionSummaryEvent", "AuthActivityAuditEvent"}},
		{name: "empty falls back to ALL", eventTypes: "", want: backend.AllEventTypes},
		{name: "only commas falls back to ALL", eventTypes: " , , ", want: backend.AllEventTypes},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var buf bytes.Buffer
			r := newTestRuntime(t, tc.eventTypes, &buf)
			got := r.RelevantEventTypes()
			if len(got) != len(tc.want) {
				t.Fatalf("RelevantEventTypes() = %v, want %v", got, tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Fatalf("RelevantEventTypes()[%d] = %q, want %q", i, got[i], tc.want[i])
				}
			}
		})
	}
}

func TestName(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	r := newTestRuntime(t, "ALL", &buf)
	if got := r.Name(); got != "GENERIC" {
		t.Fatalf("Name() = %q, want GENERIC", got)
	}
}

func TestIsRelevant(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	r := newTestRuntime(t, "ALL", &buf)
	if !r.IsRelevant(context.Background(), events.NewEnrichedEvent(&events.Event{}, nil)) {
		t.Fatal("IsRelevant() = false, want true")
	}
}

func TestProcessLogsEvent(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	r := newTestRuntime(t, "ALL", &buf)

	ev := &events.Event{
		Metadata: events.Metadata{EventType: "EppDetectionSummaryEvent", Offset: 42},
		FeedID:   "feed-1",
		Raw:      []byte(`{"metadata":{"eventType":"EppDetectionSummaryEvent"}}`),
	}

	buf.Reset()
	if err := r.Process(context.Background(), events.NewEnrichedEvent(ev, nil)); err != nil {
		t.Fatalf("Process returned error: %v", err)
	}

	// Assert the emitted JSON log line carries the structured fields.
	out := buf.String()
	if !strings.Contains(out, "EppDetectionSummaryEvent") {
		t.Fatalf("log output missing event_type: %s", out)
	}

	// Parse the last JSON line and verify fields.
	var rec map[string]any
	line := lastLine(out)
	if err := json.Unmarshal([]byte(line), &rec); err != nil {
		t.Fatalf("log line is not valid JSON: %v (line=%q)", err, line)
	}
	if rec["event_type"] != "EppDetectionSummaryEvent" {
		t.Errorf("event_type = %v, want EppDetectionSummaryEvent", rec["event_type"])
	}
	if rec["feed_id"] != "feed-1" {
		t.Errorf("feed_id = %v, want feed-1", rec["feed_id"])
	}
	if rec["uid"] != "feed-1_42" {
		t.Errorf("uid = %v, want feed-1_42", rec["uid"])
	}
	// The raw event body carries tenant data and must not appear on the INFO
	// line; it is emitted only at DEBUG (see TestProcessLogsRawAtDebug).
	if _, ok := rec["event"]; ok {
		t.Errorf("INFO log line unexpectedly carries raw event body")
	}
}

// TestProcessLogsRawAtDebug verifies the raw event body is emitted at DEBUG so
// operators opt into logging tenant data rather than getting it by default.
func TestProcessLogsRawAtDebug(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	cfg := &config.Config{Generic: config.GenericConfig{EventTypes: "ALL"}}
	b, err := New(cfg, logger)
	if err != nil {
		t.Fatalf("New returned error: %v", err)
	}
	r, ok := b.(*Runtime)
	if !ok {
		t.Fatalf("New returned %T, want *Runtime", b)
	}

	raw := `{"metadata":{"eventType":"EppDetectionSummaryEvent"}}`
	ev := &events.Event{
		Metadata: events.Metadata{EventType: "EppDetectionSummaryEvent", Offset: 42},
		FeedID:   "feed-1",
		Raw:      []byte(raw),
	}

	buf.Reset()
	if err := r.Process(context.Background(), events.NewEnrichedEvent(ev, nil)); err != nil {
		t.Fatalf("Process returned error: %v", err)
	}

	// Find the DEBUG line carrying the raw body among the emitted lines.
	var found bool
	for _, line := range strings.Split(strings.TrimSpace(buf.String()), "\n") {
		var rec map[string]any
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			continue
		}
		if rec["event"] == raw {
			found = true
		}
	}
	if !found {
		t.Fatalf("no DEBUG line carried the raw event body; output: %s", buf.String())
	}
}

func lastLine(s string) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	return lines[len(lines)-1]
}
