// Package testutil holds hermetic helpers shared across the project's test
// suites: a silent logger and builders for synthetic Falcon stream events.
//
// Only helpers that rely solely on exported API belong here. Test doubles that
// reach into a package's unexported types stay co-located with that package's
// tests, where they can see those internals.
package testutil

import (
	"fmt"
	"log/slog"
	"testing"

	"github.com/crowdstrike/falcon-integration-gateway/internal/events"
)

// DiscardLogger returns a logger that drops every record, for tests that need a
// non-nil *slog.Logger but assert nothing about its output.
func DiscardLogger() *slog.Logger {
	return slog.New(slog.DiscardHandler)
}

// EventOptions configures a synthetic Falcon stream event. The zero value
// renders a minimal event with an empty body at offset 0.
type EventOptions struct {
	// FeedID is the stream partition ID ParseLine stamps onto the Event; it is
	// ignored by EventLine, which only renders the wire JSON.
	FeedID string
	// EventType populates metadata.eventType.
	EventType string
	// Offset populates metadata.offset.
	Offset uint64
	// CreationMillis populates metadata.eventCreationTime (epoch milliseconds).
	CreationMillis int64
	// SeverityName, when non-empty, is added to the event body as SeverityName
	// so the global severity filter can be exercised.
	SeverityName string
}

// EventLine renders one newline-free Falcon stream event as wire JSON. It is the
// single source of the stream-event skeleton the test suites assert against.
func EventLine(opts EventOptions) string {
	body := "{}"
	if opts.SeverityName != "" {
		body = fmt.Sprintf(`{"SeverityName":%q}`, opts.SeverityName)
	}
	return fmt.Sprintf(
		`{"metadata":{"eventType":%q,"offset":%d,"eventCreationTime":%d},"event":%s}`,
		opts.EventType, opts.Offset, opts.CreationMillis, body,
	)
}

// MustEvent renders opts via EventLine and parses it through events.ParseLine so
// the real accessors are exercised, failing the test on a parse error.
func MustEvent(t *testing.T, opts EventOptions) *events.Event {
	t.Helper()
	ev, err := events.ParseLine([]byte(EventLine(opts)), opts.FeedID)
	if err != nil {
		t.Fatalf("testutil.MustEvent: ParseLine: %v", err)
	}
	return ev
}
