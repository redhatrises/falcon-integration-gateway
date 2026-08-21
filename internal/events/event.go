// Package events defines the raw Falcon Event Streams event and the pure,
// config-independent accessors, severity mapping, and filters over it.
//
// This is a port of fig/falcon/models.py (the Event class). It depends on no
// stateful FIG package (in particular not config): filtering thresholds are
// passed in by the caller so the model stays pure and testable. Its only FIG
// dependency is the stdlib-only utils leaf, for shared numeric coercion.
package events

import (
	"bytes"
	"encoding/json"
	"strconv"
	"time"

	"github.com/crowdstrike/falcon-integration-gateway/internal/utils"
)

// severityByName maps CrowdStrike SeverityName values to the internal 1-5
// scale. Port of fig/falcon/models.py:44-52.
var severityByName = map[string]int{
	"Informational": 1,
	"Low":           2,
	"Medium":        3,
	"High":          4,
	"Critical":      5,
}

// EppDetectionSummaryEventType is the eventType of an endpoint-protection
// detection summary — the detection family every detection-forwarding backend
// filters on, both per-event and as a server-side stream filter.
const EppDetectionSummaryEventType = "EppDetectionSummaryEvent"

// Metadata is the "metadata" object of a stream event line.
type Metadata struct {
	EventType         string `json:"eventType"`
	Offset            uint64 `json:"offset"`
	EventCreationTime int64  `json:"eventCreationTime"`
	CustomerIDString  string `json:"customerIDString"`
	Version           string `json:"version"`
}

// Event is one decoded line from the Falcon Event Streams data feed.
//
// FeedID is the stream partition/feed identifier parsed from the datafeed URL;
// it is an alphanumeric ([0-9a-zA-Z]+) token, so it is a string, not an int.
// Raw holds a copy of the original line for backends that forward the verbatim
// JSON (e.g. GENERIC).
type Event struct {
	Metadata Metadata       `json:"metadata"`
	Event    map[string]any `json:"event"`
	FeedID   string         `json:"-"`
	Raw      []byte         `json:"-"`
}

// ParseLine decodes a single newline-delimited stream line into an Event,
// tagging it with feedID and storing a defensive copy of the raw bytes. The
// event body is decoded with UseNumber so JSON numbers land in the event map as
// json.Number, preserving integer identifiers larger than 2^53 that a float64
// would round (utils.IntFromAny and CEF rendering handle json.Number exactly).
func ParseLine(line []byte, feedID string) (*Event, error) {
	var ev Event
	dec := json.NewDecoder(bytes.NewReader(line))
	dec.UseNumber()
	if err := dec.Decode(&ev); err != nil {
		return nil, err
	}
	ev.FeedID = feedID
	raw := make([]byte, len(line))
	copy(raw, line)
	ev.Raw = raw
	return &ev, nil
}

// EventType returns the event type from metadata.
func (e *Event) EventType() string {
	return e.Metadata.EventType
}

// Offset returns the stream offset from metadata.
func (e *Event) Offset() uint64 {
	return e.Metadata.Offset
}

// UID returns a stable identifier "<feedID>_<offset>". Port of Event.uid.
func (e *Event) UID() string {
	return e.FeedID + "_" + strconv.FormatUint(e.Metadata.Offset, 10)
}

// DedupKey returns a deterministic identifier for the event, suitable for
// downstream de-duplication of a crash-restart redelivery. It is the UID
// (<feedID>_<offset>): the offset is monotonic within a feed, so the key is
// unique per stream event, and a redelivered event returns at the same offset,
// so the same event always yields the same key. The detection/audit id
// (EventID) is deliberately not used here — Falcon re-emits summary and alert
// events at new offsets under the same id when a detection is updated, so it is
// not unique per event and would collapse distinct events.
func (e *Event) DedupKey() string {
	return e.UID()
}

// CreationTime returns the event creation time as a UTC time.Time.
//
// The stream timestamp is epoch milliseconds; this always interprets it as UTC
// so the age filter is timezone-independent.
func (e *Event) CreationTime() time.Time {
	return time.UnixMilli(e.Metadata.EventCreationTime).UTC()
}

// MappedSeverity maps the event's SeverityName to the internal 1-5 scale.
//
// A missing SeverityName key defaults to "Critical" (5) and any unrecognized
// value also defaults to 5.
func (e *Event) MappedSeverity() int {
	name, ok := e.stringField("SeverityName")
	if !ok {
		// A missing key defaults to "Critical" -> 5.
		return 5
	}
	if v, found := severityByName[name]; found {
		return v
	}
	// Unknown value -> 5 (highest).
	return 5
}

// SensorID returns the sensor identifier, preferring SensorId then AgentId.
// Port of Event.sensor_id. Returns "" when neither is present.
func (e *Event) SensorID() string {
	if v, ok := e.stringField("SensorId"); ok {
		return v
	}
	v, _ := e.stringField("AgentId")
	return v
}

// ComputerName returns the host name, preferring ComputerName then Hostname.
// Port of Event.computer_name. Returns "" when neither is present.
func (e *Event) ComputerName() string {
	if v, ok := e.stringField("ComputerName"); ok {
		return v
	}
	v, _ := e.stringField("Hostname")
	return v
}

// EventID returns the detection or audit identifier, preferring the detection
// key DetectId and falling back to the audit key CompositeId. Port of
// FalconEvent.event_id. Returns "" when neither is present.
func (e *Event) EventID() string {
	if v, ok := e.stringField("DetectId"); ok {
		return v
	}
	v, _ := e.stringField("CompositeId")
	return v
}

// FalconLink returns the Falcon console link for the event (FalconHostLink).
func (e *Event) FalconLink() string {
	v, _ := e.stringField("FalconHostLink")
	return v
}

// CID returns the customer ID from metadata (metadata.customerIDString).
func (e *Event) CID() string {
	return e.Metadata.CustomerIDString
}

// SeverityName returns the textual severity (e.g. "High"), or "" when absent.
func (e *Event) SeverityName() string {
	v, _ := e.stringField("SeverityName")
	return v
}

// Severity returns the numeric severity from the event, defaulting to 5 (the
// most severe) when the field is absent, matching fig/falcon/models.py:66-68.
func (e *Event) Severity() int {
	if e.Event == nil {
		return 5
	}
	if _, ok := e.Event["Severity"]; !ok {
		return 5
	}
	return e.intField("Severity")
}

// DetectDescription returns the description, preferring the detection key
// DetectDescription and falling back to the audit key Description. Port of
// FalconEvent.detect_description.
func (e *Event) DetectDescription() string {
	if v, ok := e.stringField("DetectDescription"); ok {
		return v
	}
	v, _ := e.stringField("Description")
	return v
}

// DetectName returns the detection or audit name, preferring the detection key
// DetectName and falling back to the audit key Name. Port of
// FalconEvent.detect_name.
func (e *Event) DetectName() string {
	if v, ok := e.stringField("DetectName"); ok {
		return v
	}
	v, _ := e.stringField("Name")
	return v
}

// ServiceName returns the ServiceName field, or "" when absent.
func (e *Event) ServiceName() string {
	v, _ := e.stringField("ServiceName")
	return v
}

// FileName returns the process image file name (FileName), or "" when absent.
func (e *Event) FileName() string {
	v, _ := e.stringField("FileName")
	return v
}

// FilePath returns the process image file path (FilePath), or "" when absent.
func (e *Event) FilePath() string {
	v, _ := e.stringField("FilePath")
	return v
}

// CommandLine returns the process command line (CommandLine), or "" when absent.
func (e *Event) CommandLine() string {
	v, _ := e.stringField("CommandLine")
	return v
}

// IsFilteredOut reports whether the event should be dropped by the two global
// filters: it returns true when the mapped severity is below sevThreshold OR the
// (UTC) creation time is before cutoff. The cutoff is passed in already
// normalized to UTC.
func (e *Event) IsFilteredOut(sevThreshold int, cutoff time.Time) bool {
	if e.MappedSeverity() < sevThreshold {
		return true
	}
	if e.CreationTime().Before(cutoff) {
		return true
	}
	return false
}

// stringField returns the string value of the named key in the inner event
// map. The second result is false when the key is absent or not a string.
func (e *Event) stringField(key string) (string, bool) {
	if e.Event == nil {
		return "", false
	}
	raw, ok := e.Event[key]
	if !ok {
		return "", false
	}
	s, ok := raw.(string)
	if !ok || s == "" {
		return "", false
	}
	return s, true
}

// intField returns the integer value of the named key in the inner event map,
// or 0 when the key is absent or not numeric. Numbers decode as json.Number
// (see ParseLine), which utils.IntFromAny converts without float64 rounding.
func (e *Event) intField(key string) int {
	if e.Event == nil {
		return 0
	}
	return utils.IntFromAny(e.Event[key])
}

// Cutoff returns the age-filter cutoff time: now (UTC) minus olderThanDays.
// Port of Event.cut_off_date (fig/falcon/models.py:87-89), fixed to UTC.
func Cutoff(now time.Time, olderThanDays int) time.Time {
	return now.UTC().AddDate(0, 0, -olderThanDays)
}
