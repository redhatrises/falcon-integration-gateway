// Package events defines the raw Falcon Event Streams event and the pure,
// config-independent accessors, severity mapping, and filters over it.
//
// This is a port of fig/falcon/models.py (the Event class). It intentionally
// imports NO other FIG package (in particular not config): filtering thresholds
// are passed in by the caller so the model stays pure and testable.
package events

import (
	"encoding/json"
	"strconv"
	"time"
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

// Metadata is the "metadata" object of a stream event line.
type Metadata struct {
	EventType         string `json:"eventType"`
	Offset            uint64 `json:"offset"`
	EventCreationTime int64  `json:"eventCreationTime"`
	CustomerIDString  string `json:"customerIDString"`
}

// Event is one decoded line from the Falcon Event Streams data feed.
//
// FeedID is the stream partition/feed identifier parsed from the datafeed URL
// (Python parses it with the regex [0-9a-zA-Z]+, so it is a string, not an
// int). Raw holds a copy of the original line for backends that forward the
// verbatim JSON (e.g. GENERIC).
type Event struct {
	Metadata Metadata       `json:"metadata"`
	Event    map[string]any `json:"event"`
	FeedID   string         `json:"-"`
	Raw      []byte         `json:"-"`
}

// ParseLine decodes a single newline-delimited stream line into an Event,
// tagging it with feedID and storing a defensive copy of the raw bytes.
func ParseLine(line []byte, feedID string) (*Event, error) {
	var ev Event
	if err := json.Unmarshal(line, &ev); err != nil {
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

// CreationTime returns the event creation time as a UTC time.Time.
//
// The Python code (fig/falcon/models.py:84-85) used naive local timestamps in
// the age filter, causing a timezone bug; this always returns UTC. The stream
// timestamp is epoch milliseconds.
func (e *Event) CreationTime() time.Time {
	return time.UnixMilli(e.Metadata.EventCreationTime).UTC()
}

// MappedSeverity maps the event's SeverityName to the internal 1-5 scale.
//
// Port of fig/falcon/models.py:42-52: a missing SeverityName key defaults to
// "Critical" (5) and any unrecognized value also defaults to 5.
func (e *Event) MappedSeverity() int {
	name, ok := e.stringField("SeverityName")
	if !ok {
		// Python defaults a missing key to "Critical" -> 5.
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

// IsFilteredOut reports whether the event should be dropped by the two global
// filters. Port of Event.irrelevant() (fig/falcon/models.py:19-40): true when
// the mapped severity is below sevThreshold OR the (UTC) creation time is
// before cutoff. The cutoff is passed in already normalized to UTC.
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

// Cutoff returns the age-filter cutoff time: now (UTC) minus olderThanDays.
// Port of Event.cut_off_date (fig/falcon/models.py:87-89), fixed to UTC.
func Cutoff(now time.Time, olderThanDays int) time.Time {
	return now.UTC().AddDate(0, 0, -olderThanDays)
}
