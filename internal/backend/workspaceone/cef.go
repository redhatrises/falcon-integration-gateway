package workspaceone

import (
	"encoding/json"
	"fmt"
	"math"
	"strconv"
	"strings"

	"github.com/crowdstrike/falcon-integration-gateway/internal/events"
)

// cefEventType is the single detection type this backend forwards. It doubles
// as the server-side stream filter via RelevantEventTypes.
const cefEventType = events.EppDetectionSummaryEventType

// cefHeaderPrefix is the fixed CEF header. Severity is hardcoded to 2 (there is
// no severity mapping); the trailing pipe opens the extension section.
const cefHeaderPrefix = "CEF:0|CrowdStrike|FalconHost|1.0|EppDetectionSummaryEvent|EPP Detection Summary Event|2|"

// cefInput carries the values buildCEF needs. token and udid are resolved by
// the caller (udid from the MDM identifier lookup). eventID is the real Falcon
// detection/audit id (see events.Event.EventID), emitted as FalconEventId;
// Falcon re-emits events under the same id at new offsets, so it is not unique
// per record. dedupKey is a deterministic, retry-stable event identifier (see
// events.Event.DedupKey), emitted as FigDeduplicationId so a downstream consumer
// can collapse a crash-restart redelivery; syslog does not de-duplicate on
// ingest, so duplicates still arrive and become removable, not absorbed.
type cefInput struct {
	ev       *events.Event
	token    string
	udid     string
	eventID  string
	dedupKey string
}

// buildCEF renders a Workspace ONE CEF record from a detection event: an
// event-map key is emitted only when present (bare key presence, so a
// present-but-empty string is still emitted), values are never escaped, and the
// field order is preserved exactly. The receiver relies on this exact framing,
// so the order and no-escaping behavior must not change. The metadata fields
// (cs4/cs1/cn3/rt) are always emitted: the identity fields are always populated
// and the typed metadata is always present on the wire.
func buildCEF(in cefInput) string {
	var b strings.Builder
	b.WriteString(cefHeaderPrefix)
	b.WriteString("Token=")
	b.WriteString(in.token)
	b.WriteString(" UDID=")
	b.WriteString(in.udid)

	var m map[string]any
	if in.ev != nil {
		m = in.ev.Event
	}

	// field appends " key=" + cefValue(value) when key is present in the raw
	// map. A JSON null (nil value) is skipped: a bare "None"/"<nil>" is never
	// emitted here (a null string field raised and dropped the whole event;
	// nulls do not occur for these keys in real streams), so omitting the field
	// is the faithful, non-corrupting behavior.
	field := func(cefKey, rawKey string) bool {
		v, ok := m[rawKey]
		if !ok || v == nil {
			return false
		}
		b.WriteString(" ")
		b.WriteString(cefKey)
		b.WriteString("=")
		b.WriteString(cefValue(v))
		return true
	}

	field("externalId", "SensorId")
	if field("cn2", "ProcessId") {
		b.WriteString(" cn2Label=ProcessId")
	}
	if field("cn1", "ParentProcessId") {
		b.WriteString(" cn1Label=ParentProcessId")
	}
	field("suser", "UserName")
	field("msg", "DetectDescription")
	field("fname", "FileName")
	field("filePath", "FilePath")
	if field("cs5", "CommandLine") {
		b.WriteString(" cs5Label=CommandLine")
	}
	field("fileHash", "MD5String")
	field("sntdom", "MachineDomain")
	if field("cs6", "FalconHostLink") {
		b.WriteString(" cs6Label=FalconHostLink")
	}

	// FalconEventId is the real detection id and FigDeduplicationId the dedup key;
	// both are always populated, so cs4 and cs1 are emitted unconditionally. The
	// detection id (DetectId/CompositeId) and the <feedID>_<offset> UID are both
	// safe CEF-extension charsets that need no escaping.
	b.WriteString(" cs4=")
	b.WriteString(in.eventID)
	b.WriteString(" cs4Label=FalconEventId")
	b.WriteString(" cs1=")
	b.WriteString(in.dedupKey)
	b.WriteString(" cs1Label=FigDeduplicationId")

	// Metadata is typed and always present, so cn3/rt are emitted unconditionally.
	if in.ev != nil {
		b.WriteString(" cn3=")
		b.WriteString(strconv.FormatUint(in.ev.Metadata.Offset, 10))
		b.WriteString(" cn3Label=Offset")
		b.WriteString(" rt=")
		b.WriteString(strconv.FormatInt(in.ev.Metadata.EventCreationTime, 10))
	}

	field("src", "LocalIP")
	field("smac", "MACAddress")
	field("cat", "Tactic")
	field("act", "Technique")
	field("reason", "Objective")
	field("outcome", "PatternDispositionValue")
	field("CSMTRPatternDisposition", "PatternDispositionDescription")

	return b.String()
}

// cefValue renders a raw JSON value as its CEF extension string. Numbers in the
// event map decode as json.Number (see events.ParseLine); rendering its exact
// text preserves integer identifiers (ProcessId, ParentProcessId,
// PatternDispositionValue) beyond float64's 2^53 precision. The float64 case
// remains for any value not sourced from that decode path, rendering a
// whole-valued float without a decimal point to match the wire format.
func cefValue(v any) string {
	switch x := v.(type) {
	case string:
		return x
	case json.Number:
		return x.String()
	case float64:
		if !math.IsInf(x, 0) && !math.IsNaN(x) && x == math.Trunc(x) {
			return strconv.FormatInt(int64(x), 10)
		}
		return strconv.FormatFloat(x, 'f', -1, 64)
	default:
		return fmt.Sprint(x)
	}
}
