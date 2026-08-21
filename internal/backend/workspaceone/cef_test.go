package workspaceone

import (
	"encoding/json"
	"testing"

	"github.com/crowdstrike/falcon-integration-gateway/internal/events"
)

const cefHeader = "CEF:0|CrowdStrike|FalconHost|1.0|EppDetectionSummaryEvent|EPP Detection Summary Event|2|"

func TestBuildCEF(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		in   cefInput
		want string
	}{
		{
			name: "full event emits every field in source order",
			in: cefInput{
				token:    "tok-abc",
				udid:     "UDID-1",
				eventID:  "ldt:abc:1",
				dedupKey: "feed1_42",
				ev: &events.Event{
					Metadata: events.Metadata{Offset: 42, EventCreationTime: 1600000000000},
					Event: map[string]any{
						"SensorId":                      "sensor-1",
						"ProcessId":                     float64(12345),
						"ParentProcessId":               float64(6789),
						"UserName":                      "alice",
						"DetectDescription":             "bad thing",
						"FileName":                      "evil.exe",
						"FilePath":                      `C:\tmp`,
						"CommandLine":                   "evil.exe --run",
						"MD5String":                     "abc123",
						"MachineDomain":                 "CORP",
						"FalconHostLink":                "https://falcon/x",
						"LocalIP":                       "10.0.0.1",
						"MACAddress":                    "00:11:22",
						"Tactic":                        "Execution",
						"Technique":                     "T1059",
						"Objective":                     "Falcon Detection",
						"PatternDispositionValue":       float64(2304),
						"PatternDispositionDescription": "Prevention, process blocked.",
					},
				},
			},
			want: cefHeader +
				"Token=tok-abc UDID=UDID-1" +
				" externalId=sensor-1" +
				" cn2=12345 cn2Label=ProcessId" +
				" cn1=6789 cn1Label=ParentProcessId" +
				" suser=alice" +
				" msg=bad thing" +
				" fname=evil.exe" +
				` filePath=C:\tmp` +
				" cs5=evil.exe --run cs5Label=CommandLine" +
				" fileHash=abc123" +
				" sntdom=CORP" +
				" cs6=https://falcon/x cs6Label=FalconHostLink" +
				" cs4=ldt:abc:1 cs4Label=FalconEventId" +
				" cs1=feed1_42 cs1Label=FigDeduplicationId" +
				" cn3=42 cn3Label=Offset" +
				" rt=1600000000000" +
				" src=10.0.0.1" +
				" smac=00:11:22" +
				" cat=Execution" +
				" act=T1059" +
				" reason=Falcon Detection" +
				" outcome=2304" +
				" CSMTRPatternDisposition=Prevention, process blocked.",
		},
		{
			name: "sparse event omits absent keys but always emits metadata fields",
			in: cefInput{
				token:    "t",
				udid:     "u",
				eventID:  "",
				dedupKey: "feed1_0",
				ev: &events.Event{
					Metadata: events.Metadata{Offset: 0, EventCreationTime: 0},
					Event: map[string]any{
						"SensorId": "sensor-1",
					},
				},
			},
			want: cefHeader +
				"Token=t UDID=u" +
				" externalId=sensor-1" +
				" cs4= cs4Label=FalconEventId" +
				" cs1=feed1_0 cs1Label=FigDeduplicationId" +
				" cn3=0 cn3Label=Offset" +
				" rt=0",
		},
		{
			name: "present-but-empty string is emitted (raw-map presence semantics)",
			in: cefInput{
				token:    "t",
				udid:     "u",
				eventID:  "ldt:abc:7",
				dedupKey: "feed1_7",
				ev: &events.Event{
					Metadata: events.Metadata{Offset: 7, EventCreationTime: 9},
					Event: map[string]any{
						"UserName": "",
					},
				},
			},
			want: cefHeader +
				"Token=t UDID=u" +
				" suser=" +
				" cs4=ldt:abc:7 cs4Label=FalconEventId" +
				" cs1=feed1_7 cs1Label=FigDeduplicationId" +
				" cn3=7 cn3Label=Offset" +
				" rt=9",
		},
		{
			name: "null-valued keys are omitted, not rendered as <nil>",
			in: cefInput{
				token:    "t",
				udid:     "u",
				eventID:  "ldt:abc:3",
				dedupKey: "feed1_3",
				ev: &events.Event{
					Metadata: events.Metadata{Offset: 3, EventCreationTime: 4},
					Event: map[string]any{
						"SensorId":  "sensor-1",
						"ProcessId": nil,
						"UserName":  "alice",
						"Tactic":    nil,
					},
				},
			},
			want: cefHeader +
				"Token=t UDID=u" +
				" externalId=sensor-1" +
				" suser=alice" +
				" cs4=ldt:abc:3 cs4Label=FalconEventId" +
				" cs1=feed1_3 cs1Label=FigDeduplicationId" +
				" cn3=3 cn3Label=Offset" +
				" rt=4",
		},
		{
			name: "no event map still emits header and metadata",
			in: cefInput{
				token:    "t",
				udid:     "u",
				eventID:  "ldt:abc:1",
				dedupKey: "feed1_1",
				ev: &events.Event{
					Metadata: events.Metadata{Offset: 1, EventCreationTime: 2},
				},
			},
			want: cefHeader +
				"Token=t UDID=u" +
				" cs4=ldt:abc:1 cs4Label=FalconEventId" +
				" cs1=feed1_1 cs1Label=FigDeduplicationId" +
				" cn3=1 cn3Label=Offset" +
				" rt=2",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := buildCEF(tt.in)
			if got != tt.want {
				t.Errorf("buildCEF() mismatch\n got: %q\nwant: %q", got, tt.want)
			}
		})
	}
}

func TestCEFValue(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		in   any
		want string
	}{
		{"string passthrough", "hello", "hello"},
		{"empty string", "", ""},
		{"whole float renders as integer", float64(12345), "12345"},
		{"zero float", float64(0), "0"},
		{"fractional float keeps decimals", float64(12.5), "12.5"},
		{"large whole float", float64(4294967296), "4294967296"},
		{"integer fallback", 42, "42"},
		{"json.Number integer", json.Number("12345"), "12345"},
		{"json.Number beyond float64 precision", json.Number("9007199254740993"), "9007199254740993"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := cefValue(tt.in); got != tt.want {
				t.Errorf("cefValue(%v) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}
