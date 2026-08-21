package gcp

import (
	"testing"
	"time"

	"cloud.google.com/go/securitycenter/apiv1/securitycenterpb"
	"google.golang.org/protobuf/types/known/structpb"
)

// sourceProp returns the string value of a source property, failing the test if
// the key is absent or not a string.
func sourceProp(t *testing.T, props map[string]*structpb.Value, key string) string {
	t.Helper()
	v, ok := props[key]
	if !ok {
		t.Fatalf("source property %q missing", key)
	}
	return v.GetStringValue()
}

func TestBuildFinding(t *testing.T) {
	t.Parallel()

	eventTime := time.Date(2026, 8, 14, 12, 0, 0, 0, time.UTC)
	in := findingInput{
		source:            "organizations/42/sources/fig",
		findingID:         "abc123",
		resourceName:      "//compute.googleapis.com/projects/p/zones/z/instances/i",
		eventID:           "detect-1",
		dedupKey:          "feed1_7",
		computerName:      "host-1",
		detectName:        "SuspiciousActivity",
		detectDescription: "a bad thing happened",
		severityName:      "Informational",
		falconLink:        "https://falcon.example/detects/detect-1",
		instanceID:        "9876543210",
		fileName:          "evil.exe",
		filePath:          `C:\tmp\evil.exe`,
		commandLine:       "evil.exe --do-harm",
		eventTime:         eventTime,
	}

	f := buildFinding(in)

	if got, want := f.GetName(), "organizations/42/sources/fig/findings/abc123"; got != want {
		t.Errorf("Name = %q, want %q", got, want)
	}
	if got, want := f.GetParent(), "organizations/42/sources/fig"; got != want {
		t.Errorf("Parent = %q, want %q", got, want)
	}
	if got := f.GetResourceName(); got != in.resourceName {
		t.Errorf("ResourceName = %q, want %q", got, in.resourceName)
	}
	if got := f.GetState(); got != securitycenterpb.Finding_ACTIVE {
		t.Errorf("State = %v, want ACTIVE", got)
	}
	if got := f.GetExternalUri(); got != in.falconLink {
		t.Errorf("ExternalUri = %q, want %q", got, in.falconLink)
	}
	if got, want := f.GetCategory(), "SuspiciousActivity"; got != want {
		t.Errorf("Category = %q, want %q", got, want)
	}
	// Informational remaps to the SCC LOW severity enum.
	if got := f.GetSeverity(); got != securitycenterpb.Finding_LOW {
		t.Errorf("Severity = %v, want LOW", got)
	}
	if got := f.GetEventTime().AsTime(); !got.Equal(eventTime) {
		t.Errorf("EventTime = %v, want %v", got, eventTime)
	}

	sp := f.GetSourceProperties()
	for _, tc := range []struct{ key, want string }{
		{"FalconEventId", "detect-1"},
		{"FigDeduplicationId", "feed1_7"},
		{"ComputerName", "host-1"},
		{"Description", "a bad thing happened"},
		{"Severity", "LOW"},
		{"Title", "Falcon Alert. Instance 9876543210"},
		{"Category", "SuspiciousActivity"},
	} {
		if got := sourceProp(t, sp, tc.key); got != tc.want {
			t.Errorf("source property %q = %q, want %q", tc.key, got, tc.want)
		}
	}

	pi, ok := sp["ProcessInformation"]
	if !ok {
		t.Fatal("source property ProcessInformation missing")
	}
	proc := pi.GetStructValue().GetFields()
	if proc == nil {
		t.Fatal("ProcessInformation is not a struct value")
	}
	for _, tc := range []struct{ key, want string }{
		{"ProcessName", "evil.exe"},
		{"ProcessPath", `C:\tmp\evil.exe`},
		{"CommandLine", "evil.exe --do-harm"},
	} {
		if got := sourceProp(t, proc, tc.key); got != tc.want {
			t.Errorf("ProcessInformation.%s = %q, want %q", tc.key, got, tc.want)
		}
	}
}

func TestFindingSeverityEnum(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		in   string
		want securitycenterpb.Finding_Severity
	}{
		{name: "critical", in: "Critical", want: securitycenterpb.Finding_CRITICAL},
		{name: "high", in: "High", want: securitycenterpb.Finding_HIGH},
		{name: "medium", in: "Medium", want: securitycenterpb.Finding_MEDIUM},
		{name: "low", in: "Low", want: securitycenterpb.Finding_LOW},
		{name: "informational maps to low", in: "Informational", want: securitycenterpb.Finding_LOW},
		{name: "unknown maps to unspecified", in: "Bogus", want: securitycenterpb.Finding_SEVERITY_UNSPECIFIED},
		{name: "empty maps to unspecified", in: "", want: securitycenterpb.Finding_SEVERITY_UNSPECIFIED},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := findingSeverity(severity(tt.in)); got != tt.want {
				t.Errorf("findingSeverity(severity(%q)) = %v, want %v", tt.in, got, tt.want)
			}
		})
	}
}
