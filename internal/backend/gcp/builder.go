package gcp

import (
	"time"

	"cloud.google.com/go/securitycenter/apiv1/securitycenterpb"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// findingsPathSegment joins a Source resource name to a finding id to form the
// full Finding resource name.
const findingsPathSegment = "/findings/"

// findingInput carries the already-resolved values needed to construct one SCC
// Finding. Resolution (host details, org/source walk, asset lookup, id and
// severity derivation) happens in the caller so this builder stays a pure,
// context-free transform that is trivial to test.
type findingInput struct {
	source            string
	findingID         string
	resourceName      string
	eventID           string
	dedupKey          string
	computerName      string
	detectName        string
	detectDescription string
	severityName      string
	falconLink        string
	instanceID        string
	fileName          string
	filePath          string
	commandLine       string
	eventTime         time.Time
}

// buildFinding assembles the SCC Finding for one detection event. The Finding is
// ACTIVE, parented to the FIG Source, carries the console link and detection
// category, and repeats the detection detail under source_properties (including
// a nested ProcessInformation struct).
func buildFinding(in findingInput) *securitycenterpb.Finding {
	sev := severity(in.severityName)
	return &securitycenterpb.Finding{
		Name:         in.source + findingsPathSegment + in.findingID,
		Parent:       in.source,
		ResourceName: in.resourceName,
		State:        securitycenterpb.Finding_ACTIVE,
		ExternalUri:  in.falconLink,
		EventTime:    timestamppb.New(in.eventTime),
		Category:     in.detectName,
		Severity:     findingSeverity(sev),
		SourceProperties: map[string]*structpb.Value{
			"FalconEventId":      structpb.NewStringValue(in.eventID),
			"FigDeduplicationId": structpb.NewStringValue(in.dedupKey),
			"ComputerName":       structpb.NewStringValue(in.computerName),
			"Description":        structpb.NewStringValue(in.detectDescription),
			"Severity":           structpb.NewStringValue(sev),
			"Title":              structpb.NewStringValue("Falcon Alert. Instance " + in.instanceID),
			"Category":           structpb.NewStringValue(in.detectName),
			"ProcessInformation": structpb.NewStructValue(&structpb.Struct{
				Fields: map[string]*structpb.Value{
					"ProcessName": structpb.NewStringValue(in.fileName),
					"ProcessPath": structpb.NewStringValue(in.filePath),
					"CommandLine": structpb.NewStringValue(in.commandLine),
				},
			}),
		},
	}
}

// findingSeverity maps an already-normalized severity string (uppercased, with
// INFORMATIONAL folded to LOW by severity()) to the SCC severity enum. An
// unrecognized or empty value yields SEVERITY_UNSPECIFIED.
func findingSeverity(normalized string) securitycenterpb.Finding_Severity {
	if v, ok := securitycenterpb.Finding_Severity_value[normalized]; ok {
		return securitycenterpb.Finding_Severity(v)
	}
	return securitycenterpb.Finding_SEVERITY_UNSPECIFIED
}
