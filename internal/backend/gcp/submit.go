package gcp

import (
	"context"

	"cloud.google.com/go/securitycenter/apiv1/securitycenterpb"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// findingCreateInput carries the arguments for creating one SCC Finding under a
// Source. It is declared here so the seam and its callers share one shape.
type findingCreateInput struct {
	source    string
	findingID string
	finding   *securitycenterpb.Finding
}

// findingClient is the seam over the SCC Finding API. findingExists reports
// whether a finding with findingName already exists under the source; it lets
// the submitter skip creation and recover from a concurrent create. createFinding
// creates the finding and surfaces the raw gRPC error so AlreadyExists can be
// classified. Keeping the seam this small lets tests inject fakes without a live
// SCC endpoint.
type findingClient interface {
	findingExists(ctx context.Context, source, findingName string) (bool, error)
	createFinding(ctx context.Context, input findingCreateInput) error
}

// submitFindingInput is an alias retained for readability at the call site:
// submitting a finding needs exactly the same values as creating one — the
// Source it belongs to, its dedup id, and the payload.
type submitFindingInput = findingCreateInput

// findingSubmitter creates SCC findings, deduplicating against the server.
// getOrCreate checks whether the finding already exists before creating it, and
// an AlreadyExists on create is reconciled by re-checking the server so
// concurrent submits and cross-run duplicates succeed.
type findingSubmitter struct {
	client findingClient
}

// submit creates the finding unless it already exists on the server. AlreadyExists
// on create is treated as success once a follow-up existence check confirms the
// finding; any other error is returned so the caller's delivery-failure policy
// governs.
func (s *findingSubmitter) submit(ctx context.Context, in submitFindingInput) error {
	return s.getOrCreate(ctx, in)
}

// getOrCreate ensures the finding exists on the server, creating it if absent and
// treating a concurrent-create AlreadyExists as success when a re-check confirms
// the finding is present.
func (s *findingSubmitter) getOrCreate(ctx context.Context, in submitFindingInput) error {
	exists, err := s.client.findingExists(ctx, in.source, in.finding.GetName())
	if err != nil {
		return err
	}
	if exists {
		return nil
	}

	createErr := s.client.createFinding(ctx, in)
	if createErr == nil {
		return nil
	}
	if status.Code(createErr) != codes.AlreadyExists {
		return createErr
	}

	exists, err = s.client.findingExists(ctx, in.source, in.finding.GetName())
	if err != nil {
		return err
	}
	if !exists {
		return createErr
	}
	return nil
}
