package offset

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	ssmtypes "github.com/aws/aws-sdk-go-v2/service/ssm/types"
)

// ssmAPI is the subset of the AWS SSM client the offset store needs. Declaring
// it here, next to the consumer, lets tests inject a fake without a live SSM
// endpoint.
type ssmAPI interface {
	GetParameter(ctx context.Context, in *ssm.GetParameterInput, optFns ...func(*ssm.Options)) (*ssm.GetParameterOutput, error)
	PutParameter(ctx context.Context, in *ssm.PutParameterInput, optFns ...func(*ssm.Options)) (*ssm.PutParameterOutput, error)
}

// SSM is a durable Store backed by a single AWS Systems Manager parameter. It
// persists a JSON object mapping feed_id -> offset, so resume offsets survive a
// process restart without a shared filesystem — useful for stateless container
// deployments where File's disk would not persist.
//
// Writes mirror File: an embedded BufferedStore updates in-memory state
// immediately but persists to SSM at most once per DefaultFlushInterval
// (coalesced to stay under the PutParameter throttling limits), with a
// guaranteed final flush on Close.
type SSM struct {
	client    ssmAPI
	parameter string
	buf       *BufferedStore
}

// NewSSM constructs an SSM-backed Store persisting to the named parameter. The
// AWS config is resolved from the ambient credential/region chain
// (env/instance-profile/IRSA); region overrides it when non-empty. Existing
// parameter contents are hydrated into memory; an absent parameter is treated
// as an empty store (not an error).
func NewSSM(ctx context.Context, region, parameter string) (*SSM, error) {
	var opts []func(*awsconfig.LoadOptions) error
	if region != "" {
		opts = append(opts, awsconfig.WithRegion(region))
	}
	awsCfg, err := awsconfig.LoadDefaultConfig(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("offset: loading aws config: %w", err)
	}
	return newSSMStore(ctx, ssm.NewFromConfig(awsCfg), parameter)
}

// newSSMStore builds the store around an injected client and hydrates it from
// the parameter's current value. It is the testable seam behind NewSSM.
func newSSMStore(ctx context.Context, client ssmAPI, parameter string) (*SSM, error) {
	if parameter == "" {
		return nil, fmt.Errorf("offset: ssm parameter name must not be empty")
	}

	offsets := make(map[string]uint64)

	out, err := client.GetParameter(ctx, &ssm.GetParameterInput{Name: aws.String(parameter)})
	var notFound *ssmtypes.ParameterNotFound
	switch {
	case errors.As(err, &notFound):
		// Missing parameter => empty store; the first Commit creates it.
	case err != nil:
		return nil, fmt.Errorf("offset: reading ssm parameter %q: %w", parameter, err)
	case out.Parameter != nil && aws.ToString(out.Parameter.Value) != "":
		if err := json.Unmarshal([]byte(aws.ToString(out.Parameter.Value)), &offsets); err != nil {
			return nil, fmt.Errorf("offset: parsing ssm parameter %q: %w", parameter, err)
		}
	}

	s := &SSM{
		client:    client,
		parameter: parameter,
	}
	s.buf = NewBufferedStore(BufferedStoreConfig{
		Initial:  offsets,
		Interval: DefaultFlushInterval,
		Persist:  s.persist,
	})
	return s, nil
}

// Load returns the current in-memory offset for feedID (hydrated from SSM on
// construction), or 0 when absent.
func (s *SSM) Load(_ context.Context, feedID string) (uint64, error) {
	return s.buf.Load(feedID), nil
}

// Commit advances feedID's offset in memory and persists to SSM if the flush
// window has elapsed. Otherwise the value is retained and flushed by a later
// Commit or by Close.
//
// The stored offset is monotonic: a commit at or below the current value is a
// no-op. The watermark is a resume floor, and moving it backward would replay
// or re-deliver events that were already handled, so a stale or out-of-order
// commit must never regress it.
func (s *SSM) Commit(ctx context.Context, feedID string, offset uint64) error {
	return s.buf.Commit(ctx, feedID, offset)
}

// Close flushes any pending state to SSM and marks the store closed. It is safe
// to call once; subsequent Commits return an error.
func (s *SSM) Close(ctx context.Context) error {
	return s.buf.Close(ctx)
}

// persist writes offsets to the SSM parameter, overwriting the prior value. The
// BufferedStore invokes it serially under its lock, so it needs no additional
// synchronization.
func (s *SSM) persist(ctx context.Context, offsets map[string]uint64) error {
	data, err := marshalOffsets(offsets)
	if err != nil {
		return err
	}

	_, err = s.client.PutParameter(ctx, &ssm.PutParameterInput{
		Name:      aws.String(s.parameter),
		Value:     aws.String(string(data)),
		Type:      ssmtypes.ParameterTypeString,
		Overwrite: aws.Bool(true),
	})
	if err != nil {
		return fmt.Errorf("offset: writing ssm parameter %q: %w", s.parameter, err)
	}
	return nil
}
