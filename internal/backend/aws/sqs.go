package aws

import (
	"context"
	"fmt"
	"log/slog"
	"strings"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
	sqstypes "github.com/aws/aws-sdk-go-v2/service/sqs/types"

	"github.com/crowdstrike/falcon-integration-gateway/internal/backend"
	"github.com/crowdstrike/falcon-integration-gateway/internal/config"
	"github.com/crowdstrike/falcon-integration-gateway/internal/events"
)

// sqsAPI is the subset of the SQS client the backend needs. Declaring it here,
// on the consumer side, lets tests inject a fake without a live queue.
type sqsAPI interface {
	GetQueueUrl(ctx context.Context, in *sqs.GetQueueUrlInput, optFns ...func(*sqs.Options)) (*sqs.GetQueueUrlOutput, error)
	SendMessage(ctx context.Context, in *sqs.SendMessageInput, optFns ...func(*sqs.Options)) (*sqs.SendMessageOutput, error)
}

// sqsRuntime forwards the verbatim event JSON to an SQS queue.
type sqsRuntime struct {
	logger   *slog.Logger
	client   sqsAPI
	queueURL string
	isFIFO   bool
	appID    string
}

// sqsRuntimeConfig carries the inputs newSQSRuntime needs so the queue-URL
// resolution stays behind a testable seam.
type sqsRuntimeConfig struct {
	client    sqsAPI
	queueName string
	appID     string
	logger    *slog.Logger
}

// newSQSRuntime resolves the queue URL once (fail-fast on a missing queue) and
// records whether the queue is FIFO, which is derived from the ".fifo" name
// suffix and governs whether messages carry group and dedup identifiers.
func newSQSRuntime(ctx context.Context, in sqsRuntimeConfig) (*sqsRuntime, error) {
	out, err := in.client.GetQueueUrl(ctx, &sqs.GetQueueUrlInput{QueueName: awssdk.String(in.queueName)})
	if err != nil {
		return nil, fmt.Errorf("aws sqs: resolving queue url for %q: %w", in.queueName, err)
	}
	return &sqsRuntime{
		logger:   in.logger,
		client:   in.client,
		queueURL: awssdk.ToString(out.QueueUrl),
		isFIFO:   strings.HasSuffix(in.queueName, ".fifo"),
		appID:    in.appID,
	}, nil
}

// newSQS is the backend.Constructor. It builds the real SQS client from the
// ambient AWS config and resolves the queue URL at startup. The one-time
// resolution uses a background context because the constructor signature has no
// context to thread.
func newSQS(cfg *config.Config, logger *slog.Logger) (backend.Backend, error) {
	ctx := context.Background()
	awsCfg, err := loadConfig(ctx, cfg.AWSSQS.Region)
	if err != nil {
		return nil, err
	}
	rt, err := newSQSRuntime(ctx, sqsRuntimeConfig{
		client:    sqs.NewFromConfig(awsCfg),
		queueName: cfg.AWSSQS.SQSQueueName,
		appID:     cfg.Falcon.ApplicationID,
		logger:    logger,
	})
	if err != nil {
		return nil, err
	}
	logger.Info("AWS SQS Backend is enabled.", "queue", cfg.AWSSQS.SQSQueueName, "fifo", rt.isFIFO)
	return rt, nil
}

// Name returns the backend registry name.
func (r *sqsRuntime) Name() string {
	return "AWS_SQS"
}

// RelevantEventTypes accepts every event type.
func (r *sqsRuntime) RelevantEventTypes() []string {
	return backend.AllEventTypes
}

// IsRelevant always returns true; SQS forwards every event.
func (r *sqsRuntime) IsRelevant(_ context.Context, _ *events.EnrichedEvent) bool {
	return true
}

// sqsDedupAttribute is the message attribute name carrying the deterministic,
// retry-stable dedup key. It is set on every message. A standard queue does not
// de-duplicate on ingest, so a crash-restart redelivery still lands a duplicate
// message; a consumer collapses duplicates by this attribute. True sink-side
// de-duplication requires a FIFO queue (see MessageDeduplicationId below).
const sqsDedupAttribute = "FigDeduplicationId"

// Process sends the verbatim original event JSON as the message body. Every
// message carries a FigDeduplicationId attribute holding a retry-stable dedup
// key. For a FIFO queue it also sets the group id ("fig/{app_id}/{feed_id}")
// and uses that same dedup key as the native deduplication id; standard queues
// carry neither of those.
func (r *sqsRuntime) Process(ctx context.Context, ev *events.EnrichedEvent) error {
	in := &sqs.SendMessageInput{
		QueueUrl:    awssdk.String(r.queueURL),
		MessageBody: awssdk.String(string(ev.Raw)),
		MessageAttributes: map[string]sqstypes.MessageAttributeValue{
			sqsDedupAttribute: {
				DataType:    awssdk.String("String"),
				StringValue: awssdk.String(ev.DedupKey()),
			},
		},
	}
	if r.isFIFO {
		// Default a missing feed id to "0" so the group id is always
		// well-formed rather than ending in an empty segment.
		feedID := ev.FeedID
		if feedID == "" {
			feedID = "0"
		}
		in.MessageGroupId = awssdk.String(fmt.Sprintf("fig/%s/%s", r.appID, feedID))
		// A FIFO queue de-duplicates queue-wide by default, so the id must be
		// unique across feeds; the dedup key (feed-qualified) is, whereas a bare
		// per-feed offset would collide between feeds.
		in.MessageDeduplicationId = awssdk.String(ev.DedupKey())
	}
	if _, err := r.client.SendMessage(ctx, in); err != nil {
		return fmt.Errorf("aws sqs: sending message: %w", err)
	}
	return nil
}

func init() {
	backend.Register("AWS_SQS", newSQS)
}
