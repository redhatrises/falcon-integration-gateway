package aws

import (
	"context"
	"errors"
	"log/slog"
	"testing"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sqs"

	"github.com/crowdstrike/falcon-integration-gateway/internal/backend"
	"github.com/crowdstrike/falcon-integration-gateway/internal/events"
)

// fakeSQS is an in-memory stand-in for the SQS API. It records the SendMessage
// inputs so tests can assert the FIFO/standard message shaping.
type fakeSQS struct {
	queueURL string
	getErr   error
	sendErr  error
	sent     []*sqs.SendMessageInput
}

func (f *fakeSQS) GetQueueUrl(_ context.Context, _ *sqs.GetQueueUrlInput, _ ...func(*sqs.Options)) (*sqs.GetQueueUrlOutput, error) {
	if f.getErr != nil {
		return nil, f.getErr
	}
	return &sqs.GetQueueUrlOutput{QueueUrl: awssdk.String(f.queueURL)}, nil
}

func (f *fakeSQS) SendMessage(_ context.Context, in *sqs.SendMessageInput, _ ...func(*sqs.Options)) (*sqs.SendMessageOutput, error) {
	f.sent = append(f.sent, in)
	if f.sendErr != nil {
		return nil, f.sendErr
	}
	return &sqs.SendMessageOutput{}, nil
}

func newSQSTestRuntime(t *testing.T, fake *fakeSQS, queueName string) *sqsRuntime {
	t.Helper()
	rt, err := newSQSRuntime(context.Background(), sqsRuntimeConfig{
		client:    fake,
		queueName: queueName,
		appID:     "app-1",
		logger:    slog.New(slog.DiscardHandler),
	})
	if err != nil {
		t.Fatalf("newSQSRuntime: %v", err)
	}
	return rt
}

func testEvent() *events.EnrichedEvent {
	return events.NewEnrichedEvent(&events.Event{
		Metadata: events.Metadata{Offset: 42},
		FeedID:   "feed1",
		Raw:      []byte(`{"raw":true}`),
	}, nil)
}

func TestSQSProcessStandardQueue(t *testing.T) {
	t.Parallel()
	fake := &fakeSQS{queueURL: "https://sqs/standard"}
	rt := newSQSTestRuntime(t, fake, "standard")

	if err := rt.Process(context.Background(), testEvent()); err != nil {
		t.Fatalf("Process: %v", err)
	}
	if len(fake.sent) != 1 {
		t.Fatalf("sent %d messages, want 1", len(fake.sent))
	}
	msg := fake.sent[0]
	if awssdk.ToString(msg.MessageBody) != `{"raw":true}` {
		t.Errorf("MessageBody = %q, want raw JSON", awssdk.ToString(msg.MessageBody))
	}
	if awssdk.ToString(msg.QueueUrl) != "https://sqs/standard" {
		t.Errorf("QueueUrl = %q", awssdk.ToString(msg.QueueUrl))
	}
	if msg.MessageGroupId != nil {
		t.Errorf("standard queue set MessageGroupId = %q, want nil", awssdk.ToString(msg.MessageGroupId))
	}
	if msg.MessageDeduplicationId != nil {
		t.Errorf("standard queue set MessageDeduplicationId, want nil")
	}
	if got := dedupAttr(t, msg); got != "feed1_42" {
		t.Errorf("%s attribute = %q, want feed1_42 (dedup key present on standard queue)", sqsDedupAttribute, got)
	}
}

// dedupAttr returns the string value of the FigDeduplicationId message
// attribute, failing the test when it is absent or not a String attribute.
func dedupAttr(t *testing.T, msg *sqs.SendMessageInput) string {
	t.Helper()
	attr, ok := msg.MessageAttributes[sqsDedupAttribute]
	if !ok {
		t.Fatalf("message missing %s attribute", sqsDedupAttribute)
	}
	if awssdk.ToString(attr.DataType) != "String" {
		t.Errorf("%s DataType = %q, want String", sqsDedupAttribute, awssdk.ToString(attr.DataType))
	}
	return awssdk.ToString(attr.StringValue)
}

func TestSQSProcessFIFOQueue(t *testing.T) {
	t.Parallel()
	fake := &fakeSQS{queueURL: "https://sqs/q.fifo"}
	rt := newSQSTestRuntime(t, fake, "q.fifo")

	if err := rt.Process(context.Background(), testEvent()); err != nil {
		t.Fatalf("Process: %v", err)
	}
	msg := fake.sent[0]
	if got := awssdk.ToString(msg.MessageGroupId); got != "fig/app-1/feed1" {
		t.Errorf("MessageGroupId = %q, want fig/app-1/feed1", got)
	}
	if got := awssdk.ToString(msg.MessageDeduplicationId); got != "feed1_42" {
		t.Errorf("MessageDeduplicationId = %q, want feed1_42 (feed-qualified dedup key)", got)
	}
	if got := dedupAttr(t, msg); got != "feed1_42" {
		t.Errorf("%s attribute = %q, want feed1_42 (dedup key present on FIFO queue too)", sqsDedupAttribute, got)
	}
}

// TestSQSProcessDedupKeyIsUID proves the dedup attribute is the feed-qualified
// UID even when an event-intrinsic id (DetectId) is present, so distinct events
// sharing a detection id are not collapsed and the FIFO id never collides
// across feeds.
func TestSQSProcessDedupKeyIsUID(t *testing.T) {
	t.Parallel()
	fake := &fakeSQS{queueURL: "https://sqs/standard"}
	rt := newSQSTestRuntime(t, fake, "standard")

	ev := events.NewEnrichedEvent(&events.Event{
		Metadata: events.Metadata{Offset: 42},
		FeedID:   "feed1",
		Raw:      []byte(`{"raw":true}`),
		Event:    map[string]any{"DetectId": "ldt:abc:1"},
	}, nil)

	if err := rt.Process(context.Background(), ev); err != nil {
		t.Fatalf("Process: %v", err)
	}
	if got := dedupAttr(t, fake.sent[0]); got != "feed1_42" {
		t.Errorf("%s attribute = %q, want feed1_42 (UID, not the DetectId)", sqsDedupAttribute, got)
	}
}

// TestSQSProcessFIFOQueueEmptyFeedID verifies a missing feed id defaults to "0"
// so the FIFO group id is well-formed instead of ending in an empty segment.
func TestSQSProcessFIFOQueueEmptyFeedID(t *testing.T) {
	t.Parallel()
	fake := &fakeSQS{queueURL: "https://sqs/q.fifo"}
	rt := newSQSTestRuntime(t, fake, "q.fifo")

	ev := events.NewEnrichedEvent(&events.Event{
		Metadata: events.Metadata{Offset: 7},
		Raw:      []byte(`{"raw":true}`),
	}, nil) // no FeedID set

	if err := rt.Process(context.Background(), ev); err != nil {
		t.Fatalf("Process: %v", err)
	}
	if got := awssdk.ToString(fake.sent[0].MessageGroupId); got != "fig/app-1/0" {
		t.Errorf("MessageGroupId = %q, want fig/app-1/0 (empty feed id defaults to 0)", got)
	}
}

func TestSQSProcessSendError(t *testing.T) {
	t.Parallel()
	sentinel := errors.New("boom")
	fake := &fakeSQS{queueURL: "https://sqs/standard", sendErr: sentinel}
	rt := newSQSTestRuntime(t, fake, "standard")

	err := rt.Process(context.Background(), testEvent())
	if !errors.Is(err, sentinel) {
		t.Fatalf("Process error = %v, want it to wrap the SendMessage failure", err)
	}
}

func TestNewSQSRuntimeQueueURLError(t *testing.T) {
	t.Parallel()
	sentinel := errors.New("no queue")
	_, err := newSQSRuntime(context.Background(), sqsRuntimeConfig{
		client:    &fakeSQS{getErr: sentinel},
		queueName: "missing",
		logger:    slog.New(slog.DiscardHandler),
	})
	if !errors.Is(err, sentinel) {
		t.Fatalf("error = %v, want it to wrap the GetQueueUrl failure", err)
	}
}

func TestSQSMetadata(t *testing.T) {
	t.Parallel()
	rt := newSQSTestRuntime(t, &fakeSQS{queueURL: "u"}, "standard")
	if rt.Name() != "AWS_SQS" {
		t.Errorf("Name = %q, want AWS_SQS", rt.Name())
	}
	if len(rt.RelevantEventTypes()) != 1 || rt.RelevantEventTypes()[0] != backend.AllEventTypes[0] {
		t.Errorf("RelevantEventTypes = %v, want AllEventTypes", rt.RelevantEventTypes())
	}
	if !rt.IsRelevant(context.Background(), testEvent()) {
		t.Error("IsRelevant = false, want true (SQS accepts all)")
	}
}
