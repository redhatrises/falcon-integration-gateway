package offset

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	ssmtypes "github.com/aws/aws-sdk-go-v2/service/ssm/types"
)

// fakeSSM is an in-memory stand-in for the SSM parameter API. It records the
// last written value per parameter name and counts calls so tests can assert
// hydration, debounced persistence, and the final Close flush without a live
// AWS endpoint.
type fakeSSM struct {
	mu       sync.Mutex
	params   map[string]string
	getErr   error
	putErr   error
	getCalls int
	putCalls int
}

func newFakeSSM() *fakeSSM {
	return &fakeSSM{params: make(map[string]string)}
}

func (f *fakeSSM) GetParameter(_ context.Context, in *ssm.GetParameterInput, _ ...func(*ssm.Options)) (*ssm.GetParameterOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.getCalls++
	if f.getErr != nil {
		return nil, f.getErr
	}
	val, ok := f.params[aws.ToString(in.Name)]
	if !ok {
		return nil, &ssmtypes.ParameterNotFound{}
	}
	return &ssm.GetParameterOutput{Parameter: &ssmtypes.Parameter{Value: aws.String(val)}}, nil
}

func (f *fakeSSM) PutParameter(_ context.Context, in *ssm.PutParameterInput, _ ...func(*ssm.Options)) (*ssm.PutParameterOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.putCalls++
	if f.putErr != nil {
		return nil, f.putErr
	}
	f.params[aws.ToString(in.Name)] = aws.ToString(in.Value)
	return &ssm.PutParameterOutput{}, nil
}

func (f *fakeSSM) stored(name string) (map[string]uint64, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	raw, ok := f.params[name]
	if !ok {
		return nil, false
	}
	m := map[string]uint64{}
	if err := json.Unmarshal([]byte(raw), &m); err != nil {
		return nil, false
	}
	return m, true
}

func (f *fakeSSM) puts() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.putCalls
}

const testSSMParam = "fig/offsets"

func TestSSMHydratesExistingParameter(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	fake := newFakeSSM()
	fake.params[testSSMParam] = `{"feed-a":555,"feed-b":12}`

	s, err := newSSMStore(ctx, fake, testSSMParam)
	if err != nil {
		t.Fatalf("newSSMStore: %v", err)
	}
	defer s.Close(ctx)

	if got, _ := s.Load(ctx, "feed-a"); got != 555 {
		t.Fatalf("Load feed-a = %d, want 555 (hydrated)", got)
	}
	if got, _ := s.Load(ctx, "feed-b"); got != 12 {
		t.Fatalf("Load feed-b = %d, want 12 (hydrated)", got)
	}
}

func TestSSMMissingParameterIsEmptyStore(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	fake := newFakeSSM() // parameter absent
	s, err := newSSMStore(ctx, fake, testSSMParam)
	if err != nil {
		t.Fatalf("newSSMStore with absent parameter should not error: %v", err)
	}
	defer s.Close(ctx)

	if got, _ := s.Load(ctx, "feed-a"); got != 0 {
		t.Fatalf("Load on empty store = %d, want 0", got)
	}
}

func TestSSMGetParameterErrorFailsConstruction(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	sentinel := errors.New("boom")
	fake := newFakeSSM()
	fake.getErr = sentinel

	_, err := newSSMStore(ctx, fake, testSSMParam)
	if err == nil {
		t.Fatal("newSSMStore = nil error, want the GetParameter failure surfaced")
	}
	if !errors.Is(err, sentinel) {
		t.Fatalf("newSSMStore error = %v, want it to wrap the GetParameter failure", err)
	}
}

func TestSSMEmptyParameterNameErrors(t *testing.T) {
	t.Parallel()
	if _, err := newSSMStore(context.Background(), newFakeSSM(), ""); err == nil {
		t.Fatal("newSSMStore with empty parameter name = nil error, want error")
	}
}

func TestSSMCommitPersistsToParameter(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	fake := newFakeSSM()
	s, err := newSSMStore(ctx, fake, testSSMParam)
	if err != nil {
		t.Fatalf("newSSMStore: %v", err)
	}

	if err := s.Commit(ctx, "feed-a", 42); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	// The first commit persists immediately (lastFlush is zero).
	stored, ok := fake.stored(testSSMParam)
	if !ok {
		t.Fatal("parameter not written after first commit")
	}
	if stored["feed-a"] != 42 {
		t.Fatalf("stored feed-a = %d, want 42", stored["feed-a"])
	}
	_ = s.Close(ctx)
}

func TestSSMDebouncedCommitFlushedOnClose(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	fake := newFakeSSM()
	s, err := newSSMStore(ctx, fake, testSSMParam)
	if err != nil {
		t.Fatalf("newSSMStore: %v", err)
	}

	// Two rapid commits: the first persists, the second is debounced within
	// the flush interval and must be flushed by Close.
	if err := s.Commit(ctx, "feed-a", 1); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	if err := s.Commit(ctx, "feed-a", 2); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	if err := s.Close(ctx); err != nil {
		t.Fatalf("Close: %v", err)
	}

	stored, ok := fake.stored(testSSMParam)
	if !ok {
		t.Fatal("parameter never written")
	}
	if stored["feed-a"] != 2 {
		t.Fatalf("debounced value not flushed on Close: got %d, want 2", stored["feed-a"])
	}
}

func TestSSMCleanCloseDoesNotWrite(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	fake := newFakeSSM()
	s, err := newSSMStore(ctx, fake, testSSMParam)
	if err != nil {
		t.Fatalf("newSSMStore: %v", err)
	}
	if err := s.Close(ctx); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if fake.puts() != 0 {
		t.Fatalf("PutParameter calls = %d, want 0 for a store with no commits", fake.puts())
	}
}

func TestSSMCommitAfterCloseErrors(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	fake := newFakeSSM()
	s, err := newSSMStore(ctx, fake, testSSMParam)
	if err != nil {
		t.Fatalf("newSSMStore: %v", err)
	}
	if err := s.Close(ctx); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := s.Commit(ctx, "feed-a", 1); err == nil {
		t.Fatal("Commit after Close = nil error, want error")
	}
}
