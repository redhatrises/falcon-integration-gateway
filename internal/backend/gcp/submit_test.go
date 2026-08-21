package gcp

import (
	"context"
	"errors"
	"testing"

	"cloud.google.com/go/securitycenter/apiv1/securitycenterpb"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// fakeFindingClient drives submit tests via injectable existence/create behavior.
type fakeFindingClient struct {
	existsFn    func() (bool, error)
	createFn    func() error
	existsCalls int
	createCalls int
}

func (f *fakeFindingClient) findingExists(_ context.Context, _, _ string) (bool, error) {
	f.existsCalls++
	return f.existsFn()
}

func (f *fakeFindingClient) createFinding(_ context.Context, _ findingCreateInput) error {
	f.createCalls++
	return f.createFn()
}

func newSubmitter(client findingClient) *findingSubmitter {
	return &findingSubmitter{client: client}
}

func submitInput() submitFindingInput {
	return submitFindingInput{
		source:    "organizations/42/sources/fig",
		findingID: "abc123",
		finding:   &securitycenterpb.Finding{Name: "organizations/42/sources/fig/findings/abc123"},
	}
}

func TestFindingSubmitterSubmit(t *testing.T) {
	t.Parallel()

	t.Run("second submit re-checks the server", func(t *testing.T) {
		t.Parallel()
		exists := []bool{false, true}
		i := 0
		fc := &fakeFindingClient{
			existsFn: func() (bool, error) { v := exists[i]; i++; return v, nil },
			createFn: func() error { return nil },
		}
		s := newSubmitter(fc)

		if err := s.submit(context.Background(), submitInput()); err != nil {
			t.Fatalf("submit: unexpected error %v", err)
		}
		if fc.existsCalls != 1 || fc.createCalls != 1 {
			t.Errorf("after first submit existsCalls=%d createCalls=%d, want 1 and 1", fc.existsCalls, fc.createCalls)
		}

		if err := s.submit(context.Background(), submitInput()); err != nil {
			t.Fatalf("second submit: unexpected error %v", err)
		}
		if fc.existsCalls != 2 || fc.createCalls != 1 {
			t.Errorf("after second submit existsCalls=%d createCalls=%d, want 2 and 1", fc.existsCalls, fc.createCalls)
		}
	})

	t.Run("existing finding on server skips create", func(t *testing.T) {
		t.Parallel()
		fc := &fakeFindingClient{
			existsFn: func() (bool, error) { return true, nil },
			createFn: func() error { t.Fatal("createFinding must not be called"); return nil },
		}
		s := newSubmitter(fc)

		if err := s.submit(context.Background(), submitInput()); err != nil {
			t.Fatalf("submit: unexpected error %v", err)
		}
		if fc.createCalls != 0 {
			t.Errorf("createCalls = %d, want 0", fc.createCalls)
		}
	})

	t.Run("AlreadyExists on create then found is success", func(t *testing.T) {
		t.Parallel()
		exists := []bool{false, true}
		i := 0
		fc := &fakeFindingClient{
			existsFn: func() (bool, error) { v := exists[i]; i++; return v, nil },
			createFn: func() error { return status.Error(codes.AlreadyExists, "dup") },
		}
		s := newSubmitter(fc)

		if err := s.submit(context.Background(), submitInput()); err != nil {
			t.Fatalf("submit: unexpected error %v", err)
		}
		if fc.existsCalls != 2 || fc.createCalls != 1 {
			t.Errorf("existsCalls=%d createCalls=%d, want 2 and 1", fc.existsCalls, fc.createCalls)
		}
	})

	t.Run("AlreadyExists but still missing on recheck returns the error", func(t *testing.T) {
		t.Parallel()
		alreadyExists := status.Error(codes.AlreadyExists, "dup")
		fc := &fakeFindingClient{
			existsFn: func() (bool, error) { return false, nil },
			createFn: func() error { return alreadyExists },
		}
		s := newSubmitter(fc)

		if err := s.submit(context.Background(), submitInput()); !errors.Is(err, alreadyExists) {
			t.Fatalf("submit error = %v, want the AlreadyExists error", err)
		}
	})

	t.Run("non-AlreadyExists create error propagates", func(t *testing.T) {
		t.Parallel()
		boom := errors.New("boom")
		fc := &fakeFindingClient{
			existsFn: func() (bool, error) { return false, nil },
			createFn: func() error { return boom },
		}
		s := newSubmitter(fc)

		if err := s.submit(context.Background(), submitInput()); !errors.Is(err, boom) {
			t.Fatalf("submit error = %v, want boom", err)
		}
	})

	t.Run("findingExists error propagates", func(t *testing.T) {
		t.Parallel()
		boom := errors.New("lookup boom")
		fc := &fakeFindingClient{
			existsFn: func() (bool, error) { return false, boom },
			createFn: func() error { t.Fatal("createFinding must not be called"); return nil },
		}
		s := newSubmitter(fc)

		if err := s.submit(context.Background(), submitInput()); !errors.Is(err, boom) {
			t.Fatalf("submit error = %v, want lookup boom", err)
		}
	})
}
