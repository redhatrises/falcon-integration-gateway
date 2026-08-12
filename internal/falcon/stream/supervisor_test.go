package stream

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/crowdstrike/falcon-integration-gateway/internal/testutil"
)

// recordingStore is an offsetStore double that records every Commit and can be
// made to fail, so the seed guard and its error path can be asserted.
type recordingStore struct {
	mu        sync.Mutex
	commits   map[string][]uint64
	commitErr error
}

func (s *recordingStore) Load(context.Context, string) (uint64, error) { return 0, nil }

func (s *recordingStore) Commit(_ context.Context, feedID string, off uint64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.commitErr != nil {
		return s.commitErr
	}
	if s.commits == nil {
		s.commits = map[string][]uint64{}
	}
	s.commits[feedID] = append(s.commits[feedID], off)
	return nil
}

func (s *recordingStore) committed(feedID string) []uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]uint64, len(s.commits[feedID]))
	copy(out, s.commits[feedID])
	return out
}

func newTestSupervisor(store offsetStore) *Supervisor {
	return &Supervisor{
		cfg:    SupervisorConfig{Store: store, Logger: testutil.DiscardLogger()},
		seeded: map[string]bool{},
	}
}

// TestSeedFloorFunc_SeedsOnceThenGuards proves the seed fires only on a feed's
// first connection: a later reconnect (which resolves the already-correct
// persisted offset) must not re-commit and regress the store behind events still
// draining from the previous connection.
func TestSeedFloorFunc_SeedsOnceThenGuards(t *testing.T) {
	t.Parallel()
	store := &recordingStore{}
	s := newTestSupervisor(store)
	seed := s.seedFloorFunc("feed-a")
	ctx := context.Background()

	if err := seed(ctx, 4_999_999); err != nil {
		t.Fatalf("first seed: %v", err)
	}
	// A reconnect calls the callback again with a different (lower) floor; the
	// guard must make it a no-op.
	if err := seed(ctx, 123); err != nil {
		t.Fatalf("second seed: %v", err)
	}

	got := store.committed("feed-a")
	if len(got) != 1 || got[0] != 4_999_999 {
		t.Fatalf("commits = %v, want exactly [4999999]", got)
	}
}

// TestSeedFloorFunc_PerFeedIsolation confirms the guard is keyed per feed, so a
// multi-partition application seeds each feed's floor independently.
func TestSeedFloorFunc_PerFeedIsolation(t *testing.T) {
	t.Parallel()
	store := &recordingStore{}
	s := newTestSupervisor(store)
	ctx := context.Background()

	if err := s.seedFloorFunc("a")(ctx, 10); err != nil {
		t.Fatal(err)
	}
	if err := s.seedFloorFunc("b")(ctx, 20); err != nil {
		t.Fatal(err)
	}

	if got := store.committed("a"); len(got) != 1 || got[0] != 10 {
		t.Fatalf("feed a commits = %v, want [10]", got)
	}
	if got := store.committed("b"); len(got) != 1 || got[0] != 20 {
		t.Fatalf("feed b commits = %v, want [20]", got)
	}
}

// TestSeedFloorFunc_CommitErrorDoesNotMarkSeeded ensures a failed seed is
// retried on the next connection rather than being silently skipped forever.
func TestSeedFloorFunc_CommitErrorDoesNotMarkSeeded(t *testing.T) {
	t.Parallel()
	boom := errors.New("commit failed")
	store := &recordingStore{commitErr: boom}
	s := newTestSupervisor(store)
	seed := s.seedFloorFunc("feed-a")
	ctx := context.Background()

	if err := seed(ctx, 5); !errors.Is(err, boom) {
		t.Fatalf("seed error = %v, want %v", err, boom)
	}

	// Recover the store and retry: the guard must not have latched, so the retry
	// seeds successfully.
	store.mu.Lock()
	store.commitErr = nil
	store.mu.Unlock()

	if err := seed(ctx, 5); err != nil {
		t.Fatalf("retry seed: %v", err)
	}
	if got := store.committed("feed-a"); len(got) != 1 || got[0] != 5 {
		t.Fatalf("commits after retry = %v, want [5]", got)
	}
}
