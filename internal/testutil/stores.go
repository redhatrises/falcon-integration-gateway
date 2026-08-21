package testutil

import (
	"context"
	"sync"
)

// RecordingStore is an offset-store test double. It records every committed
// offset per feed, can be primed with a per-feed Load base or a Commit error,
// and reports whether it was closed. Its method set structurally satisfies
// offset.Store and any read-only subset a consumer declares, so producer and
// pipeline tests can share one double instead of hand-rolling their own.
//
// The zero value is usable (a nil LoadBase reads as 0 for every feed); use
// NewRecordingStore when a test needs to prime Load results.
type RecordingStore struct {
	mu sync.Mutex

	// LoadBase is the value Load returns per feed; an absent feed reads as 0.
	// Set entries before exercising the store under test.
	LoadBase map[string]uint64
	// CommitErr, when non-nil, is returned by Commit without recording the
	// offset, so the commit-failure path can be asserted.
	CommitErr error

	commits map[string][]uint64
	last    map[string]uint64
	closed  bool
}

// NewRecordingStore returns a RecordingStore with an initialized LoadBase map
// ready for priming.
func NewRecordingStore() *RecordingStore {
	return &RecordingStore{LoadBase: map[string]uint64{}}
}

// Load returns the primed base offset for feedID, or 0 when none is set.
func (s *RecordingStore) Load(_ context.Context, feedID string) (uint64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.LoadBase[feedID], nil
}

// Commit records off as the newest committed offset for feedID, unless CommitErr
// is set, in which case it fails without recording.
func (s *RecordingStore) Commit(_ context.Context, feedID string, off uint64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.CommitErr != nil {
		return s.CommitErr
	}
	if s.commits == nil {
		s.commits = map[string][]uint64{}
		s.last = map[string]uint64{}
	}
	s.commits[feedID] = append(s.commits[feedID], off)
	s.last[feedID] = off
	return nil
}

// Close marks the store closed.
func (s *RecordingStore) Close(_ context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closed = true
	return nil
}

// Committed returns a copy of the offsets committed for feedID, in commit order.
func (s *RecordingStore) Committed(feedID string) []uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]uint64, len(s.commits[feedID]))
	copy(out, s.commits[feedID])
	return out
}

// LastCommitted returns the newest offset committed for feedID, or 0 when none.
func (s *RecordingStore) LastCommitted(feedID string) uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.last[feedID]
}

// Closed reports whether Close has been called.
func (s *RecordingStore) Closed() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.closed
}
