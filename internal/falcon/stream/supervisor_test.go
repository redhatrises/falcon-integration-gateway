package stream

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	prommetrics "github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/crowdstrike/falcon-integration-gateway/internal/events"
	"github.com/crowdstrike/falcon-integration-gateway/internal/falcon/client"
	"github.com/crowdstrike/falcon-integration-gateway/internal/metrics"
	"github.com/crowdstrike/falcon-integration-gateway/internal/testutil"
)

func newTestSupervisor(store offsetStore) *Supervisor {
	return &Supervisor{
		cfg:    SupervisorConfig{Store: store, Logger: testutil.DiscardLogger()},
		seeded: map[string]bool{},
	}
}

// fakeControlPlane is a controlPlane double. ListStreams returns successive
// scripted results (result[i]/err[i] on the i-th call); Refresh records each
// partition and returns refreshErr.
type fakeControlPlane struct {
	mu sync.Mutex

	listResults [][]client.Stream
	listErrs    []error
	listCalls   int

	// listRepeat, when set, is returned by every ListStreams call whose index is
	// past listResults/listErrs — used to drive the supervisor's reconnect loop
	// through many sessions without scripting each call.
	listRepeat []client.Stream

	refreshErr        error
	refreshCalls      int
	refreshPartitions []int64
}

func (f *fakeControlPlane) ListStreams(_ context.Context, _ string) ([]client.Stream, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	i := f.listCalls
	f.listCalls++
	if i < len(f.listErrs) && f.listErrs[i] != nil {
		return nil, f.listErrs[i]
	}
	if i < len(f.listResults) {
		return f.listResults[i], nil
	}
	if f.listRepeat != nil {
		return f.listRepeat, nil
	}
	return nil, errors.New("fakeControlPlane: no scripted result")
}

func (f *fakeControlPlane) Refresh(_ context.Context, _ string, partition int64) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.refreshCalls++
	f.refreshPartitions = append(f.refreshPartitions, partition)
	return f.refreshErr
}

func (f *fakeControlPlane) ListCallCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.listCalls
}

// testStream builds a Stream descriptor whose dataFeedURL and refreshURL parse
// to the given feed id and partition through the client regexes.
func testStream(dataFeedURL string, partition, refreshInterval int64) client.Stream {
	return client.NewStream(client.StreamFields{
		Token:           "tok",
		URL:             dataFeedURL,
		RefreshInterval: refreshInterval,
		RefreshURL:      fmt.Sprintf("https://falcon.example/sensors/entities/datafeed-actions/v1/%d?appId=fig", partition),
	})
}

// TestSeedFloorFunc_SeedsOnceThenGuards proves the seed fires only on a feed's
// first connection: a later reconnect (which resolves the already-correct
// persisted offset) must not re-commit and regress the store behind events still
// draining from the previous connection.
func TestSeedFloorFunc_SeedsOnceThenGuards(t *testing.T) {
	t.Parallel()
	store := &testutil.RecordingStore{}
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

	got := store.Committed("feed-a")
	if len(got) != 1 || got[0] != 4_999_999 {
		t.Fatalf("commits = %v, want exactly [4999999]", got)
	}
}

// TestSeedFloorFunc_PerFeedIsolation confirms the guard is keyed per feed, so a
// multi-partition application seeds each feed's floor independently.
func TestSeedFloorFunc_PerFeedIsolation(t *testing.T) {
	t.Parallel()
	store := &testutil.RecordingStore{}
	s := newTestSupervisor(store)
	ctx := context.Background()

	if err := s.seedFloorFunc("a")(ctx, 10); err != nil {
		t.Fatal(err)
	}
	if err := s.seedFloorFunc("b")(ctx, 20); err != nil {
		t.Fatal(err)
	}

	if got := store.Committed("a"); len(got) != 1 || got[0] != 10 {
		t.Fatalf("feed a commits = %v, want [10]", got)
	}
	if got := store.Committed("b"); len(got) != 1 || got[0] != 20 {
		t.Fatalf("feed b commits = %v, want [20]", got)
	}
}

// TestSeedFloorFunc_CommitErrorDoesNotMarkSeeded ensures a failed seed is
// retried on the next connection rather than being silently skipped forever.
func TestSeedFloorFunc_CommitErrorDoesNotMarkSeeded(t *testing.T) {
	t.Parallel()
	boom := errors.New("commit failed")
	store := &testutil.RecordingStore{CommitErr: boom}
	s := newTestSupervisor(store)
	seed := s.seedFloorFunc("feed-a")
	ctx := context.Background()

	if err := seed(ctx, 5); !errors.Is(err, boom) {
		t.Fatalf("seed error = %v, want %v", err, boom)
	}

	// Recover the store and retry: the guard must not have latched, so the retry
	// seeds successfully.
	store.CommitErr = nil

	if err := seed(ctx, 5); err != nil {
		t.Fatalf("retry seed: %v", err)
	}
	if got := store.Committed("feed-a"); len(got) != 1 || got[0] != 5 {
		t.Fatalf("commits after retry = %v, want [5]", got)
	}
}

// TestListStreams covers the bounded-retry list logic: a clean result returns
// immediately, a non-"no streams" error surfaces at once, and an exhausted
// NoStreamsError budget returns that error after the final attempt.
func TestListStreams(t *testing.T) {
	t.Parallel()

	oneStream := []client.Stream{testStream(
		"https://falcon.example/sensors/entities/datafeed/v1/feedA?appId=fig", 0, 0)}
	boom := errors.New("platform 500")

	tests := []struct {
		name           string
		results        [][]client.Stream
		errs           []error
		retries        int
		wantErrIs      error
		wantNoStreams  bool
		wantStreams    int
		wantListCalled int
	}{
		{
			name:           "success returns streams on first attempt",
			results:        [][]client.Stream{oneStream},
			retries:        3,
			wantStreams:    1,
			wantListCalled: 1,
		},
		{
			name:           "non-nostreams error returns immediately",
			errs:           []error{boom},
			retries:        3,
			wantErrIs:      boom,
			wantListCalled: 1,
		},
		{
			name:           "exhausted nostreams budget returns the nostreams error",
			errs:           []error{&client.NoStreamsError{AppID: "fig"}},
			retries:        1,
			wantNoStreams:  true,
			wantListCalled: 1,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			cp := &fakeControlPlane{listResults: tc.results, listErrs: tc.errs}
			s := &Supervisor{
				cfg: SupervisorConfig{
					Client:           cp,
					ApplicationID:    "fig",
					ReconnectRetries: tc.retries,
					Logger:           testutil.DiscardLogger(),
				},
				seeded: map[string]bool{},
			}

			got, err := s.listStreams(context.Background())

			if tc.wantErrIs != nil {
				if !errors.Is(err, tc.wantErrIs) {
					t.Fatalf("listStreams err = %v, want %v", err, tc.wantErrIs)
				}
			}
			if tc.wantNoStreams {
				var noStreams *client.NoStreamsError
				if !errors.As(err, &noStreams) {
					t.Fatalf("listStreams err = %v, want *client.NoStreamsError", err)
				}
			}
			if tc.wantErrIs == nil && !tc.wantNoStreams {
				if err != nil {
					t.Fatalf("listStreams err = %v, want nil", err)
				}
				if len(got) != tc.wantStreams {
					t.Fatalf("listStreams returned %d streams, want %d", len(got), tc.wantStreams)
				}
			}
			if cp.ListCallCount() != tc.wantListCalled {
				t.Fatalf("ListStreams called %d times, want %d", cp.ListCallCount(), tc.wantListCalled)
			}
		})
	}
}

// TestListStreams_HonorsContextDuringRetryBackoff verifies the retry loop stops
// promptly when the context is cancelled mid-backoff instead of sleeping out the
// full no-streams interval.
func TestListStreams_HonorsContextDuringRetryBackoff(t *testing.T) {
	t.Parallel()

	cp := &fakeControlPlane{listErrs: []error{&client.NoStreamsError{AppID: "fig"}}}
	s := &Supervisor{
		cfg: SupervisorConfig{
			Client:           cp,
			ApplicationID:    "fig",
			ReconnectRetries: 5, // enough attempts that the loop would otherwise sleep
			Logger:           testutil.DiscardLogger(),
		},
		seeded: map[string]bool{},
	}

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(20 * time.Millisecond)
		cancel()
	}()

	_, err := s.listStreams(ctx)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("listStreams err = %v, want context.Canceled", err)
	}
	if cp.ListCallCount() != 1 {
		t.Fatalf("ListStreams called %d times, want 1 (cancelled during first backoff)", cp.ListCallCount())
	}
}

// TestRefreshStream covers the session refresher: a cancelled context is a clean
// stop, a non-positive interval simply waits for shutdown, and a refresh error
// ends the session with a wrapped error carrying the partition.
func TestRefreshStream(t *testing.T) {
	t.Parallel()

	t.Run("context cancel is a clean stop", func(t *testing.T) {
		t.Parallel()
		cp := &fakeControlPlane{}
		s := &Supervisor{cfg: SupervisorConfig{Client: cp, ApplicationID: "fig", Logger: testutil.DiscardLogger()}, seeded: map[string]bool{}}
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if err := s.refreshStream(ctx, testStream("u", 3, 1)); err != nil {
			t.Fatalf("refreshStream = %v, want nil on cancel", err)
		}
	})

	t.Run("non-positive interval waits for shutdown", func(t *testing.T) {
		t.Parallel()
		cp := &fakeControlPlane{}
		s := &Supervisor{cfg: SupervisorConfig{Client: cp, ApplicationID: "fig", Logger: testutil.DiscardLogger()}, seeded: map[string]bool{}}
		ctx, cancel := context.WithCancel(context.Background())
		go func() {
			time.Sleep(20 * time.Millisecond)
			cancel()
		}()
		if err := s.refreshStream(ctx, testStream("u", 3, 0)); err != nil {
			t.Fatalf("refreshStream = %v, want nil", err)
		}
		if cp.refreshCalls != 0 {
			t.Fatalf("Refresh called %d times, want 0 for a non-positive interval", cp.refreshCalls)
		}
	})

	t.Run("refresh error ends the session", func(t *testing.T) {
		t.Parallel()
		boom := errors.New("refresh rejected")
		cp := &fakeControlPlane{refreshErr: boom}
		s := &Supervisor{cfg: SupervisorConfig{Client: cp, ApplicationID: "fig", Logger: testutil.DiscardLogger()}, seeded: map[string]bool{}}
		// RefreshInterval 1s -> a 900ms tick; the first fire calls Refresh and errors.
		err := s.refreshStream(context.Background(), testStream("u", 7, 1))
		if !errors.Is(err, boom) {
			t.Fatalf("refreshStream err = %v, want %v", err, boom)
		}
		if cp.refreshPartitions[0] != 7 {
			t.Fatalf("refreshed partition = %d, want 7", cp.refreshPartitions[0])
		}
	})
}

// TestRunOnce_ResumesAtCommittedPlusOne is the end-to-end resume proof: runOnce
// resolves the feed's persisted offset from the store and opens the long-poll at
// committed+1, then emits the delivered event. It exercises listStreams ->
// readStream -> connection URL construction through a live loopback server.
func TestRunOnce_ResumesAtCommittedPlusOne(t *testing.T) {
	t.Parallel()

	var (
		mu       sync.Mutex
		gotQuery string
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		gotQuery = r.URL.RawQuery
		mu.Unlock()
		fmt.Fprintln(w, testutil.EventLine(testutil.EventOptions{EventType: "T", Offset: 43}))
	}))
	defer srv.Close()

	feedURL := srv.URL + "/sensors/entities/datafeed/v1/feedA?appId=fig"
	cp := &fakeControlPlane{listResults: [][]client.Stream{{testStream(feedURL, 1, 0)}}}

	store := testutil.NewRecordingStore()
	store.LoadBase["feedA"] = 42 // persisted watermark; resume must ask for 43

	s := &Supervisor{
		cfg: SupervisorConfig{
			Client:        cp,
			Store:         store,
			ApplicationID: "fig",
			Logger:        testutil.DiscardLogger(),
		},
		httpClient: srv.Client(),
		seeded:     map[string]bool{},
	}

	out := make(chan *events.Event)
	var (
		got  []uint64
		done = make(chan struct{})
	)
	go func() {
		for ev := range out {
			got = append(got, ev.Offset())
		}
		close(done)
	}()

	err := s.runOnce(context.Background(), out)
	close(out)
	<-done

	if err != nil {
		t.Fatalf("runOnce: %v", err)
	}
	mu.Lock()
	q := gotQuery
	mu.Unlock()
	if !strings.Contains(q, "offset=43") {
		t.Fatalf("long-poll query = %q, want it to resume at offset=43 (committed+1)", q)
	}
	if len(got) != 1 || got[0] != 43 {
		t.Fatalf("emitted offsets = %v, want [43]", got)
	}
}

// TestSupervisorRun_ReconnectsAndSkipsFirstSession drives the full Run reconnect
// loop through a fixed number of sessions and proves the StreamReconnects metric
// counts every rebuild except the first session, and that a context cancellation
// (here, triggered by the server on the final session) ends the loop with
// ctx.Err() rather than looping forever. The injected millisecond backoff keeps
// the test fast; the server ends each session immediately (empty body -> EOF).
func TestSupervisorRun_ReconnectsAndSkipsFirstSession(t *testing.T) {
	const sessions = 3

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var hits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		// The n-th session is the n-th request. On the final session, cancel the
		// supervisor's context so Run returns instead of reconnecting again; this
		// makes the total session count deterministic (no trailing reconnect).
		if hits.Add(1) >= sessions {
			cancel()
			return
		}
		fmt.Fprintln(w, testutil.EventLine(testutil.EventOptions{EventType: "T", Offset: 1000}))
	}))
	defer srv.Close()

	feedURL := srv.URL + "/sensors/entities/datafeed/v1/feedA?appId=fig"
	cp := &fakeControlPlane{listRepeat: []client.Stream{testStream(feedURL, 1, 0)}}

	s := &Supervisor{
		cfg: SupervisorConfig{
			Client:                   cp,
			Store:                    testutil.NewRecordingStore(),
			ApplicationID:            "fig",
			ReconnectInitialInterval: time.Millisecond,
			ReconnectMaxInterval:     time.Millisecond,
			Logger:                   testutil.DiscardLogger(),
		},
		httpClient: srv.Client(),
		seeded:     map[string]bool{},
	}

	before := prommetrics.ToFloat64(metrics.StreamReconnects)

	out := make(chan *events.Event)
	go func() {
		for range out { //nolint:revive // drain emitted events
		}
	}()

	err := s.Run(ctx, out)
	close(out)

	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Run err = %v, want context.Canceled", err)
	}
	if got := hits.Load(); got != sessions {
		t.Fatalf("server saw %d sessions, want %d", got, sessions)
	}
	if got := prommetrics.ToFloat64(metrics.StreamReconnects) - before; got != sessions-1 {
		t.Fatalf("StreamReconnects delta = %v, want %d (first session not counted)", got, sessions-1)
	}
}
