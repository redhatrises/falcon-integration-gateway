package stream

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/crowdstrike/falcon-integration-gateway/internal/events"
	"github.com/crowdstrike/falcon-integration-gateway/internal/testutil"
)

// eventLine renders one newline-delimited stream event at the given offset.
func eventLine(off uint64) string {
	return testutil.EventLine(testutil.EventOptions{EventType: "T", Offset: off})
}

func TestResolveOffset(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name            string
		configOffset    uint64
		queueOffset     uint64
		startFromNewest bool
		wantOffset      uint64
		wantWhence      bool
	}{
		{"cold start", 0, 0, false, 0, false},
		{"resume from persisted queue offset", 0, 42, false, 42, false},
		{"operator-pinned config offset", 100, 0, false, 100, false},
		{"persisted offset beats lower config", 10, 50, false, 50, false},
		{"config offset beats lower persisted", 90, 50, false, 90, false},
		{"start-from-newest on first connection", 0, 0, true, 0, true},
		{"start-from-newest resumes from persisted, not whence", 0, 7, true, 7, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			off, whence := resolveOffset(tc.configOffset, tc.queueOffset, tc.startFromNewest)
			if off != tc.wantOffset || whence != tc.wantWhence {
				t.Fatalf("resolveOffset(%d,%d,%v) = (%d,%v), want (%d,%v)",
					tc.configOffset, tc.queueOffset, tc.startFromNewest,
					off, whence, tc.wantOffset, tc.wantWhence)
			}
		})
	}
}

// TestConnection_SeedsFloorBeforeFirstEmit is the P0 regression: the stream
// resumes at whatever offset Falcon has retained (far above a cold-start 0), so
// the connection must seed the pipeline's commit-watermark floor to
// firstOffset-1 before it emits the first event. Without the seed the watermark
// waits forever for an offset-1 that never arrives and nothing is ever committed.
func TestConnection_SeedsFloorBeforeFirstEmit(t *testing.T) {
	t.Parallel()

	const firstOff = uint64(5_000_000)
	lines := []string{
		eventLine(firstOff),
		eventLine(firstOff + 1),
		eventLine(firstOff + 2),
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		flusher, _ := w.(http.Flusher)
		for _, l := range lines {
			fmt.Fprintln(w, l)
			if flusher != nil {
				flusher.Flush()
			}
		}
	}))
	defer srv.Close()

	var (
		mu    sync.Mutex
		seeds []uint64
		got   []uint64
		order []string // interleaving of "seed" and "emit" to assert ordering
	)

	seedFloor := func(_ context.Context, floor uint64) error {
		mu.Lock()
		seeds = append(seeds, floor)
		order = append(order, "seed")
		mu.Unlock()
		return nil
	}

	out := make(chan *events.Event)
	done := make(chan struct{})
	go func() {
		for ev := range out {
			mu.Lock()
			got = append(got, ev.Offset())
			order = append(order, "emit")
			mu.Unlock()
		}
		close(done)
	}()

	conn := newConnection(connectionConfig{
		url:        srv.URL + "?",
		token:      "tok",
		feedID:     "feed-a",
		httpClient: srv.Client(),
		seedFloor:  seedFloor,
		logger:     testutil.DiscardLogger(),
	})

	err := conn.run(context.Background(), out)
	close(out)
	<-done

	if err != nil {
		t.Fatalf("run: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()

	if len(seeds) != 1 {
		t.Fatalf("seedFloor called %d times, want exactly 1 (%v)", len(seeds), seeds)
	}
	if seeds[0] != firstOff-1 {
		t.Fatalf("seeded floor = %d, want %d (firstOffset-1)", seeds[0], firstOff-1)
	}
	if len(order) == 0 || order[0] != "seed" {
		t.Fatalf("seed did not happen before the first emit: order = %v", order)
	}
	want := []uint64{firstOff, firstOff + 1, firstOff + 2}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("emitted offsets = %v, want %v", got, want)
	}
}

// TestConnection_NoSeedOnZeroOffset verifies the underflow guard: an event at
// offset 0 must not seed a floor of uint64(0-1).
func TestConnection_NoSeedOnZeroOffset(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprintln(w, eventLine(0))
	}))
	defer srv.Close()

	var seeded bool
	seedFloor := func(_ context.Context, _ uint64) error {
		seeded = true
		return nil
	}

	out := make(chan *events.Event, 1)
	conn := newConnection(connectionConfig{
		url:        srv.URL + "?",
		token:      "tok",
		feedID:     "feed-a",
		httpClient: srv.Client(),
		seedFloor:  seedFloor,
		logger:     testutil.DiscardLogger(),
	})
	if err := conn.run(context.Background(), out); err != nil {
		t.Fatalf("run: %v", err)
	}
	if seeded {
		t.Fatal("seedFloor was called for an offset-0 event; want no seed (underflow guard)")
	}
}
