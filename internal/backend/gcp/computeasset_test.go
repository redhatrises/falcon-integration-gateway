package gcp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	compute "google.golang.org/api/compute/v1"
	"google.golang.org/api/googleapi"
	"google.golang.org/api/option"
)

const testZoneURL = "https://www.googleapis.com/compute/v1/projects/proj/zones/us-central1-b"

// step is one canned HTTP response the scriptedHandler serves in sequence.
type step struct {
	status int
	body   string
	header map[string]string
}

// scriptedHandler serves a fixed sequence of responses, one per request, and
// counts how many requests it received. Once the script is exhausted it repeats
// the final step, so an "always 429" case needs only a single step while a
// bounded walk that should stop early is still safe (the surplus step ends
// pagination rather than looping forever).
type scriptedHandler struct {
	mu    sync.Mutex
	steps []step
	calls int
}

func (h *scriptedHandler) ServeHTTP(w http.ResponseWriter, _ *http.Request) {
	h.mu.Lock()
	i := h.calls
	if i >= len(h.steps) {
		i = len(h.steps) - 1
	}
	h.calls++
	s := h.steps[i]
	h.mu.Unlock()

	for k, v := range s.header {
		w.Header().Set(k, v)
	}
	if s.status != 0 {
		w.WriteHeader(s.status)
	}
	_, _ = io.WriteString(w, s.body)
}

func (h *scriptedHandler) callCount() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.calls
}

// newTestResolver builds a computeResolver whose Compute service targets a
// throwaway httptest server driven by the given steps. Backoffs are sub-millisecond
// so rate-limit retries do not slow the test.
func newTestResolver(t *testing.T, steps ...step) (*computeResolver, *scriptedHandler) {
	t.Helper()
	h := &scriptedHandler{steps: steps}
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)

	svc, err := compute.NewService(context.Background(),
		option.WithEndpoint(srv.URL),
		option.WithHTTPClient(srv.Client()))
	if err != nil {
		t.Fatalf("compute.NewService: %v", err)
	}
	return &computeResolver{
		svc:         svc,
		maxRetries:  2,
		baseBackoff: time.Millisecond,
		maxBackoff:  2 * time.Millisecond,
	}, h
}

func testInstance(id uint64, name string) *compute.Instance {
	// The instances resolveInstance parses all live in testZoneURL's project and
	// zone. A real aggregatedList result carries a self link; model it from the
	// zone URL so the resolver derives the resource name from the same canonical
	// URL GCP returns.
	inst := &compute.Instance{Id: id, Name: name, Zone: testZoneURL}
	inst.SelfLink = "https://www.googleapis.com/compute/v1" + testZoneURL[strings.Index(testZoneURL, "/projects/"):] + "/instances/" + name
	return inst
}

// listBody marshals an InstanceAggregatedList page as the Compute REST API would
// return it. The instance id round-trips as a quoted JSON string (its struct tag
// is `id,string`), matching the wire format resolveInstance parses.
func listBody(t *testing.T, nextPageToken string, insts ...*compute.Instance) string {
	t.Helper()
	l := &compute.InstanceAggregatedList{
		Items: map[string]compute.InstancesScopedList{
			"zones/us-central1-b": {Instances: insts},
		},
		NextPageToken: nextPageToken,
	}
	b, err := json.Marshal(l)
	if err != nil {
		t.Fatalf("marshal aggregated list: %v", err)
	}
	return string(b)
}

func TestComputeResolverResolveInstance(t *testing.T) {
	t.Parallel()

	const (
		project  = "1020304050"
		instance = "12345"
		// The resolved name keys on the project id carried by the instance's own
		// self link (proj), not the numeric project number the lookup is scoped by
		// (project, above): SCC names the resource by project id, and querying by
		// number does not change what the instance URL reports.
		want = "//compute.googleapis.com/projects/proj/zones/us-central1-b/instances/vm-1"
	)

	t.Run("single match", func(t *testing.T) {
		t.Parallel()
		r, h := newTestResolver(t, step{status: http.StatusOK, body: listBody(t, "", testInstance(12345, "vm-1"))})

		names, err := r.resolveInstance(context.Background(), project, instance)
		if err != nil {
			t.Fatalf("resolveInstance: %v", err)
		}
		if len(names) != 1 || names[0] != want {
			t.Fatalf("names = %v, want [%s]", names, want)
		}
		if got := h.callCount(); got != 1 {
			t.Fatalf("callCount = %d, want 1", got)
		}
	})

	t.Run("filter silently ignored yields not found", func(t *testing.T) {
		t.Parallel()
		// The server echoes an instance whose id does not match the filter; the
		// per-match id recheck rejects it, so the lookup reports zero names.
		r, h := newTestResolver(t, step{status: http.StatusOK, body: listBody(t, "", testInstance(999, "other"))})

		names, err := r.resolveInstance(context.Background(), project, instance)
		if err != nil {
			t.Fatalf("resolveInstance: %v", err)
		}
		if len(names) != 0 {
			t.Fatalf("names = %v, want none", names)
		}
		if got := h.callCount(); got != 1 {
			t.Fatalf("callCount = %d, want 1", got)
		}
	})

	t.Run("multiple matches", func(t *testing.T) {
		t.Parallel()
		r, _ := newTestResolver(t, step{status: http.StatusOK, body: listBody(t, "",
			testInstance(12345, "vm-1"),
			testInstance(12345, "vm-2"))})

		names, err := r.resolveInstance(context.Background(), project, instance)
		if err != nil {
			t.Fatalf("resolveInstance: %v", err)
		}
		if len(names) != 2 {
			t.Fatalf("names = %v, want two", names)
		}
	})

	t.Run("permission denied is not retried", func(t *testing.T) {
		t.Parallel()
		r, h := newTestResolver(t, step{status: http.StatusForbidden})

		_, err := r.resolveInstance(context.Background(), project, instance)
		if !errors.Is(err, ErrAssetPermissionDenied) {
			t.Fatalf("err = %v, want ErrAssetPermissionDenied", err)
		}
		if got := h.callCount(); got != 1 {
			t.Fatalf("callCount = %d, want 1 (no retry on 403)", got)
		}
	})

	t.Run("rate limited then success retries", func(t *testing.T) {
		t.Parallel()
		r, h := newTestResolver(t,
			step{status: http.StatusTooManyRequests, header: map[string]string{"Retry-After": "0"}},
			step{status: http.StatusOK, body: listBody(t, "", testInstance(12345, "vm-1"))})

		names, err := r.resolveInstance(context.Background(), project, instance)
		if err != nil {
			t.Fatalf("resolveInstance: %v", err)
		}
		if len(names) != 1 || names[0] != want {
			t.Fatalf("names = %v, want [%s]", names, want)
		}
		if got := h.callCount(); got != 2 {
			t.Fatalf("callCount = %d, want 2 (one retry)", got)
		}
	})

	t.Run("rate limited exhausted surfaces generic error", func(t *testing.T) {
		t.Parallel()
		r, h := newTestResolver(t, step{status: http.StatusTooManyRequests})

		_, err := r.resolveInstance(context.Background(), project, instance)
		if err == nil {
			t.Fatal("resolveInstance: got nil error, want rate-limit failure")
		}
		if errors.Is(err, ErrAssetPermissionDenied) {
			t.Fatalf("err = %v, want a plain rate-limit error, not ErrAssetPermissionDenied", err)
		}
		if !isRateLimited(err) {
			t.Fatalf("err = %v, want the underlying 429 preserved", err)
		}
		// One initial attempt plus maxRetries retries.
		if got, wantCalls := h.callCount(), r.maxRetries+1; got != wantCalls {
			t.Fatalf("callCount = %d, want %d", got, wantCalls)
		}
	})

	t.Run("match on a later page is followed", func(t *testing.T) {
		t.Parallel()
		// The first page carries a next-page token and no match; the walk must
		// follow the token to the second page, where the target instance lives.
		r, h := newTestResolver(t,
			step{status: http.StatusOK, body: listBody(t, "next-token", testInstance(999, "other"))},
			step{status: http.StatusOK, body: listBody(t, "", testInstance(12345, "vm-1"))})

		names, err := r.resolveInstance(context.Background(), project, instance)
		if err != nil {
			t.Fatalf("resolveInstance: %v", err)
		}
		if len(names) != 1 || names[0] != want {
			t.Fatalf("names = %v, want [%s]", names, want)
		}
		if got := h.callCount(); got != 2 {
			t.Fatalf("callCount = %d, want 2 (must follow the page token)", got)
		}
	})

	t.Run("ignored filter flooding past the scan bound fails loud", func(t *testing.T) {
		t.Parallel()
		// A dropped id filter streams the whole fleet back: many instances, none
		// matching. Once the scan runs past the sanity bound the lookup must fail
		// loud (errFilterIgnored) rather than report a false not-found that would
		// silently drop the detection.
		flood := make([]*compute.Instance, filterIgnoredScanBound+1)
		for i := range flood {
			flood[i] = testInstance(uint64(1_000_000+i), fmt.Sprintf("vm-%d", i))
		}
		r, _ := newTestResolver(t, step{status: http.StatusOK, body: listBody(t, "", flood...)})

		_, err := r.resolveInstance(context.Background(), project, instance)
		if !errors.Is(err, errFilterIgnored) {
			t.Fatalf("err = %v, want errFilterIgnored", err)
		}
		if errors.Is(err, ErrAssetNotFound) {
			t.Fatalf("err = %v, must not be reported as not-found", err)
		}
	})

	t.Run("non-retryable error surfaces immediately", func(t *testing.T) {
		t.Parallel()
		r, h := newTestResolver(t, step{status: http.StatusInternalServerError})

		_, err := r.resolveInstance(context.Background(), project, instance)
		if err == nil {
			t.Fatal("resolveInstance: got nil error, want a 500 failure")
		}
		if errors.Is(err, ErrAssetPermissionDenied) {
			t.Fatalf("err = %v, want a plain error, not ErrAssetPermissionDenied", err)
		}
		if isRateLimited(err) {
			t.Fatalf("err = %v, a 500 must not be treated as rate-limited", err)
		}
		if got := h.callCount(); got != 1 {
			t.Fatalf("callCount = %d, want 1 (500 is not retried)", got)
		}
	})

	t.Run("context cancellation during backoff", func(t *testing.T) {
		t.Parallel()
		r, _ := newTestResolver(t, step{status: http.StatusTooManyRequests})
		// A comfortably long backoff so cancellation, not exhaustion, ends the wait.
		r.baseBackoff = time.Hour
		r.maxBackoff = time.Hour

		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		_, err := r.resolveInstance(ctx, project, instance)
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("err = %v, want context.Canceled", err)
		}
	})
}

func TestIsPermissionDenied(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{"403", &googleapi.Error{Code: http.StatusForbidden}, true},
		{"wrapped 403", fmt.Errorf("context: %w", &googleapi.Error{Code: http.StatusForbidden}), true},
		{"404", &googleapi.Error{Code: http.StatusNotFound}, false},
		{"429", &googleapi.Error{Code: http.StatusTooManyRequests}, false},
		{"plain error", errors.New("boom"), false},
		{"nil", nil, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := isPermissionDenied(tt.err); got != tt.want {
				t.Fatalf("isPermissionDenied(%v) = %v, want %v", tt.err, got, tt.want)
			}
		})
	}
}

func TestIsRateLimited(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{"429", &googleapi.Error{Code: http.StatusTooManyRequests}, true},
		{"wrapped 429", fmt.Errorf("context: %w", &googleapi.Error{Code: http.StatusTooManyRequests}), true},
		{"403", &googleapi.Error{Code: http.StatusForbidden}, false},
		{"500", &googleapi.Error{Code: http.StatusInternalServerError}, false},
		{"plain error", errors.New("boom"), false},
		{"nil", nil, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := isRateLimited(tt.err); got != tt.want {
				t.Fatalf("isRateLimited(%v) = %v, want %v", tt.err, got, tt.want)
			}
		})
	}
}

func rateLimitErr(retryAfterHdr string) error {
	h := http.Header{}
	if retryAfterHdr != "" {
		h.Set("Retry-After", retryAfterHdr)
	}
	return &googleapi.Error{Code: http.StatusTooManyRequests, Header: h}
}

func TestRetryAfter(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		err     error
		wantDur time.Duration
		wantOK  bool
	}{
		{"seconds", rateLimitErr("5"), 5 * time.Second, true},
		{"zero seconds", rateLimitErr("0"), 0, true},
		{"negative seconds", rateLimitErr("-3"), 0, false},
		{"absent header", rateLimitErr(""), 0, false},
		{"unparseable", rateLimitErr("soon"), 0, false},
		{"not a googleapi error", errors.New("boom"), 0, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			gotDur, gotOK := retryAfter(tt.err)
			if gotDur != tt.wantDur || gotOK != tt.wantOK {
				t.Fatalf("retryAfter = (%v, %v), want (%v, %v)", gotDur, gotOK, tt.wantDur, tt.wantOK)
			}
		})
	}
}

func TestRetryAfterHTTPDate(t *testing.T) {
	t.Parallel()

	t.Run("future date returns positive delay", func(t *testing.T) {
		t.Parallel()
		future := time.Now().Add(90 * time.Second).UTC().Format(http.TimeFormat)
		d, ok := retryAfter(rateLimitErr(future))
		if !ok {
			t.Fatal("retryAfter ok = false, want true for a future HTTP date")
		}
		if d <= 0 {
			t.Fatalf("retryAfter delay = %v, want positive", d)
		}
	})

	t.Run("past date collapses to zero", func(t *testing.T) {
		t.Parallel()
		past := time.Now().Add(-time.Hour).UTC().Format(http.TimeFormat)
		d, ok := retryAfter(rateLimitErr(past))
		if !ok || d != 0 {
			t.Fatalf("retryAfter = (%v, %v), want (0, true) for a past HTTP date", d, ok)
		}
	})
}

func TestNewComputeResolver(t *testing.T) {
	t.Parallel()
	r := newComputeResolver(nil)
	if r.maxRetries != defaultAssetLookupMaxRetries {
		t.Errorf("maxRetries = %d, want %d", r.maxRetries, defaultAssetLookupMaxRetries)
	}
	if r.baseBackoff != defaultAssetLookupBaseBackoff {
		t.Errorf("baseBackoff = %v, want %v", r.baseBackoff, defaultAssetLookupBaseBackoff)
	}
	if r.maxBackoff != defaultAssetLookupMaxBackoff {
		t.Errorf("maxBackoff = %v, want %v", r.maxBackoff, defaultAssetLookupMaxBackoff)
	}
}

func TestBackoff(t *testing.T) {
	t.Parallel()
	// Production-like parameters so the clamp and doubling are exercised at the
	// documented defaults.
	r := &computeResolver{baseBackoff: time.Second, maxBackoff: 30 * time.Second}

	tests := []struct {
		name    string
		header  string
		attempt int
		want    time.Duration
	}{
		{"no header first attempt", "", 0, time.Second},
		{"no header doubles", "", 2, 4 * time.Second},
		{"positive seconds honored", "5", 0, 5 * time.Second},
		{"seconds over cap clamped", "60", 0, 30 * time.Second},
		{"negative seconds ignored falls back to base", "-3", 0, time.Second},
		{"overflow shift clamps to max", "", 63, 30 * time.Second},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := r.backoff(rateLimitErr(tt.header), tt.attempt); got != tt.want {
				t.Fatalf("backoff(%q, %d) = %v, want %v", tt.header, tt.attempt, got, tt.want)
			}
		})
	}

	t.Run("far-future HTTP-date clamps to max", func(t *testing.T) {
		t.Parallel()
		future := time.Now().Add(time.Hour).UTC().Format(http.TimeFormat)
		if got := r.backoff(rateLimitErr(future), 0); got != 30*time.Second {
			t.Fatalf("backoff(HTTP-date, 0) = %v, want %v (clamped)", got, 30*time.Second)
		}
	})
}

func TestInstanceResourceName(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		inst *compute.Instance
		want string
	}{
		{
			// A GCE self link in the shape aggregatedList returns (project id +
			// zone + instance name, the name carrying a UUID suffix) and matching
			// the resourceName form observed in SCC/CAI. The resource name is the
			// self link with its scheme/host/version prefix swapped for the SCC
			// host. Identifiers here are synthetic.
			name: "full self link with project id and uuid-suffixed name",
			inst: &compute.Instance{
				SelfLink: "https://www.googleapis.com/compute/v1/projects/example-gcp-project/zones/us-central1-a/instances/workstations-00000000-0000-0000-0000-000000000000",
			},
			want: "//compute.googleapis.com/projects/example-gcp-project/zones/us-central1-a/instances/workstations-00000000-0000-0000-0000-000000000000",
		},
		{
			// The API version segment is not fixed at v1; the rewrite must strip
			// whatever version prefix the self link carries.
			name: "self link with beta api version",
			inst: &compute.Instance{
				SelfLink: "https://www.googleapis.com/compute/beta/projects/p/zones/z/instances/i",
			},
			want: "//compute.googleapis.com/projects/p/zones/z/instances/i",
		},
		{
			// No self link (unexpected in practice): rebuild from the zone URL,
			// which carries the same project id and zone, plus the instance name.
			name: "no self link falls back to zone url",
			inst: &compute.Instance{
				Zone: "https://www.googleapis.com/compute/v1/projects/p/zones/z",
				Name: "i",
			},
			want: "//compute.googleapis.com/projects/p/zones/z/instances/i",
		},
		{
			// Neither a self link nor a parseable zone URL: the name degrades to
			// host + instance name rather than emitting a malformed prefix.
			name: "no usable url degrades to instance name",
			inst: &compute.Instance{Name: "i"},
			want: "//compute.googleapis.com/instances/i",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := instanceResourceName(tt.inst); got != tt.want {
				t.Fatalf("instanceResourceName = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestComputeResourcePath(t *testing.T) {
	t.Parallel()
	tests := []struct {
		in, want string
	}{
		{"https://www.googleapis.com/compute/v1/projects/p/zones/z/instances/i", "/projects/p/zones/z/instances/i"},
		{"https://www.googleapis.com/compute/v1/projects/p/zones/us-central1-b", "/projects/p/zones/us-central1-b"},
		{"us-central1-b", ""},
		{"", ""},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			t.Parallel()
			if got := computeResourcePath(tt.in); got != tt.want {
				t.Fatalf("computeResourcePath(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}
