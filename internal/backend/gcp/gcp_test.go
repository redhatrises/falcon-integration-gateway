package gcp

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"testing"

	"github.com/crowdstrike/falcon-integration-gateway/internal/backend"
	"github.com/crowdstrike/falcon-integration-gateway/internal/cache"
	"github.com/crowdstrike/falcon-integration-gateway/internal/common"
	"github.com/crowdstrike/falcon-integration-gateway/internal/events"
	"github.com/crowdstrike/falcon-integration-gateway/internal/testutil"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func gcpTestEvent(enricher events.Enricher) *events.EnrichedEvent {
	return events.NewEnrichedEvent(&events.Event{
		Metadata: events.Metadata{
			EventType:         detectionEventType,
			EventCreationTime: 1620000000000,
		},
		Event: map[string]any{},
	}, enricher)
}

func TestName(t *testing.T) {
	t.Parallel()
	rt := &Runtime{logger: slog.New(slog.DiscardHandler)}
	if rt.Name() != backendName {
		t.Errorf("Name() = %q, want %q", rt.Name(), backendName)
	}
}

func TestRelevantEventTypes(t *testing.T) {
	t.Parallel()
	rt := &Runtime{logger: slog.New(slog.DiscardHandler)}
	got := rt.RelevantEventTypes()
	if len(got) != 1 || got[0] != detectionEventType {
		t.Errorf("RelevantEventTypes() = %v, want [%q]", got, detectionEventType)
	}
}

func TestIsRelevant(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name      string
		provider  string
		enrichErr error
		want      bool
	}{
		{name: "gcp provider is relevant", provider: "GCP", want: true},
		{name: "non-gcp provider is not relevant", provider: "AWS", want: false},
		{name: "empty provider is not relevant", provider: "", want: false},
		{name: "enrichment error fails open", provider: "", enrichErr: errors.New("lookup failed"), want: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			rt := &Runtime{logger: slog.New(slog.DiscardHandler)}
			enricher := &testutil.FakeEnricher{Host: &common.HostDetails{CloudProvider: tc.provider}, HostErr: tc.enrichErr}
			ev := gcpTestEvent(enricher)
			if got := rt.IsRelevant(context.Background(), ev); got != tc.want {
				t.Errorf("IsRelevant = %v, want %v", got, tc.want)
			}
		})
	}
}

// capturingHandler collects emitted log records so a test can assert the fields
// of a warning without depending on the rendered text.
type capturingHandler struct {
	mu      sync.Mutex
	records []slog.Record
}

func (h *capturingHandler) Enabled(context.Context, slog.Level) bool { return true }

func (h *capturingHandler) Handle(_ context.Context, r slog.Record) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.records = append(h.records, r.Clone())
	return nil
}

func (h *capturingHandler) WithAttrs([]slog.Attr) slog.Handler { return h }
func (h *capturingHandler) WithGroup(string) slog.Handler      { return h }

// attrValue returns the first value logged under key across all captured
// records, and whether any record carried it.
func (h *capturingHandler) attrValue(key string) (string, bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, r := range h.records {
		var value string
		var found bool
		r.Attrs(func(a slog.Attr) bool {
			if a.Key == key {
				value = a.Value.String()
				found = true
				return false
			}
			return true
		})
		if found {
			return value, true
		}
	}
	return "", false
}

// recordingFindingClient captures createFinding inputs so Process tests can
// assert the submitted finding, with injectable existence/create behavior.
type recordingFindingClient struct {
	existsFn  func() (bool, error)
	createErr error
	created   []findingCreateInput
}

func (r *recordingFindingClient) findingExists(_ context.Context, _, _ string) (bool, error) {
	if r.existsFn != nil {
		return r.existsFn()
	}
	return false, nil
}

func (r *recordingFindingClient) createFinding(_ context.Context, in findingCreateInput) error {
	r.created = append(r.created, in)
	return r.createErr
}

// processEvent builds a detection EnrichedEvent with populated process fields.
func processEvent(enricher events.Enricher) *events.EnrichedEvent {
	return events.NewEnrichedEvent(&events.Event{
		Metadata: events.Metadata{
			EventType:         detectionEventType,
			EventCreationTime: 1620000000000,
		},
		Event: map[string]any{
			"DetectId":          "ldt:abc:123",
			"DetectName":        "Malware",
			"DetectDescription": "bad things happened",
			"SeverityName":      "High",
			"FalconHostLink":    "https://falcon.example/link",
			"ComputerName":      "host-1",
			"FileName":          "evil.exe",
			"FilePath":          "/tmp",
			"CommandLine":       "evil --run",
		},
	}, enricher)
}

// gcpHost is the resolved GCP host details Process tests operate on.
func gcpHost() *common.HostDetails {
	return &common.HostDetails{
		Known:                  true,
		CloudProvider:          gcpCloudProvider,
		CloudProviderAccountID: "111111111",
		InstanceID:             "9876543210",
	}
}

// newProcessRuntime wires a Runtime with the given seams and empty caches.
func newProcessRuntime(resolver orgResolver, source sourceClient, lister assetLister, findings findingClient) *Runtime {
	return &Runtime{
		orgs:      &orgCache{resolver: resolver, cache: cache.New[string, string](0)},
		sources:   &sourceCache{client: source, cache: cache.New[string, string](0)},
		assets:    newAssetCache(lister, defaultAssetCacheSize),
		submitter: &findingSubmitter{client: findings},
		logger:    slog.New(slog.DiscardHandler),
	}
}

func TestProcessCreatesFinding(t *testing.T) {
	t.Parallel()

	fc := &recordingFindingClient{}
	rt := newProcessRuntime(
		&fakeOrgResolver{byProj: map[string]string{"111111111": "42"}},
		&fakeSourceClient{existing: map[string]string{"42": "organizations/42/sources/fig"}},
		&fakeAssetLister{names: []string{"//compute.googleapis.com/projects/p/zones/z/instances/i"}},
		fc,
	)

	if err := rt.Process(context.Background(), processEvent(&testutil.FakeEnricher{Host: gcpHost()})); err != nil {
		t.Fatalf("Process: unexpected error %v", err)
	}
	if len(fc.created) != 1 {
		t.Fatalf("createFinding calls = %d, want 1", len(fc.created))
	}

	got := fc.created[0]
	wantID := findingID("ldt:abc:123", 1620000000000)
	if got.findingID != wantID {
		t.Errorf("findingID = %q, want %q", got.findingID, wantID)
	}
	if want := "organizations/42/sources/fig" + findingsPathSegment + wantID; got.finding.GetName() != want {
		t.Errorf("finding.Name = %q, want %q", got.finding.GetName(), want)
	}
	if want := "//compute.googleapis.com/projects/p/zones/z/instances/i"; got.finding.GetResourceName() != want {
		t.Errorf("finding.ResourceName = %q, want %q", got.finding.GetResourceName(), want)
	}
	if got.finding.GetCategory() != "Malware" {
		t.Errorf("finding.Category = %q, want %q", got.finding.GetCategory(), "Malware")
	}
}

func TestProcessPermissionDeniedDrops(t *testing.T) {
	t.Parallel()

	fc := &recordingFindingClient{}
	rt := newProcessRuntime(
		&fakeOrgResolver{err: status.Error(codes.PermissionDenied, "denied")},
		&fakeSourceClient{},
		&fakeAssetLister{},
		fc,
	)

	err := rt.Process(context.Background(), processEvent(&testutil.FakeEnricher{Host: gcpHost()}))
	var drop *backend.DropError
	if !errors.As(err, &drop) {
		t.Fatalf("Process error = %v, want a *backend.DropError", err)
	}
	if drop.Reason != "permission_denied" {
		t.Errorf("drop reason = %q, want %q", drop.Reason, "permission_denied")
	}
	if len(fc.created) != 0 {
		t.Errorf("createFinding calls = %d, want 0 (dropped)", len(fc.created))
	}
}

func TestProcessPermissionDeniedOnSourceLogsOrgID(t *testing.T) {
	t.Parallel()

	h := &capturingHandler{}
	fc := &recordingFindingClient{}
	rt := &Runtime{
		orgs:      &orgCache{resolver: &fakeOrgResolver{byProj: map[string]string{"111111111": "42"}}, cache: cache.New[string, string](0)},
		sources:   &sourceCache{client: &fakeSourceClient{createErr: status.Error(codes.PermissionDenied, "denied")}, cache: cache.New[string, string](0)},
		assets:    newAssetCache(&fakeAssetLister{}, defaultAssetCacheSize),
		submitter: &findingSubmitter{client: fc},
		logger:    slog.New(h),
	}

	err := rt.Process(context.Background(), processEvent(&testutil.FakeEnricher{Host: gcpHost()}))
	var drop *backend.DropError
	if !errors.As(err, &drop) {
		t.Fatalf("Process error = %v, want a *backend.DropError", err)
	}
	if drop.Reason != "permission_denied" {
		t.Errorf("drop reason = %q, want %q", drop.Reason, "permission_denied")
	}
	if len(fc.created) != 0 {
		t.Errorf("createFinding calls = %d, want 0 (dropped)", len(fc.created))
	}

	orgID, ok := h.attrValue("org_id")
	if !ok {
		t.Fatal("permission-denied warning is missing the org_id field")
	}
	if orgID != "42" {
		t.Errorf("logged org_id = %q, want %q", orgID, "42")
	}
}

func TestProcessAssetNotFoundDrops(t *testing.T) {
	t.Parallel()

	fc := &recordingFindingClient{}
	rt := newProcessRuntime(
		&fakeOrgResolver{byProj: map[string]string{"111111111": "42"}},
		&fakeSourceClient{existing: map[string]string{"42": "organizations/42/sources/fig"}},
		&fakeAssetLister{names: nil},
		fc,
	)

	err := rt.Process(context.Background(), processEvent(&testutil.FakeEnricher{Host: gcpHost()}))
	var drop *backend.DropError
	if !errors.As(err, &drop) {
		t.Fatalf("Process error = %v, want a *backend.DropError", err)
	}
	if drop.Reason != "asset_not_found" {
		t.Errorf("drop reason = %q, want %q", drop.Reason, "asset_not_found")
	}
	if len(fc.created) != 0 {
		t.Errorf("createFinding calls = %d, want 0 (dropped)", len(fc.created))
	}
}
func TestProcessEnrichmentErrorReturned(t *testing.T) {
	t.Parallel()

	boom := errors.New("enrichment boom")
	rt := newProcessRuntime(
		&fakeOrgResolver{},
		&fakeSourceClient{},
		&fakeAssetLister{},
		&recordingFindingClient{},
	)

	err := rt.Process(context.Background(), processEvent(&testutil.FakeEnricher{HostErr: boom}))
	if !errors.Is(err, boom) {
		t.Fatalf("Process error = %v, want enrichment boom returned for DLQ", err)
	}
}

func TestProcessOrgErrorReturned(t *testing.T) {
	t.Parallel()

	boom := errors.New("resolve boom")
	rt := newProcessRuntime(
		&fakeOrgResolver{err: boom},
		&fakeSourceClient{},
		&fakeAssetLister{},
		&recordingFindingClient{},
	)

	err := rt.Process(context.Background(), processEvent(&testutil.FakeEnricher{Host: gcpHost()}))
	if !errors.Is(err, boom) {
		t.Fatalf("Process error = %v, want org-resolution boom returned for DLQ", err)
	}
}

func TestProcessAssetErrorReturned(t *testing.T) {
	t.Parallel()

	boom := errors.New("asset boom")
	rt := newProcessRuntime(
		&fakeOrgResolver{byProj: map[string]string{"111111111": "42"}},
		&fakeSourceClient{existing: map[string]string{"42": "organizations/42/sources/fig"}},
		&fakeAssetLister{err: boom},
		&recordingFindingClient{},
	)

	err := rt.Process(context.Background(), processEvent(&testutil.FakeEnricher{Host: gcpHost()}))
	if !errors.Is(err, boom) {
		t.Fatalf("Process error = %v, want asset-lookup boom returned for DLQ", err)
	}
}

func TestProcessSubmitErrorReturned(t *testing.T) {
	t.Parallel()

	boom := errors.New("create boom")
	fc := &recordingFindingClient{createErr: boom}
	rt := newProcessRuntime(
		&fakeOrgResolver{byProj: map[string]string{"111111111": "42"}},
		&fakeSourceClient{existing: map[string]string{"42": "organizations/42/sources/fig"}},
		&fakeAssetLister{names: []string{"//compute.googleapis.com/projects/p/zones/z/instances/i"}},
		fc,
	)

	err := rt.Process(context.Background(), processEvent(&testutil.FakeEnricher{Host: gcpHost()}))
	if !errors.Is(err, boom) {
		t.Fatalf("Process error = %v, want submit boom returned for DLQ", err)
	}
}

func TestResolveOrgSource(t *testing.T) {
	t.Parallel()
	orgs := newOrgCache(&fakeOrgResolver{byProj: map[string]string{
		"111111111": "42",
		"222222222": "99",
	}})
	sources := newSourceCache(&fakeSourceClient{existing: map[string]string{
		"42": "organizations/42/sources/fig",
		"99": "organizations/99/sources/fig",
	}})
	rt := &Runtime{orgs: orgs, sources: sources, logger: slog.New(slog.DiscardHandler)}

	tests := []struct {
		name       string
		project    string
		wantOrg    string
		wantSource string
	}{
		{name: "first project resolves to its org source", project: "111111111", wantOrg: "42", wantSource: "organizations/42/sources/fig"},
		{name: "second project resolves to its org source", project: "222222222", wantOrg: "99", wantSource: "organizations/99/sources/fig"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			gotOrg, gotSource, err := rt.resolveOrgSource(context.Background(), tc.project)
			if err != nil {
				t.Fatalf("resolveOrgSource(%q) unexpected error: %v", tc.project, err)
			}
			if gotOrg != tc.wantOrg {
				t.Errorf("resolveOrgSource(%q) orgID = %q, want %q", tc.project, gotOrg, tc.wantOrg)
			}
			if gotSource != tc.wantSource {
				t.Errorf("resolveOrgSource(%q) source = %q, want %q", tc.project, gotSource, tc.wantSource)
			}
		})
	}
}

func TestResolveOrgSourceOrgErrorPropagates(t *testing.T) {
	t.Parallel()
	orgs := newOrgCache(&fakeOrgResolver{err: errors.New("resolve failed")})
	sources := newSourceCache(&fakeSourceClient{})
	rt := &Runtime{orgs: orgs, sources: sources, logger: slog.New(slog.DiscardHandler)}

	if _, _, err := rt.resolveOrgSource(context.Background(), "111111111"); err == nil {
		t.Fatal("resolveOrgSource = nil error, want org-resolution error propagated")
	}
}

func TestResolveOrgSourceSourceErrorPropagates(t *testing.T) {
	t.Parallel()
	orgs := newOrgCache(&fakeOrgResolver{byProj: map[string]string{"111111111": "42"}})
	sources := newSourceCache(&fakeSourceClient{createErr: errors.New("create failed")})
	rt := &Runtime{orgs: orgs, sources: sources, logger: slog.New(slog.DiscardHandler)}

	if _, _, err := rt.resolveOrgSource(context.Background(), "111111111"); err == nil {
		t.Fatal("resolveOrgSource = nil error, want source get-or-create error propagated")
	}
}
