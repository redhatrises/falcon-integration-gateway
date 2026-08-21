package aws

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"testing"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/securityhub"
	securityhubtypes "github.com/aws/aws-sdk-go-v2/service/securityhub/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"

	"github.com/crowdstrike/falcon-integration-gateway/internal/cache"
	"github.com/crowdstrike/falcon-integration-gateway/internal/common"
	"github.com/crowdstrike/falcon-integration-gateway/internal/events"
	"github.com/crowdstrike/falcon-integration-gateway/internal/testutil"
)

// fakeSecurityHub records GetFindings/BatchImportFindings calls and can simulate
// an existing (deduped) finding or transport errors.
type fakeSecurityHub struct {
	existing    []securityhubtypes.AwsSecurityFinding
	getErr      error
	importErr   error
	failed      []securityhubtypes.ImportFindingsError
	getCalls    int
	importCalls int
	imported    []securityhubtypes.AwsSecurityFinding
}

func (f *fakeSecurityHub) GetFindings(_ context.Context, _ *securityhub.GetFindingsInput, _ ...func(*securityhub.Options)) (*securityhub.GetFindingsOutput, error) {
	f.getCalls++
	if f.getErr != nil {
		return nil, f.getErr
	}
	return &securityhub.GetFindingsOutput{Findings: f.existing}, nil
}

func (f *fakeSecurityHub) BatchImportFindings(_ context.Context, in *securityhub.BatchImportFindingsInput, _ ...func(*securityhub.Options)) (*securityhub.BatchImportFindingsOutput, error) {
	f.importCalls++
	if f.importErr != nil {
		return nil, f.importErr
	}
	if len(f.failed) > 0 {
		failed := int32(len(f.failed))              //nolint:gosec // test fixture: small, controlled slice lengths
		success := int32(len(in.Findings)) - failed //nolint:gosec // test fixture: small, controlled slice lengths
		return &securityhub.BatchImportFindingsOutput{
			SuccessCount:   &success,
			FailedCount:    &failed,
			FailedFindings: f.failed,
		}, nil
	}
	f.imported = append(f.imported, in.Findings...)
	one := int32(1)
	zero := int32(0)
	return &securityhub.BatchImportFindingsOutput{SuccessCount: &one, FailedCount: &zero}, nil
}

// fakeEC2 answers DescribeRegions with a fixed region list and DescribeInstances
// with per-region instances keyed by the region passed via the options override.
// mu guards the call counters so concurrent walks (findInstance runs outside the
// backend lock) do not race the fake itself; sequential tests read the counters
// after the calls return.
type fakeEC2 struct {
	regions       []string
	byRegion      map[string][]ec2types.Instance
	regionsErr    error
	describeErr   error
	mu            sync.Mutex
	regionsCalls  int
	describeCalls int
}

func (f *fakeEC2) DescribeRegions(_ context.Context, _ *ec2.DescribeRegionsInput, _ ...func(*ec2.Options)) (*ec2.DescribeRegionsOutput, error) {
	f.mu.Lock()
	f.regionsCalls++
	f.mu.Unlock()
	if f.regionsErr != nil {
		return nil, f.regionsErr
	}
	out := &ec2.DescribeRegionsOutput{}
	for _, r := range f.regions {
		out.Regions = append(out.Regions, ec2types.Region{RegionName: awssdk.String(r)})
	}
	return out, nil
}

func (f *fakeEC2) DescribeInstances(_ context.Context, _ *ec2.DescribeInstancesInput, optFns ...func(*ec2.Options)) (*ec2.DescribeInstancesOutput, error) {
	f.mu.Lock()
	f.describeCalls++
	f.mu.Unlock()
	if f.describeErr != nil {
		return nil, f.describeErr
	}
	opts := ec2.Options{}
	for _, fn := range optFns {
		fn(&opts)
	}
	instances := f.byRegion[opts.Region]
	if len(instances) == 0 {
		return &ec2.DescribeInstancesOutput{}, nil
	}
	return &ec2.DescribeInstancesOutput{
		Reservations: []ec2types.Reservation{{Instances: instances}},
	}, nil
}

// describeCount reads the DescribeInstances call counter under the lock so it is
// safe to observe after concurrent walks (findInstance runs outside the backend
// lock).
func (f *fakeEC2) describeCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.describeCalls
}

// fakeSTS returns a fixed caller-identity account id and counts how many times
// it is called so tests can assert the account id is resolved once and cached.
type fakeSTS struct {
	account string
	err     error
	calls   int
}

func (f *fakeSTS) GetCallerIdentity(_ context.Context, _ *sts.GetCallerIdentityInput, _ ...func(*sts.Options)) (*sts.GetCallerIdentityOutput, error) {
	f.calls++
	if f.err != nil {
		return nil, f.err
	}
	return &sts.GetCallerIdentityOutput{Account: awssdk.String(f.account)}, nil
}

func newTestSecurityHub(sh securityHubAPI, ec2c ec2API, stsc stsAPI) *securityHub {
	return &securityHub{
		logger:          slog.New(slog.DiscardHandler),
		sh:              sh,
		ec2:             ec2c,
		sts:             stsc,
		region:          "us-east-1",
		confirmInstance: false,
		acceptAllEvents: false,
		figVersion:      "9.9.9",
		regions:         cache.New[string, string](defaultRegionCacheSize),
		account:         cache.New[string, string](0),
	}
}

func detectionEvent(enricher events.Enricher, inner map[string]any) *events.EnrichedEvent {
	if inner == nil {
		inner = map[string]any{}
	}
	return events.NewEnrichedEvent(&events.Event{
		Metadata: events.Metadata{
			EventType:         "EppDetectionSummaryEvent",
			Offset:            5,
			EventCreationTime: 1620000000000,
			CustomerIDString:  "cid-123",
		},
		FeedID: "feed1",
		Raw:    []byte(`{"event":{}}`),
		Event:  inner,
	}, enricher)
}

func TestTruncateField(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		value string
		max   int
		want  string
	}{
		{"shorter than limit", "abc", 10, "abc"},
		{"exactly at limit", "abcde", 5, "abcde"},
		{"longer than limit", "abcdefgh", 5, "ab..."},
		{"limit too small for ellipsis", "abcdef", 2, "ab"},
		{"limit exactly three", "abcdef", 3, "abc"},
		{"zero limit", "abc", 0, ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := truncateField(tc.value, tc.max)
			if got != tc.want {
				t.Errorf("truncateField(%q, %d) = %q, want %q", tc.value, tc.max, got, tc.want)
			}
			if len(got) > tc.max {
				t.Errorf("truncateField result length %d exceeds max %d", len(got), tc.max)
			}
		})
	}
}

func TestProductARN(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		region string
		want   string
	}{
		{"commercial", "us-east-1", "arn:aws:securityhub:us-east-1:517716713836:product/crowdstrike/crowdstrike-falcon"},
		{"govcloud", "us-gov-west-1", "arn:aws-us-gov:securityhub:us-gov-west-1:358431324613:product/crowdstrike/crowdstrike-falcon"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := productARN(tc.region); got != tc.want {
				t.Errorf("productARN(%q) = %q, want %q", tc.region, got, tc.want)
			}
		})
	}
}

func TestSecurityHubIsRelevant(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name      string
		acceptAll bool
		provider  string
		enrichErr error
		want      bool
	}{
		{"accept all bypasses provider check", true, "", nil, true},
		{"aws provider", false, "AWS", nil, true},
		{"aws-cn prefix case-insensitive", false, "aws-cn", nil, true},
		{"non-aws provider", false, "Azure", nil, false},
		{"enrichment error fails open", false, "", errors.New("lookup failed"), true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			rt := newTestSecurityHub(&fakeSecurityHub{}, &fakeEC2{}, &fakeSTS{})
			rt.acceptAllEvents = tc.acceptAll
			enricher := &testutil.FakeEnricher{Host: &common.HostDetails{CloudProvider: tc.provider}, HostErr: tc.enrichErr}
			ev := detectionEvent(enricher, nil)
			if got := rt.IsRelevant(context.Background(), ev); got != tc.want {
				t.Errorf("IsRelevant = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestFindInstanceMACMatch(t *testing.T) {
	t.Parallel()
	ec2c := &fakeEC2{
		regions: []string{"us-east-1", "us-west-2"},
		byRegion: map[string][]ec2types.Instance{
			"us-west-2": {{
				InstanceId: awssdk.String("i-123"),
				NetworkInterfaces: []ec2types.InstanceNetworkInterface{
					{MacAddress: awssdk.String("0A:1B:2C:3D:4E:5F")},
				},
			}},
		},
	}
	rt := newTestSecurityHub(&fakeSecurityHub{}, ec2c, &fakeSTS{})

	region, found, err := rt.findInstance(context.Background(), "i-123", "0a-1b-2c-3d-4e-5f")
	if err != nil {
		t.Fatalf("findInstance: %v", err)
	}
	if !found {
		t.Fatal("findInstance found = false, want true")
	}
	if region != "us-west-2" {
		t.Errorf("region = %q, want us-west-2", region)
	}
}

// TestFindInstanceContextCanceled verifies the region walk is abandoned the
// moment the context is cancelled rather than continuing to probe every region.
func TestFindInstanceContextCanceled(t *testing.T) {
	t.Parallel()
	ec2c := &fakeEC2{
		regions:     []string{"us-east-1", "us-west-2", "eu-west-1"},
		describeErr: context.Canceled,
	}
	rt := newTestSecurityHub(&fakeSecurityHub{}, ec2c, &fakeSTS{})

	_, _, err := rt.findInstance(context.Background(), "i-123", "0a:1b:2c:3d:4e:5f")
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("findInstance error = %v, want it to wrap context.Canceled", err)
	}
	if ec2c.describeCalls != 1 {
		t.Errorf("DescribeInstances calls = %d, want 1 (walk abandoned on cancellation)", ec2c.describeCalls)
	}
}

func TestFindInstanceMACMiss(t *testing.T) {
	t.Parallel()
	ec2c := &fakeEC2{
		regions: []string{"us-east-1", "us-west-2"},
		byRegion: map[string][]ec2types.Instance{
			"us-west-2": {{
				InstanceId: awssdk.String("i-123"),
				NetworkInterfaces: []ec2types.InstanceNetworkInterface{
					{MacAddress: awssdk.String("ff:ff:ff:ff:ff:ff")},
				},
			}},
		},
	}
	rt := newTestSecurityHub(&fakeSecurityHub{}, ec2c, &fakeSTS{})

	_, found, err := rt.findInstance(context.Background(), "i-123", "0a:1b:2c:3d:4e:5f")
	if err != nil {
		t.Fatalf("findInstance: %v", err)
	}
	if found {
		t.Error("findInstance found = true, want false (no MAC match)")
	}
}

// TestFindInstanceCachesRegion verifies a successful (instanceID, MAC) lookup is
// memoized: a second call for the same pair is served from cache and issues no
// further DescribeInstances calls. The region for a found instance is immutable,
// so this is safe.
func TestFindInstanceCachesRegion(t *testing.T) {
	t.Parallel()
	ec2c := &fakeEC2{
		regions: []string{"us-east-1", "us-west-2"},
		byRegion: map[string][]ec2types.Instance{
			"us-west-2": {{
				InstanceId: awssdk.String("i-123"),
				NetworkInterfaces: []ec2types.InstanceNetworkInterface{
					{MacAddress: awssdk.String("0a:1b:2c:3d:4e:5f")},
				},
			}},
		},
	}
	rt := newTestSecurityHub(&fakeSecurityHub{}, ec2c, &fakeSTS{})

	region, found, err := rt.findInstance(context.Background(), "i-123", "0a:1b:2c:3d:4e:5f")
	if err != nil || !found || region != "us-west-2" {
		t.Fatalf("first findInstance = (%q, %v, %v), want (us-west-2, true, nil)", region, found, err)
	}
	callsAfterFirst := ec2c.describeCalls

	region, found, err = rt.findInstance(context.Background(), "i-123", "0a:1b:2c:3d:4e:5f")
	if err != nil || !found || region != "us-west-2" {
		t.Fatalf("second findInstance = (%q, %v, %v), want (us-west-2, true, nil)", region, found, err)
	}
	if ec2c.describeCalls != callsAfterFirst {
		t.Errorf("DescribeInstances calls after cached lookup = %d, want %d (served from cache)", ec2c.describeCalls, callsAfterFirst)
	}
}

// TestFindInstanceCacheKeyIncludesMAC verifies the cache key disambiguates on MAC
// as well as instance id: a reused instance id with a different MAC is a distinct
// lookup, not a cache hit against the first entry. Keying on instance id alone
// would emit a finding against the wrong region.
func TestFindInstanceCacheKeyIncludesMAC(t *testing.T) {
	t.Parallel()
	ec2c := &fakeEC2{
		regions: []string{"us-east-1", "us-west-2"},
		byRegion: map[string][]ec2types.Instance{
			"us-east-1": {{
				InstanceId: awssdk.String("i-123"),
				NetworkInterfaces: []ec2types.InstanceNetworkInterface{
					{MacAddress: awssdk.String("aa:aa:aa:aa:aa:aa")},
				},
			}},
			"us-west-2": {{
				InstanceId: awssdk.String("i-123"),
				NetworkInterfaces: []ec2types.InstanceNetworkInterface{
					{MacAddress: awssdk.String("bb:bb:bb:bb:bb:bb")},
				},
			}},
		},
	}
	rt := newTestSecurityHub(&fakeSecurityHub{}, ec2c, &fakeSTS{})

	region, found, err := rt.findInstance(context.Background(), "i-123", "aa:aa:aa:aa:aa:aa")
	if err != nil || !found || region != "us-east-1" {
		t.Fatalf("first findInstance = (%q, %v, %v), want (us-east-1, true, nil)", region, found, err)
	}

	region, found, err = rt.findInstance(context.Background(), "i-123", "bb:bb:bb:bb:bb:bb")
	if err != nil || !found || region != "us-west-2" {
		t.Fatalf("second findInstance (different MAC) = (%q, %v, %v), want (us-west-2, true, nil) — key must include MAC", region, found, err)
	}
}

// TestFindInstanceDoesNotCacheMiss verifies a not-found result is never cached, so
// an instance that appears after an initial miss (newly launched, or EC2 API
// eventual consistency) is found on a later event rather than latched to "not
// found" forever.
func TestFindInstanceDoesNotCacheMiss(t *testing.T) {
	t.Parallel()
	ec2c := &fakeEC2{
		regions:  []string{"us-east-1", "us-west-2"},
		byRegion: map[string][]ec2types.Instance{}, // instance absent initially
	}
	rt := newTestSecurityHub(&fakeSecurityHub{}, ec2c, &fakeSTS{})

	if _, found, err := rt.findInstance(context.Background(), "i-123", "0a:1b:2c:3d:4e:5f"); err != nil || found {
		t.Fatalf("first findInstance = (found %v, err %v), want (false, nil)", found, err)
	}

	// The instance now exists; a miss must not have been cached.
	ec2c.byRegion["us-west-2"] = []ec2types.Instance{{
		InstanceId: awssdk.String("i-123"),
		NetworkInterfaces: []ec2types.InstanceNetworkInterface{
			{MacAddress: awssdk.String("0a:1b:2c:3d:4e:5f")},
		},
	}}
	region, found, err := rt.findInstance(context.Background(), "i-123", "0a:1b:2c:3d:4e:5f")
	if err != nil || !found || region != "us-west-2" {
		t.Fatalf("second findInstance = (%q, %v, %v), want (us-west-2, true, nil) — miss must not be cached", region, found, err)
	}
}

// mustFind calls findInstance and fails the test unless the instance is found.
func mustFind(t *testing.T, rt *securityHub, instanceID, mac string) string {
	t.Helper()
	region, found, err := rt.findInstance(context.Background(), instanceID, mac)
	if err != nil || !found {
		t.Fatalf("findInstance(%q, %q) = (%q, found %v, err %v), want found", instanceID, mac, region, found, err)
	}
	return region
}

// TestFindInstanceEvictsOldestUnderBound verifies the region cache honors its FIFO
// bound: past the cap the oldest entry is evicted, the most-recent entries stay
// cached (served without a re-walk), and an evicted key is re-walked on its next
// lookup. A small regionCacheMax stands in for the production regionCacheSize so
// the test exercises eviction without inserting thousands of entries.
func TestFindInstanceEvictsOldestUnderBound(t *testing.T) {
	t.Parallel()
	ec2c := &fakeEC2{
		regions: []string{"us-east-1", "us-west-2"},
		byRegion: map[string][]ec2types.Instance{
			"us-east-1": {
				{NetworkInterfaces: []ec2types.InstanceNetworkInterface{{MacAddress: awssdk.String("aa:aa:aa:aa:aa:aa")}}},
				{NetworkInterfaces: []ec2types.InstanceNetworkInterface{{MacAddress: awssdk.String("bb:bb:bb:bb:bb:bb")}}},
				{NetworkInterfaces: []ec2types.InstanceNetworkInterface{{MacAddress: awssdk.String("cc:cc:cc:cc:cc:cc")}}},
			},
		},
	}
	rt := newTestSecurityHub(&fakeSecurityHub{}, ec2c, &fakeSTS{})
	rt.regions = cache.New[string, string](2)

	// Three distinct keys; the third insert evicts the first (i-1).
	mustFind(t, rt, "i-1", "aa:aa:aa:aa:aa:aa")
	mustFind(t, rt, "i-2", "bb:bb:bb:bb:bb:bb")
	mustFind(t, rt, "i-3", "cc:cc:cc:cc:cc:cc")

	// i-2 and i-3 are the two most-recent keys: cache hits, no new walk.
	callsBefore := ec2c.describeCount()
	mustFind(t, rt, "i-2", "bb:bb:bb:bb:bb:bb")
	mustFind(t, rt, "i-3", "cc:cc:cc:cc:cc:cc")
	if got := ec2c.describeCount(); got != callsBefore {
		t.Errorf("DescribeInstances during hot re-lookups = %d, want %d (served from cache)", got, callsBefore)
	}

	// i-1 was evicted: its re-lookup must re-walk (miss is not cached as absence).
	callsBefore = ec2c.describeCount()
	if region := mustFind(t, rt, "i-1", "aa:aa:aa:aa:aa:aa"); region != "us-east-1" {
		t.Errorf("evicted re-lookup region = %q, want us-east-1", region)
	}
	if got := ec2c.describeCount(); got <= callsBefore {
		t.Errorf("DescribeInstances after evicted re-lookup = %d, want > %d (re-walk expected)", got, callsBefore)
	}
}

// TestFindInstanceConcurrentStaysConsistent runs many goroutines through
// findInstance for one shared (instanceID, MAC) key and several distinct keys
// under -race. It proves concurrent walks resolve the correct region for every
// caller with no data race; the cache's own bound and single-load guarantees are
// covered by the cache package's tests.
func TestFindInstanceConcurrentStaysConsistent(t *testing.T) {
	t.Parallel()
	ec2c := &fakeEC2{
		regions: []string{"us-east-1", "us-west-2", "eu-west-1"},
		byRegion: map[string][]ec2types.Instance{
			"eu-west-1": {
				{NetworkInterfaces: []ec2types.InstanceNetworkInterface{{MacAddress: awssdk.String("aa:aa:aa:aa:aa:aa")}}},
				{NetworkInterfaces: []ec2types.InstanceNetworkInterface{{MacAddress: awssdk.String("bb:bb:bb:bb:bb:bb")}}},
				{NetworkInterfaces: []ec2types.InstanceNetworkInterface{{MacAddress: awssdk.String("cc:cc:cc:cc:cc:cc")}}},
				{NetworkInterfaces: []ec2types.InstanceNetworkInterface{{MacAddress: awssdk.String("dd:dd:dd:dd:dd:dd")}}},
			},
		},
	}
	rt := newTestSecurityHub(&fakeSecurityHub{}, ec2c, &fakeSTS{})

	keys := []struct{ id, mac string }{
		{"i-shared", "aa:aa:aa:aa:aa:aa"},
		{"i-2", "bb:bb:bb:bb:bb:bb"},
		{"i-3", "cc:cc:cc:cc:cc:cc"},
		{"i-4", "dd:dd:dd:dd:dd:dd"},
	}
	const want = "eu-west-1"

	const workers = 32
	var wg sync.WaitGroup
	for i := range workers {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			// Every worker hammers the shared key so same-key stores race; a
			// rotating distinct key exercises independent stores in parallel.
			if region, found, err := rt.findInstance(context.Background(), keys[0].id, keys[0].mac); err != nil || !found || region != want {
				t.Errorf("shared findInstance = (%q, %v, %v), want (%q, true, nil)", region, found, err, want)
			}
			k := keys[i%len(keys)]
			if region, found, err := rt.findInstance(context.Background(), k.id, k.mac); err != nil || !found || region != want {
				t.Errorf("distinct findInstance = (%q, %v, %v), want (%q, true, nil)", region, found, err, want)
			}
		}(i)
	}
	wg.Wait()
}

// benchRegions is a realistic commercial-partition region set for the confirm
// instance walk benchmark; the target instance sits in the last one so the walk
// probes every region (worst case, but also the shape a cache most helps).
var benchRegions = []string{
	"us-east-1", "us-east-2", "us-west-1", "us-west-2",
	"eu-west-1", "eu-west-2", "eu-west-3", "eu-central-1",
	"ap-south-1", "ap-northeast-1", "ap-northeast-2", "ap-southeast-1",
	"ap-southeast-2", "ca-central-1", "sa-east-1", "eu-north-1", "me-south-1",
}

// BenchmarkFindInstance measures the per-event cost of the confirm-instance
// region walk. The dominant, deployment-independent cost is the number of EC2
// DescribeInstances round-trips per lookup: the walk probes regions in order
// until a network-interface MAC matches, so an instance in a late region costs
// one call per enabled region on every event. A real fleet emits many
// detections from the same hosts, so the reported ec2calls/op is what a
// per-(instanceID+MAC) cache would collapse to near zero on repeat lookups.
func BenchmarkFindInstance(b *testing.B) {
	const targetRegion = "me-south-1"
	const mac = "0a:1b:2c:3d:4e:5f"
	ec2c := &fakeEC2{
		regions: benchRegions,
		byRegion: map[string][]ec2types.Instance{
			targetRegion: {{
				InstanceId: awssdk.String("i-123"),
				NetworkInterfaces: []ec2types.InstanceNetworkInterface{
					{MacAddress: awssdk.String(mac)},
				},
			}},
		},
	}
	rt := newTestSecurityHub(&fakeSecurityHub{}, ec2c, &fakeSTS{})
	ctx := context.Background()

	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		if _, _, err := rt.findInstance(ctx, "i-123", mac); err != nil {
			b.Fatalf("findInstance: %v", err)
		}
	}
	b.StopTimer()
	b.ReportMetric(float64(ec2c.describeCalls)/float64(b.N), "ec2calls/op")
}

func TestSecurityHubProcessImportsAWSFinding(t *testing.T) {
	t.Parallel()
	sh := &fakeSecurityHub{}
	rt := newTestSecurityHub(sh, &fakeEC2{}, &fakeSTS{account: "111122223333"})
	inner := map[string]any{
		"SeverityName":      "High",
		"DetectDescription": "malware detected",
		"DetectId":          "det-1",
		"FalconHostLink":    "https://falcon/host/1",
		"Tactic":            "Execution",
		"Technique":         "PowerShell",
		"FileName":          "evil.exe",
		"FilePath":          "C:\\temp\\evil.exe",
		"SHA256String":      "abcd",
		"NetworkAccesses": []any{map[string]any{
			"ConnectionDirection": float64(0),
			"Protocol":            "TCP",
			"LocalAddress":        "10.0.0.1",
			"LocalPort":           float64(1234),
			"RemoteAddress":       "8.8.8.8",
			"RemotePort":          float64(443),
		}},
	}
	host := &common.HostDetails{
		CloudProvider: "AWS",
		InstanceID:    "i-abc",
		SensorID:      "sensor-1",
	}
	ev := detectionEvent(&testutil.FakeEnricher{Host: host}, inner)

	if err := rt.Process(context.Background(), ev); err != nil {
		t.Fatalf("Process: %v", err)
	}
	if sh.importCalls != 1 {
		t.Fatalf("BatchImportFindings calls = %d, want 1", sh.importCalls)
	}
	f := sh.imported[0]
	if awssdk.ToString(f.AwsAccountId) != "111122223333" {
		t.Errorf("AwsAccountId = %q, want 111122223333", awssdk.ToString(f.AwsAccountId))
	}
	if awssdk.ToString(f.Id) != "crowdstrike:crowdstrike-falcon:det-1" {
		t.Errorf("Id = %q", awssdk.ToString(f.Id))
	}
	if !strings.HasPrefix(awssdk.ToString(f.Title), "Falcon Alert. Instance: i-abc") {
		t.Errorf("Title = %q", awssdk.ToString(f.Title))
	}
	if f.Severity == nil || f.Severity.Label != securityhubtypes.SeverityLabelHigh {
		t.Errorf("Severity.Label = %v, want HIGH", f.Severity)
	}
	if len(f.Resources) != 1 || awssdk.ToString(f.Resources[0].Type) != "AwsEc2Instance" {
		t.Errorf("Resources = %+v, want one AwsEc2Instance", f.Resources)
	}
	if awssdk.ToString(f.Resources[0].Region) != "us-east-1" {
		t.Errorf("Resource Region = %q, want us-east-1", awssdk.ToString(f.Resources[0].Region))
	}
	if f.ProductFields["crowdstrike/crowdstrike-falcon/cid"] != "cid-123" {
		t.Errorf("ProductFields cid = %q", f.ProductFields["crowdstrike/crowdstrike-falcon/cid"])
	}
	if f.ProductFields["crowdstrike/crowdstrike-falcon/FigVersion"] != "9.9.9" {
		t.Errorf("ProductFields FigVersion = %q", f.ProductFields["crowdstrike/crowdstrike-falcon/FigVersion"])
	}
	if f.ProductFields["crowdstrike/crowdstrike-falcon/FileName"] != "evil.exe" {
		t.Errorf("ProductFields FileName = %q", f.ProductFields["crowdstrike/crowdstrike-falcon/FileName"])
	}
	if len(f.Types) != 3 || f.Types[1] != "Category: Execution" || f.Types[2] != "Classifier: PowerShell" {
		t.Errorf("Types = %v", f.Types)
	}
	if f.Process == nil || awssdk.ToString(f.Process.Name) != "evil.exe" || awssdk.ToString(f.Process.Path) != "C:\\temp\\evil.exe" {
		t.Errorf("Process = %+v", f.Process)
	}
	if f.Network == nil || f.Network.Direction != securityhubtypes.NetworkDirectionIn {
		t.Errorf("Network.Direction = %v, want IN", f.Network)
	}
	if awssdk.ToString(f.Network.SourceIpV4) != "10.0.0.1" || awssdk.ToInt32(f.Network.SourcePort) != 1234 {
		t.Errorf("Network source = %q:%d", awssdk.ToString(f.Network.SourceIpV4), awssdk.ToInt32(f.Network.SourcePort))
	}
	if f.RecordState != securityhubtypes.RecordStateActive {
		t.Errorf("RecordState = %v, want ACTIVE", f.RecordState)
	}
}

func TestSecurityHubProcessDescriptionTruncated(t *testing.T) {
	t.Parallel()
	sh := &fakeSecurityHub{}
	rt := newTestSecurityHub(sh, &fakeEC2{}, &fakeSTS{account: "111122223333"})
	inner := map[string]any{
		"SeverityName":      "Low",
		"DetectDescription": strings.Repeat("x", 2000),
		"DetectId":          "det-2",
	}
	ev := detectionEvent(&testutil.FakeEnricher{Host: &common.HostDetails{CloudProvider: "AWS", InstanceID: "i-1"}}, inner)

	if err := rt.Process(context.Background(), ev); err != nil {
		t.Fatalf("Process: %v", err)
	}
	desc := awssdk.ToString(sh.imported[0].Description)
	if len(desc) != asffLimitDescription {
		t.Errorf("Description length = %d, want %d", len(desc), asffLimitDescription)
	}
	if !strings.HasSuffix(desc, "...") {
		t.Errorf("truncated Description should end with ..., got tail %q", desc[len(desc)-5:])
	}
}

// TestSecurityHubProcessPartialImportFails asserts that a BatchImportFindings
// response with FailedCount>0 surfaces as an error wrapping errPartialImport.
// Each batch carries a single finding, so a partial failure means the event was
// not stored: it must retry/drop rather than silently advance the watermark.
func TestSecurityHubProcessPartialImportFails(t *testing.T) {
	t.Parallel()
	sh := &fakeSecurityHub{failed: []securityhubtypes.ImportFindingsError{{
		Id:           awssdk.String("crowdstrike:crowdstrike-falcon:det-5"),
		ErrorCode:    awssdk.String("InvalidInput"),
		ErrorMessage: awssdk.String("resource id is malformed"),
	}}}
	rt := newTestSecurityHub(sh, &fakeEC2{}, &fakeSTS{account: "111122223333"})
	inner := map[string]any{"SeverityName": "High", "DetectId": "det-5"}
	ev := detectionEvent(&testutil.FakeEnricher{Host: &common.HostDetails{CloudProvider: "AWS", InstanceID: "i-5"}}, inner)

	err := rt.Process(context.Background(), ev)
	if err == nil {
		t.Fatal("Process: got nil error, want partial-import error")
	}
	if !errors.Is(err, errPartialImport) {
		t.Fatalf("Process error = %v, want it to wrap errPartialImport", err)
	}
	if sh.importCalls != 1 {
		t.Errorf("BatchImportFindings calls = %d, want 1", sh.importCalls)
	}
	// The rejected finding's details must survive into the error for the logs.
	if !strings.Contains(err.Error(), "resource id is malformed") || !strings.Contains(err.Error(), "InvalidInput") {
		t.Errorf("error missing failed-finding detail: %v", err)
	}
}

func TestSecurityHubProcessDedupSkip(t *testing.T) {
	t.Parallel()
	sh := &fakeSecurityHub{existing: []securityhubtypes.AwsSecurityFinding{{Id: awssdk.String("crowdstrike:crowdstrike-falcon:det-3")}}}
	rt := newTestSecurityHub(sh, &fakeEC2{}, &fakeSTS{account: "111122223333"})
	inner := map[string]any{"SeverityName": "High", "DetectId": "det-3"}
	ev := detectionEvent(&testutil.FakeEnricher{Host: &common.HostDetails{CloudProvider: "AWS", InstanceID: "i-1"}}, inner)

	if err := rt.Process(context.Background(), ev); err != nil {
		t.Fatalf("Process: %v", err)
	}
	if sh.importCalls != 0 {
		t.Errorf("BatchImportFindings calls = %d, want 0 (already present)", sh.importCalls)
	}
}

func TestSecurityHubAcceptAllNonAWSBypass(t *testing.T) {
	t.Parallel()
	sh := &fakeSecurityHub{}
	ec2c := &fakeEC2{}
	rt := newTestSecurityHub(sh, ec2c, &fakeSTS{account: "111122223333"})
	rt.acceptAllEvents = true
	rt.confirmInstance = true // must be bypassed for the non-AWS event

	inner := map[string]any{"SeverityName": "Medium", "DetectId": "det-4", "SensorId": "sensor-9"}
	host := &common.HostDetails{CloudProvider: "Azure", Hostname: "host-9"}
	ev := detectionEvent(&testutil.FakeEnricher{Host: host}, inner)

	if err := rt.Process(context.Background(), ev); err != nil {
		t.Fatalf("Process: %v", err)
	}
	if ec2c.regionsCalls != 0 {
		t.Errorf("DescribeRegions calls = %d, want 0 (confirmation bypassed)", ec2c.regionsCalls)
	}
	if sh.importCalls != 1 {
		t.Fatalf("BatchImportFindings calls = %d, want 1", sh.importCalls)
	}
	res := sh.imported[0].Resources[0]
	if awssdk.ToString(res.Type) != "Other" {
		t.Errorf("Resource Type = %q, want Other", awssdk.ToString(res.Type))
	}
	if awssdk.ToString(res.Id) != "sensor-9" {
		t.Errorf("Resource Id = %q, want sensor-9", awssdk.ToString(res.Id))
	}
	if res.Details == nil || res.Details.Other["CloudProvider"] != "Azure" {
		t.Errorf("Resource Details.Other = %+v, want CloudProvider Azure", res.Details)
	}
	if res.Details == nil || res.Details.Other["Hostname"] != "host-9" {
		t.Errorf("Resource Details.Other[Hostname] = %q, want host-9", res.Details.Other["Hostname"])
	}
}

func TestSecurityHubProcessConfirmInstanceNotFound(t *testing.T) {
	t.Parallel()
	sh := &fakeSecurityHub{}
	ec2c := &fakeEC2{regions: []string{"us-east-1"}} // no matching instance
	rt := newTestSecurityHub(sh, ec2c, &fakeSTS{account: "111122223333"})
	rt.confirmInstance = true

	inner := map[string]any{"SeverityName": "High", "DetectId": "det-5"}
	host := &common.HostDetails{CloudProvider: "AWS", InstanceID: "i-missing", MACAddress: "00:11:22:33:44:55"}
	ev := detectionEvent(&testutil.FakeEnricher{Host: host}, inner)

	if err := rt.Process(context.Background(), ev); err != nil {
		t.Fatalf("Process: %v", err)
	}
	if sh.importCalls != 0 {
		t.Errorf("BatchImportFindings calls = %d, want 0 (instance not found)", sh.importCalls)
	}
}

func TestSecurityHubProcessConfirmInstanceNoInstanceID(t *testing.T) {
	t.Parallel()
	sh := &fakeSecurityHub{}
	ec2c := &fakeEC2{regions: []string{"us-east-1"}}
	rt := newTestSecurityHub(sh, ec2c, &fakeSTS{account: "111122223333"})
	rt.confirmInstance = true

	inner := map[string]any{"SeverityName": "High", "DetectId": "det-6"}
	host := &common.HostDetails{CloudProvider: "AWS"} // no InstanceID to confirm
	ev := detectionEvent(&testutil.FakeEnricher{Host: host}, inner)

	if err := rt.Process(context.Background(), ev); err != nil {
		t.Fatalf("Process: %v", err)
	}
	if ec2c.regionsCalls != 0 {
		t.Errorf("DescribeRegions calls = %d, want 0 (no instance id to confirm)", ec2c.regionsCalls)
	}
	if sh.importCalls != 0 {
		t.Errorf("BatchImportFindings calls = %d, want 0 (alert not processed)", sh.importCalls)
	}
}

func TestSecurityHubProcessEnrichmentError(t *testing.T) {
	t.Parallel()
	sentinel := errors.New("enrich boom")
	rt := newTestSecurityHub(&fakeSecurityHub{}, &fakeEC2{}, &fakeSTS{})
	ev := detectionEvent(&testutil.FakeEnricher{HostErr: sentinel}, nil)

	err := rt.Process(context.Background(), ev)
	if !errors.Is(err, sentinel) {
		t.Fatalf("Process error = %v, want it to wrap the enrichment failure", err)
	}
}

func TestSecurityHubMetadata(t *testing.T) {
	t.Parallel()
	rt := newTestSecurityHub(&fakeSecurityHub{}, &fakeEC2{}, &fakeSTS{})
	if rt.Name() != "AWS" {
		t.Errorf("Name = %q, want AWS", rt.Name())
	}
	types := rt.RelevantEventTypes()
	if len(types) != 1 || types[0] != "EppDetectionSummaryEvent" {
		t.Errorf("RelevantEventTypes = %v, want [EppDetectionSummaryEvent]", types)
	}
}

// TestSecurityHubAccountIDCachedAcrossEvents verifies the STS account id is
// resolved once and reused for subsequent events rather than fetched per event.
func TestSecurityHubAccountIDCachedAcrossEvents(t *testing.T) {
	t.Parallel()
	sh := &fakeSecurityHub{}
	stsc := &fakeSTS{account: "111122223333"}
	rt := newTestSecurityHub(sh, &fakeEC2{}, stsc)
	host := &common.HostDetails{CloudProvider: "AWS", InstanceID: "i-abc"}

	for i := range 3 {
		inner := map[string]any{"SeverityName": "High", "DetectId": "det-cache"}
		ev := detectionEvent(&testutil.FakeEnricher{Host: host}, inner)
		if err := rt.Process(context.Background(), ev); err != nil {
			t.Fatalf("Process #%d: %v", i, err)
		}
	}
	if stsc.calls != 1 {
		t.Errorf("GetCallerIdentity calls = %d, want 1 (account id must be cached)", stsc.calls)
	}
	for _, f := range sh.imported {
		if awssdk.ToString(f.AwsAccountId) != "111122223333" {
			t.Errorf("AwsAccountId = %q, want 111122223333", awssdk.ToString(f.AwsAccountId))
		}
	}
}

// TestSecurityHubAccountIDNotLatchedOnError verifies a failed STS lookup is not
// cached: a transient failure is retried on the next event and can then succeed.
func TestSecurityHubAccountIDNotLatchedOnError(t *testing.T) {
	t.Parallel()
	sh := &fakeSecurityHub{}
	stsc := &fakeSTS{err: errors.New("sts unavailable")}
	rt := newTestSecurityHub(sh, &fakeEC2{}, stsc)
	host := &common.HostDetails{CloudProvider: "AWS", InstanceID: "i-abc"}

	ev := detectionEvent(&testutil.FakeEnricher{Host: host}, map[string]any{"SeverityName": "High", "DetectId": "det-1"})
	if err := rt.Process(context.Background(), ev); err == nil {
		t.Fatal("Process = nil, want the STS failure surfaced")
	}
	if sh.importCalls != 0 {
		t.Errorf("BatchImportFindings calls = %d, want 0 when account id is unresolved", sh.importCalls)
	}

	stsc.err = nil
	stsc.account = "111122223333"
	ev = detectionEvent(&testutil.FakeEnricher{Host: host}, map[string]any{"SeverityName": "High", "DetectId": "det-2"})
	if err := rt.Process(context.Background(), ev); err != nil {
		t.Fatalf("Process after recovery: %v", err)
	}
	if stsc.calls != 2 {
		t.Errorf("GetCallerIdentity calls = %d, want 2 (failure not latched)", stsc.calls)
	}
	if awssdk.ToString(sh.imported[0].AwsAccountId) != "111122223333" {
		t.Errorf("AwsAccountId = %q, want 111122223333", awssdk.ToString(sh.imported[0].AwsAccountId))
	}
}
