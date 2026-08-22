package gcp

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	compute "google.golang.org/api/compute/v1"
	"google.golang.org/api/googleapi"

	"github.com/crowdstrike/falcon-integration-gateway/internal/utils"
)

const (
	// defaultAssetLookupMaxRetries bounds how many times a rate-limited (HTTP 429)
	// compute lookup is retried before it is surfaced as a delivery failure.
	defaultAssetLookupMaxRetries = 4
	// defaultAssetLookupBaseBackoff is the first-retry wait used when the server
	// sends no Retry-After header; it doubles each attempt up to maxBackoff.
	defaultAssetLookupBaseBackoff = 1 * time.Second
	// defaultAssetLookupMaxBackoff caps any single inter-retry wait, including a
	// server-supplied Retry-After.
	defaultAssetLookupMaxBackoff = 30 * time.Second
	// filterIgnoredScanBound caps how many instances aggregatedList scans before
	// concluding the server-side id filter was not applied. A working "id="
	// filter returns at most one instance (a numeric id is unique within a
	// project), so scanning far more than that means the filter was dropped and
	// the whole fleet is streaming back. Rather than let that unmatched flood
	// masquerade as a genuine not-found — which would silently drop the detection
	// — the scan is abandoned with errFilterIgnored so the lookup fails loudly.
	filterIgnoredScanBound = 100
)

// errStopPaging halts aggregatedList pagination once the target instance has
// been found. It never escapes resolveInstance: the caller treats it as a
// normal end-of-results.
var errStopPaging = errors.New("gcp: stop paging")

// errFilterIgnored is returned when aggregatedList scans past
// filterIgnoredScanBound instances without a match, indicating the server-side
// id filter was not applied. It is surfaced as an ordinary lookup error so the
// delivery-failure policy engages, rather than being reported as a not-found
// that would drop the event.
var errFilterIgnored = errors.New("gcp: aggregatedList id filter appears to be ignored")

// computeResolver resolves a compute instance's SCC resource name by numeric id
// through the Compute Engine aggregatedList API with a server-side id filter,
// scoped to one project. Unlike a full inventory enumeration this is a point
// lookup: the filter returns only the instance whose numeric id matches, so a
// healthy call yields at most one instance and the per-event cost stays flat as
// a project's fleet grows.
//
// A rate-limit response (HTTP 429) is retried in place with a Retry-After-aware
// backoff rather than surfaced immediately: under quota pressure the retry
// parks the calling worker, throttling the lookup rate instead of amplifying it.
type computeResolver struct {
	svc         *compute.Service
	maxRetries  int
	baseBackoff time.Duration
	maxBackoff  time.Duration
}

var _ assetResolver = (*computeResolver)(nil)

// newComputeResolver builds a computeResolver with the default rate-limit
// backoff parameters.
func newComputeResolver(svc *compute.Service) *computeResolver {
	return &computeResolver{
		svc:         svc,
		maxRetries:  defaultAssetLookupMaxRetries,
		baseBackoff: defaultAssetLookupBaseBackoff,
		maxBackoff:  defaultAssetLookupMaxBackoff,
	}
}

// resolveInstance returns the SCC resource name of every compute instance in
// projectNumber whose numeric id equals instanceID. A GCE numeric id is unique
// within a project, so the healthy result is zero or one name; the caller maps
// the count to the not-found / ambiguous outcomes. The server-side filter is
// authoritative, but each returned instance is still verified against instanceID
// so a silently-ignored filter fails loudly (errFilterIgnored) once the scan
// runs past a sane bound, rather than reporting the resulting flood as a
// spurious not-found.
//
// A permission denial (HTTP 403) is translated to ErrAssetPermissionDenied so
// the caller can drop the event and let it self-heal once the grant lands,
// rather than treating a fixable IAM gap as a delivery failure. A rate-limit
// (HTTP 429) is retried with a bounded Retry-After-aware backoff; once retries
// are exhausted it is surfaced as an ordinary error for the delivery-failure
// policy.
func (r *computeResolver) resolveInstance(ctx context.Context, projectNumber, instanceID string) ([]string, error) {
	for attempt := 0; ; attempt++ {
		names, err := r.aggregatedList(ctx, projectNumber, instanceID)
		if err == nil {
			return names, nil
		}
		if isPermissionDenied(err) {
			return nil, fmt.Errorf("%w (instance %s in project %s): %w", ErrAssetPermissionDenied, instanceID, projectNumber, err)
		}
		if isRateLimited(err) && attempt < r.maxRetries {
			if !utils.Sleep(ctx, r.backoff(err, attempt)) {
				return nil, fmt.Errorf("gcp: rate-limited looking up compute instance %s in project %s: %w", instanceID, projectNumber, ctx.Err())
			}
			continue
		}
		return nil, fmt.Errorf("gcp: listing compute instance %s in project %s: %w", instanceID, projectNumber, err)
	}
}

// aggregatedList runs the filtered aggregatedList lookup and returns the
// resource names of the matching instances. It trusts the server-side "id="
// filter: a numeric id is unique within a project, so the healthy result is at
// most one instance and the walk stops (errStopPaging) as soon as a match is
// collected on a page. ReturnPartialSuccess keeps a transient per-scope error
// (an unreachable zone, or a scope the service account cannot list) from
// failing the whole call.
//
// Because a working filter returns almost nothing, a scan that runs past
// filterIgnoredScanBound without a match means the filter was dropped and the
// whole fleet is streaming back. That is reported as errFilterIgnored — a loud
// lookup error — rather than an empty result, so it cannot masquerade as a
// genuine not-found and silently drop the detection.
func (r *computeResolver) aggregatedList(ctx context.Context, projectNumber, instanceID string) ([]string, error) {
	var names []string
	scanned := 0
	call := r.svc.Instances.AggregatedList(projectNumber).
		Filter("id=" + instanceID).
		ReturnPartialSuccess(true)
	err := call.Pages(ctx, func(page *compute.InstanceAggregatedList) error {
		for _, scoped := range page.Items {
			for _, inst := range scoped.Instances {
				scanned++
				if strconv.FormatUint(inst.Id, 10) == instanceID {
					names = append(names, instanceResourceName(inst))
				}
			}
		}
		if len(names) > 0 {
			return errStopPaging
		}
		if scanned > filterIgnoredScanBound {
			return errFilterIgnored
		}
		return nil
	})
	if err != nil && !errors.Is(err, errStopPaging) {
		return nil, err
	}
	return names, nil
}

// backoff is the wait before the given rate-limit retry attempt. A valid server
// Retry-After takes precedence (clamped to maxBackoff; a zero means retry
// immediately); otherwise the base delay doubles per attempt, also clamped. A
// non-positive shifted value (overflow) collapses to maxBackoff.
func (r *computeResolver) backoff(err error, attempt int) time.Duration {
	if d, ok := retryAfter(err); ok {
		if d > r.maxBackoff {
			return r.maxBackoff
		}
		return d
	}
	if d := r.baseBackoff << attempt; d > 0 && d <= r.maxBackoff {
		return d
	}
	return r.maxBackoff
}

// instanceResourceName builds the Security Command Center full resource name for
// a compute instance by rewriting the instance's server-defined self link into
// the //compute.googleapis.com/... form SCC findings reference. The self link is
// the instance's canonical URL
// (https://www.googleapis.com/compute/v1/projects/{id}/zones/{zone}/instances/{name}),
// and SCC derives its resource name from that same representation, so swapping the
// self link's scheme, host, and API-version prefix for the SCC host yields exactly
// the name SCC uses. This is why the numeric project number the lookup is scoped
// by is not used to build the name: SCC keys the resource on the project id
// carried by the self link, not the number Falcon supplies.
//
// A self link is expected on every aggregatedList result; if one is absent the
// zone URL carries the same project id and zone, so the name is rebuilt from it
// plus the instance name.
func instanceResourceName(inst *compute.Instance) string {
	const host = "//compute.googleapis.com"
	if p := computeResourcePath(inst.SelfLink); p != "" {
		return host + p
	}
	return host + computeResourcePath(inst.Zone) + "/instances/" + inst.Name
}

// computeResourcePath returns the "/projects/…"-onward path of a server-defined
// Compute Engine URL (a self link or zone URL), stripping the scheme, host, and
// API-version prefix that vary between API versions. It returns "" when the URL
// carries no such segment.
func computeResourcePath(u string) string {
	if i := strings.Index(u, "/projects/"); i >= 0 {
		return u[i:]
	}
	return ""
}

// isPermissionDenied reports whether err is a Compute Engine authorization
// failure (HTTP 403). The compute client is a REST client, so a denial arrives
// as a *googleapi.Error rather than a gRPC status.
func isPermissionDenied(err error) bool {
	if gerr, ok := errors.AsType[*googleapi.Error](err); ok {
		return gerr.Code == http.StatusForbidden
	}
	return false
}

// isRateLimited reports whether err is a Compute Engine rate-limit / quota
// response (HTTP 429). Like isPermissionDenied it inspects the REST
// *googleapi.Error.
func isRateLimited(err error) bool {
	if gerr, ok := errors.AsType[*googleapi.Error](err); ok {
		return gerr.Code == http.StatusTooManyRequests
	}
	return false
}

// retryAfter extracts a Retry-After delay from a *googleapi.Error, supporting
// both the delta-seconds and HTTP-date forms. It reports ok=false when err is
// not a googleapi error, the header is absent, or the value cannot be parsed.
func retryAfter(err error) (time.Duration, bool) {
	gerr, ok := errors.AsType[*googleapi.Error](err)
	if !ok {
		return 0, false
	}
	v := gerr.Header.Get("Retry-After")
	if v == "" {
		return 0, false
	}
	if secs, e := strconv.Atoi(v); e == nil {
		if secs < 0 {
			return 0, false
		}
		return time.Duration(secs) * time.Second, true
	}
	if t, e := http.ParseTime(v); e == nil {
		if d := time.Until(t); d > 0 {
			return d, true
		}
		return 0, true
	}
	return 0, false
}
