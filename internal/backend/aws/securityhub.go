// Package aws implements the AWS backend family — Security Hub ("AWS"), SQS
// ("AWS_SQS"), and CloudTrail Lake ("CLOUDTRAIL_LAKE") — plus the two AWS-SDK
// pieces they share: the SDK configuration path and the Falcon credential-store
// loaders.
//
// The SDK's own module is imported under the awssdk alias throughout this
// package so the names do not collide with this package's own name.
package aws

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"strings"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/securityhub"
	securityhubtypes "github.com/aws/aws-sdk-go-v2/service/securityhub/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"

	"github.com/crowdstrike/falcon-integration-gateway/internal/backend"
	"github.com/crowdstrike/falcon-integration-gateway/internal/cache"
	"github.com/crowdstrike/falcon-integration-gateway/internal/common"
	"github.com/crowdstrike/falcon-integration-gateway/internal/config"
	"github.com/crowdstrike/falcon-integration-gateway/internal/events"
	"github.com/crowdstrike/falcon-integration-gateway/internal/utils"
	"github.com/crowdstrike/falcon-integration-gateway/internal/version"
)

// ASFF field length limits. Values longer than these are truncated with a
// trailing ellipsis before submission so Security Hub does not reject the
// finding.
const (
	asffLimitTitle          = 256
	asffLimitDescription    = 1024
	asffLimitProcessName    = 64
	asffLimitProcessPath    = 512
	asffLimitProductField   = 2048
	asffLimitResourceDetail = 1024
)

// securityHubAPI is the subset of the Security Hub client the backend needs.
// Each method takes the variadic options so a per-region override can be applied
// per call and tests can inject a fake.
type securityHubAPI interface {
	GetFindings(ctx context.Context, in *securityhub.GetFindingsInput, optFns ...func(*securityhub.Options)) (*securityhub.GetFindingsOutput, error)
	BatchImportFindings(ctx context.Context, in *securityhub.BatchImportFindingsInput, optFns ...func(*securityhub.Options)) (*securityhub.BatchImportFindingsOutput, error)
}

// ec2API is the subset of the EC2 client used to confirm an instance by walking
// regions and matching a network-interface MAC address.
type ec2API interface {
	DescribeRegions(ctx context.Context, in *ec2.DescribeRegionsInput, optFns ...func(*ec2.Options)) (*ec2.DescribeRegionsOutput, error)
	DescribeInstances(ctx context.Context, in *ec2.DescribeInstancesInput, optFns ...func(*ec2.Options)) (*ec2.DescribeInstancesOutput, error)
}

// stsAPI is the subset of the STS client used to resolve the account id that
// owns the findings.
type stsAPI interface {
	GetCallerIdentity(ctx context.Context, in *sts.GetCallerIdentityInput, optFns ...func(*sts.Options)) (*sts.GetCallerIdentityOutput, error)
}

// securityHub forwards Falcon detection events into AWS Security Hub as ASFF
// findings.
type securityHub struct {
	logger          *slog.Logger
	sh              securityHubAPI
	ec2             ec2API
	sts             stsAPI
	region          string
	confirmInstance bool
	acceptAllEvents bool
	figVersion      string

	// regions memoizes the region hosting a confirmed (instanceID, MAC) pair so
	// repeat events for the same host skip the region walk. It is bounded with
	// FIFO eviction; the pair→region mapping is immutable, so evicting a
	// still-in-use entry only costs a correct re-walk, never a wrong region.
	regions *cache.Cache[string, string]
	// account memoizes the STS-resolved account id that owns the findings. The id
	// is fixed for the process lifetime, so it is resolved once under a single key
	// and reused; a failed lookup is not cached and is retried on the next event.
	account *cache.Cache[string, string]
}

// defaultRegionCacheSize bounds the confirm-instance region cache. The
// instance→region mapping is immutable, so entries are genuinely reused across
// events; a churning fleet is bounded with insertion-order (FIFO) eviction.
// Overflow costs only a correct re-walk, never a wrong region.
const defaultRegionCacheSize = 4096

// newSecurityHub is the backend.Constructor. It builds the Security Hub, EC2,
// and STS clients from the ambient AWS config. The one-time startup work uses a
// background context because the constructor signature has no context to thread.
func newSecurityHub(cfg *config.Config, logger *slog.Logger) (backend.Backend, error) {
	ctx := context.Background()
	awsCfg, err := loadConfig(ctx, cfg.AWS.Region)
	if err != nil {
		return nil, err
	}
	logger.Info("AWS Security Hub Backend is enabled.", "region", cfg.AWS.Region)
	return &securityHub{
		logger:          logger,
		sh:              securityhub.NewFromConfig(awsCfg),
		ec2:             ec2.NewFromConfig(awsCfg),
		sts:             sts.NewFromConfig(awsCfg),
		region:          cfg.AWS.Region,
		confirmInstance: cfg.AWS.ConfirmInstance,
		acceptAllEvents: cfg.AWS.AcceptAllEvents,
		figVersion:      version.Version,
		regions:         cache.New[string, string](defaultRegionCacheSize),
		account:         cache.New[string, string](0),
	}, nil
}

// Name returns the backend registry name.
func (s *securityHub) Name() string {
	return "AWS"
}

// RelevantEventTypes narrows the stream to endpoint detection summaries.
func (s *securityHub) RelevantEventTypes() []string {
	return []string{events.EppDetectionSummaryEventType}
}

// IsRelevant accepts every event when acceptAllEvents is set, and otherwise only
// events whose host resolved to an AWS cloud provider. When enrichment fails the
// cloud provider cannot be read, so it accepts the event and lets Process surface
// the error to the delivery-failure policy rather than silently dropping it.
func (s *securityHub) IsRelevant(ctx context.Context, ev *events.EnrichedEvent) bool {
	if s.acceptAllEvents {
		return true
	}
	return events.MatchesProvider(ctx, ev, isAWSProvider)
}

// Process resolves host details, optionally confirms the backing EC2 instance,
// builds the ASFF finding, and imports it into Security Hub (skipping the import
// when a finding with the same id already exists).
func (s *securityHub) Process(ctx context.Context, ev *events.EnrichedEvent) error {
	host, err := ev.Host(ctx)
	if err != nil {
		return fmt.Errorf("aws security hub: resolving host details: %w", err)
	}
	isAWS := isAWSProvider(host.CloudProvider)

	detRegion := s.region
	switch {
	case s.acceptAllEvents && !isAWS:
		// Forward non-AWS events without instance confirmation.
	case s.confirmInstance:
		if host.InstanceID == "" {
			s.logger.Info("instance id not provided by detection; alert not processed", "event", ev.UID())
			return nil
		}
		region, found, err := s.findInstance(ctx, host.InstanceID, host.MACAddress)
		if err != nil {
			return fmt.Errorf("aws security hub: confirming instance %q: %w", host.InstanceID, err)
		}
		if !found {
			s.logger.Warn("instance not found in any region; not forwarding", "instance_id", host.InstanceID, "event", ev.UID())
			return nil
		}
		detRegion = region
	default:
		// Standard path: forward to the configured region.
	}

	finding, err := s.createPayload(ctx, ev, host, detRegion, isAWS)
	if err != nil {
		return err
	}
	return s.sendToSecurityHub(ctx, finding, detRegion)
}

// errRegionNotFound signals that the region walk matched no instance. It keeps a
// not-found result out of the region cache — the cache does not memoize load
// errors — while findInstance translates it back to a found=false result.
var errRegionNotFound = errors.New("aws security hub: instance not found in any region")

// accountCacheKey is the single fixed key under which the process-wide AWS
// account id is memoized.
const accountCacheKey = "account"

// findInstance returns the region hosting the instance whose network-interface
// MAC matches macAddress. A found (instanceID, MAC) pair is memoized so repeat
// events for the same host skip the region walk entirely; a not-found result is
// not cached, so an instance that appears later is still discovered. The cache
// key is instanceID plus the normalized MAC. For a given key the region is
// immutable, so a cached answer always matches what a fresh walk would find —
// including the walk's first-match order in the unlikely event more than one
// region reports the same pair.
func (s *securityHub) findInstance(ctx context.Context, instanceID, macAddress string) (string, bool, error) {
	target := normalizeMAC(macAddress)
	key := instanceID + "|" + target
	region, err := s.regions.Get(ctx, key, func(ctx context.Context) (string, error) {
		region, found, err := s.walkRegionsForMAC(ctx, instanceID, target)
		if err != nil {
			return "", err
		}
		if !found {
			return "", errRegionNotFound
		}
		return region, nil
	})
	switch {
	case errors.Is(err, errRegionNotFound):
		return s.region, false, nil
	case err != nil:
		return "", false, err
	default:
		return region, true, nil
	}
}

// walkRegionsForMAC walks every enabled region looking for the instance whose
// network interface MAC (already normalized) matches target, returning the region
// it was found in. Per-region DescribeInstances errors are skipped (the instance
// simply is not in that region); only a DescribeRegions failure is fatal. When no
// interface matches it returns the configured region and found=false.
func (s *securityHub) walkRegionsForMAC(ctx context.Context, instanceID, target string) (string, bool, error) {
	regionsOut, err := s.ec2.DescribeRegions(ctx, &ec2.DescribeRegionsInput{})
	if err != nil {
		return "", false, fmt.Errorf("describing regions: %w", err)
	}
	for _, r := range regionsOut.Regions {
		region := awssdk.ToString(r.RegionName)
		out, err := s.ec2.DescribeInstances(ctx, &ec2.DescribeInstancesInput{
			InstanceIds: []string{instanceID},
		}, func(o *ec2.Options) { o.Region = region })
		if err != nil {
			// A cancelled or timed-out context is not "the instance is not in
			// this region"; it means the caller is shutting down, so abandon
			// the walk rather than hammering every remaining region.
			if utils.IsCanceled(err) {
				return "", false, fmt.Errorf("describing instances in %s: %w", region, err)
			}
			continue
		}
		for _, res := range out.Reservations {
			for _, inst := range res.Instances {
				for _, iface := range inst.NetworkInterfaces {
					if normalizeMAC(awssdk.ToString(iface.MacAddress)) == target {
						return region, true, nil
					}
				}
			}
		}
	}
	return s.region, false, nil
}

// resolveAccountID returns the AWS account id that owns the findings. The value
// is fixed for the life of the process, so it is resolved via STS on the first
// event and memoized; subsequent events reuse the cached id instead of making a
// per-event GetCallerIdentity call. Only a successful lookup is cached, so a
// transient STS failure is retried on the next event rather than latched.
func (s *securityHub) resolveAccountID(ctx context.Context) (string, error) {
	return s.account.Get(ctx, accountCacheKey, func(ctx context.Context) (string, error) {
		idOut, err := s.sts.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{}, func(o *sts.Options) { o.Region = s.region })
		if err != nil {
			return "", fmt.Errorf("aws security hub: resolving account id: %w", err)
		}
		return awssdk.ToString(idOut.Account), nil
	})
}

// createPayload builds the ASFF finding for one detection event. instanceRegion
// is the region reported on the resource; the product ARN and account lookup use
// the configured region.
func (s *securityHub) createPayload(ctx context.Context, ev *events.EnrichedEvent, host *common.HostDetails, instanceRegion string, isAWS bool) (securityhubtypes.AwsSecurityFinding, error) {
	account, err := s.resolveAccountID(ctx)
	if err != nil {
		return securityhubtypes.AwsSecurityFinding{}, err
	}

	fields := ev.Event.Event
	severityName := ev.SeverityName()

	resType, resID, titleSuffix, other := s.resourceInfo(ev, host, isAWS)

	resource := securityhubtypes.Resource{
		Type:   awssdk.String(resType),
		Id:     awssdk.String(resID),
		Region: awssdk.String(instanceRegion),
	}
	if len(other) > 0 {
		resource.Details = &securityhubtypes.ResourceDetails{Other: other}
	}

	now := time.Now().UTC()
	finding := securityhubtypes.AwsSecurityFinding{
		SchemaVersion: awssdk.String("2018-10-08"),
		Id:            awssdk.String("crowdstrike:crowdstrike-falcon:" + ev.EventID()),
		ProductArn:    awssdk.String(productARN(s.region)),
		GeneratorId:   awssdk.String("Falcon Host"),
		AwsAccountId:  awssdk.String(account),
		CreatedAt:     awssdk.String(ev.CreationTime().Format(time.RFC3339Nano)),
		UpdatedAt:     awssdk.String(now.Format(time.RFC3339Nano)),
		RecordState:   securityhubtypes.RecordStateActive,
		SourceUrl:     awssdk.String(ev.FalconLink()),
		Severity: &securityhubtypes.Severity{
			Label:    securityhubtypes.SeverityLabel(strings.ToUpper(severityName)),
			Original: awssdk.String(severityName),
		},
		Title:         awssdk.String(truncateField("Falcon Alert. "+titleSuffix, asffLimitTitle)),
		Description:   awssdk.String(truncateField(ev.DetectDescription()+" "+cloudAccountInfo(host), asffLimitDescription)),
		ProductFields: buildProductFields(fields, ev.CID(), s.figVersion),
		Resources:     []securityhubtypes.Resource{resource},
	}

	if tactic, technique := ttps(fields); tactic != "" && technique != "" {
		finding.Types = []string{"Namespace: TTPs", "Category: " + tactic, "Classifier: " + technique}
	}
	if name := mapString(fields, "FileName"); name != "" {
		if path := mapString(fields, "FilePath"); path != "" {
			finding.Process = &securityhubtypes.ProcessDetails{
				Name: awssdk.String(truncateField(name, asffLimitProcessName)),
				Path: awssdk.String(truncateField(path, asffLimitProcessPath)),
			}
		}
	}
	if net := networkPayload(fields); net != nil {
		finding.Network = net
	}
	return finding, nil
}

// resourceInfo derives the ASFF resource type, id, title suffix, and (for
// non-AWS hosts) the enhanced resource-details map. AWS hosts map to an
// AwsEc2Instance resource keyed by instance id; other hosts map to an Other
// resource keyed by sensor id with the full host projection attached.
func (s *securityHub) resourceInfo(ev *events.EnrichedEvent, host *common.HostDetails, isAWS bool) (resType, resID, titleSuffix string, other map[string]string) {
	if isAWS {
		resID = host.InstanceID
		if resID == "" {
			resID = "UnknownInstanceId:" + ev.EventID()
		}
		return "AwsEc2Instance", resID, "Instance: " + resID, nil
	}
	resID = ev.SensorID()
	if host.CloudProvider != "" {
		titleSuffix = host.CloudProvider + " Host: " + resID
	} else {
		titleSuffix = "Host: " + resID
	}
	return "Other", resID, titleSuffix, enhancedResourceDetails(host)
}

// sendToSecurityHub imports the finding, first checking whether a finding with
// the same id already exists so a restart does not re-import. A GetFindings error
// is treated as "not present" and the import proceeds. The region is applied per
// call so a confirmed instance's region is honored.
func (s *securityHub) sendToSecurityHub(ctx context.Context, finding securityhubtypes.AwsSecurityFinding, region string) error {
	optFn := func(o *securityhub.Options) { o.Region = region }
	id := awssdk.ToString(finding.Id)

	out, err := s.sh.GetFindings(ctx, &securityhub.GetFindingsInput{
		Filters: &securityhubtypes.AwsSecurityFindingFilters{
			Id: []securityhubtypes.StringFilter{{
				Value:      awssdk.String(id),
				Comparison: securityhubtypes.StringFilterComparisonEquals,
			}},
		},
	}, optFn)
	if err == nil && out != nil && len(out.Findings) > 0 {
		s.logger.Info("finding already present in Security Hub; skipping import", "id", id)
		return nil
	}

	resp, err := s.sh.BatchImportFindings(ctx, &securityhub.BatchImportFindingsInput{
		Findings: []securityhubtypes.AwsSecurityFinding{finding},
	}, optFn)
	if err != nil {
		return fmt.Errorf("aws security hub: importing finding %q: %w", id, err)
	}
	if resp != nil && resp.FailedCount != nil && *resp.FailedCount > 0 {
		return fmt.Errorf("aws security hub: importing finding %q: %w", id, failedImportError(resp.FailedFindings))
	}
	return nil
}

// errPartialImport reports that BatchImportFindings accepted the request but
// rejected one or more findings (FailedCount > 0). Because each batch carries a
// single finding, this means the event was not stored and must be retried rather
// than silently dropped.
var errPartialImport = errors.New("aws security hub: batch import reported failed findings")

// failedImportError summarizes the per-finding rejections into an error that
// wraps errPartialImport, preserving each finding's id, error code, and message
// for the retry/drop logs.
func failedImportError(failed []securityhubtypes.ImportFindingsError) error {
	details := make([]string, 0, len(failed))
	for _, f := range failed {
		details = append(details, fmt.Sprintf("%s: %s (%s)",
			awssdk.ToString(f.Id), awssdk.ToString(f.ErrorMessage), awssdk.ToString(f.ErrorCode)))
	}
	return fmt.Errorf("%w: %s", errPartialImport, strings.Join(details, "; "))
}

// buildProductFields renders the crowdstrike/crowdstrike-falcon/* product field
// map: the customer id and gateway version, the flat detection attributes present
// on the event, and up to five MITRE ATT&CK entries.
func buildProductFields(fields map[string]any, cid, figVersion string) map[string]string {
	const prefix = "crowdstrike/crowdstrike-falcon/"
	pf := map[string]string{
		prefix + "cid":        cid,
		prefix + "FigVersion": figVersion,
	}
	targets := []string{
		"FileName", "FilePath", "SHA256String", "SHA1String", "MD5String",
		"CommandLine", "ParentImageFileName", "ParentCommandLine",
		"GrandParentImageFileName", "GrandParentCommandLine", "IOCType",
		"IOCValue", "AssociatedFile", "PatternDispositionDescription",
		"Tactic", "Technique", "Objective",
	}
	for _, f := range targets {
		if v, ok := fields[f]; ok {
			pf[prefix+f] = truncateField(anyToString(v), asffLimitProductField)
		}
	}
	if mitre, ok := fields["MitreAttack"].([]any); ok {
		keys := []string{"Tactic", "TacticID", "Technique", "TechniqueID", "PatternID"}
		for i, entry := range mitre {
			if i >= 5 {
				break
			}
			m, ok := entry.(map[string]any)
			if !ok {
				continue
			}
			for _, k := range keys {
				if v, ok := m[k]; ok {
					pf[fmt.Sprintf("%sMitreAttack/%d/%s", prefix, i, k)] = truncateField(anyToString(v), asffLimitProductField)
				}
			}
		}
	}
	return pf
}

// enhancedResourceDetails builds the ASFF resource "Other" map from the host
// projection, including only fields that resolved to a non-empty value and
// truncating each to the resource-detail limit.
func enhancedResourceDetails(host *common.HostDetails) map[string]string {
	other := map[string]string{}
	add := func(key, val string) {
		if val != "" {
			other[key] = truncateField(val, asffLimitResourceDetail)
		}
	}
	add("Hostname", host.Hostname)
	add("AID", host.DeviceID)
	add("Platform", host.Platform)
	add("ExternalIP", host.ExternalIP)
	add("LocalIP", host.LocalIP)
	add("MACAddress", host.MACAddress)
	add("Domain", host.MachineDomain)
	add("AgentVersion", host.AgentVersion)
	add("LastSeenTimestamp", host.LastSeen)
	add("OSVersion", host.OSVersion)
	if len(host.Tags) > 0 {
		add("DeviceTags", strings.Join(host.Tags, ", "))
	}
	add("SiteName", host.SiteName)
	if len(host.OU) > 0 {
		add("OrganizationalUnit", strings.Join(host.OU, ", "))
	}
	add("CloudProvider", host.CloudProvider)
	add("CloudAccountId", host.CloudProviderAccountID)
	add("InstanceId", host.InstanceID)
	return other
}

// networkPayload builds the ASFF Network object from the first NetworkAccesses
// entry, or nil when the event carries no network access details.
func networkPayload(fields map[string]any) *securityhubtypes.Network {
	accesses, ok := fields["NetworkAccesses"].([]any)
	if !ok || len(accesses) == 0 {
		return nil
	}
	na, ok := accesses[0].(map[string]any)
	if !ok {
		return nil
	}
	direction := securityhubtypes.NetworkDirectionOut
	if utils.IntFromAny(na["ConnectionDirection"]) == 0 {
		direction = securityhubtypes.NetworkDirectionIn
	}
	return &securityhubtypes.Network{
		Direction:       direction,
		Protocol:        awssdk.String(mapString(na, "Protocol")),
		SourceIpV4:      awssdk.String(mapString(na, "LocalAddress")),
		SourcePort:      awssdk.Int32(int32FromAny(na["LocalPort"])),
		DestinationIpV4: awssdk.String(mapString(na, "RemoteAddress")),
		DestinationPort: awssdk.Int32(int32FromAny(na["RemotePort"])),
	}
}

// cloudAccountInfo renders the "| <provider> Account: <id>" suffix appended to
// the finding description, or "" when no cloud account id resolved.
func cloudAccountInfo(host *common.HostDetails) string {
	if host.CloudProviderAccountID == "" {
		return ""
	}
	provider := host.CloudProvider
	if provider == "" {
		provider = "Cloud"
	}
	return fmt.Sprintf("| %s Account: %s", provider, host.CloudProviderAccountID)
}

// ttps resolves the tactic and technique for the finding Types, preferring the
// flat event fields and falling back to the first MITRE ATT&CK entry.
func ttps(fields map[string]any) (tactic, technique string) {
	tactic = mapString(fields, "Tactic")
	technique = mapString(fields, "Technique")
	if tactic != "" && technique != "" {
		return tactic, technique
	}
	mitre, ok := fields["MitreAttack"].([]any)
	if !ok || len(mitre) == 0 {
		return tactic, technique
	}
	m, ok := mitre[0].(map[string]any)
	if !ok {
		return tactic, technique
	}
	if tactic == "" {
		tactic = mapString(m, "Tactic")
	}
	if technique == "" {
		technique = mapString(m, "Technique")
	}
	return tactic, technique
}

// productARN returns the CrowdStrike Falcon Security Hub product ARN for the
// region, selecting the GovCloud partition and account when the region is a
// GovCloud region.
func productARN(region string) string {
	if strings.Contains(region, "gov") {
		return fmt.Sprintf("arn:aws-us-gov:securityhub:%s:358431324613:product/crowdstrike/crowdstrike-falcon", region)
	}
	return fmt.Sprintf("arn:aws:securityhub:%s:517716713836:product/crowdstrike/crowdstrike-falcon", region)
}

// truncateField shortens value to at most limit characters, replacing the tail
// with an ellipsis when it overruns. Counting is by rune so multibyte content is
// not split mid-character.
func truncateField(value string, limit int) string {
	runes := []rune(value)
	if len(runes) <= limit {
		return value
	}
	// Below four characters there is no room for content plus an ellipsis, so
	// return a plain prefix rather than indexing past the start of the slice.
	if limit <= 3 {
		return string(runes[:limit])
	}
	return string(runes[:limit-3]) + "..."
}

// isAWSProvider reports whether a cloud-provider string denotes AWS, matching on
// the first three characters case-insensitively (so "AWS", "aws-cn", etc.).
func isAWSProvider(provider string) bool {
	return strings.HasPrefix(strings.ToUpper(provider), "AWS")
}

// normalizeMAC lowercases a MAC address and strips ":" and "-" separators so two
// differently formatted addresses compare equal.
func normalizeMAC(mac string) string {
	mac = strings.ToLower(mac)
	mac = strings.ReplaceAll(mac, ":", "")
	mac = strings.ReplaceAll(mac, "-", "")
	return mac
}

// anyToString renders a JSON-decoded value as a string for a product field.
func anyToString(v any) string {
	switch x := v.(type) {
	case string:
		return x
	case nil:
		return ""
	default:
		return fmt.Sprint(x)
	}
}

// int32FromAny extracts an int32 from a JSON-decoded numeric value, returning 0
// for any non-numeric or out-of-range value. Used for network ports, which
// always fit in int32.
func int32FromAny(v any) int32 {
	n := utils.IntFromAny(v)
	if n < math.MinInt32 || n > math.MaxInt32 {
		return 0
	}
	return int32(n)
}

func init() {
	backend.Register("AWS", newSecurityHub)
}
