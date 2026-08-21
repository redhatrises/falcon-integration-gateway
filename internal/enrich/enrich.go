// Package enrich resolves per-sensor host details and MDM identifiers from the
// Falcon Hosts and Real Time Response APIs, caching results so the pipeline's
// cloud-detection gate and enrichment-consuming backends touch the network at
// most once per sensor within a bounded window.
package enrich

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/cenkalti/backoff/v5"

	"github.com/crowdstrike/falcon-integration-gateway/internal/common"
	"github.com/crowdstrike/falcon-integration-gateway/internal/config"
	"github.com/crowdstrike/falcon-integration-gateway/internal/falcon/client"
)

// Enrichment timing defaults. These are not user-tunable: host-detail fetches
// retry a few times over the transient errors a busy tenant produces, and MDM
// lookups poll RTR command status until a bounded deadline so a command that
// never completes cannot wedge a worker.
const (
	defaultMaxTries     = 4
	defaultPollInterval = 2 * time.Second
	defaultMDMTimeout   = 60 * time.Second

	// defaultArcTimeout bounds one Arc-config fetch over RTR. The fetch delegates
	// the whole session lifecycle (open, execute, poll, read) to the client, whose
	// poll honors ctx.Done but imposes no deadline of its own. The pipeline
	// delivers on a long-lived context with no deadline, so without this bound a
	// dead sensor's poll would park a worker until process shutdown.
	defaultArcTimeout = 60 * time.Second
)

// HostRTRClient is the slice of the Falcon client the enricher depends on. It is
// declared here, next to its only consumer, so the enricher can be tested with a
// hermetic call recorder in place of a live tenant connection.
type HostRTRClient interface {
	DeviceDetails(ctx context.Context, deviceID string) ([]*common.HostDetails, error)
	InitRTRSession(ctx context.Context, deviceID string) (*client.RTRSession, error)
	ExecuteRTRCommand(ctx context.Context, cmd client.RTRCommand) (*client.RTRCommandResult, error)
	CheckRTRCommandStatus(ctx context.Context, cloudRequestID string, sequenceID int) (*client.RTRCommandStatus, error)
	DeleteRTRSession(ctx context.Context, sessionID string) error
	RTRFetchFile(ctx context.Context, deviceID, filepath string) ([]byte, error)
}

// Resolver implements events.Enricher over a Falcon client, caching host details
// and MDM identifiers per sensor.
type Resolver struct {
	client HostRTRClient
	logger *slog.Logger

	hosts *singleflightCache[*common.HostDetails]
	mdm   *singleflightCache[string]
	arc   *singleflightCache[arcResult]

	arcKeyword string

	newBackOff   func() backoff.BackOff
	maxTries     uint
	pollInterval time.Duration
	mdmTimeout   time.Duration
	arcTimeout   time.Duration
}

// Params holds the constructor inputs for New: the resolved config, the Falcon
// host/RTR client, and a logger.
type Params struct {
	Config *config.Config
	Client HostRTRClient
	Logger *slog.Logger
}

// New constructs a Resolver whose per-sensor host and MDM caches are sized and
// expired from the [enrich] config section. The RTR timing (retry count, poll
// interval, MDM deadline) uses fixed defaults tuned for a live tenant. It
// returns an error rather than panicking when the cache size is out of range so
// a misconfiguration fails startup instead of the first lookup.
func New(p Params) (*Resolver, error) {
	size := p.Config.Cache.Size
	if size < 1 {
		return nil, fmt.Errorf("enrich: cache size must be positive, got %d", size)
	}
	ttl := p.Config.Cache.TTLDuration

	return &Resolver{
		client:       p.Client,
		logger:       p.Logger,
		hosts:        newSingleflightCache[*common.HostDetails](size, ttl),
		mdm:          newSingleflightCache[string](size, ttl),
		arc:          newSingleflightCache[arcResult](size, ttl),
		arcKeyword:   p.Config.Falcon.RTRQuarantineKeyword,
		newBackOff:   func() backoff.BackOff { return backoff.NewExponentialBackOff() },
		maxTries:     defaultMaxTries,
		pollInterval: defaultPollInterval,
		mdmTimeout:   defaultMDMTimeout,
		arcTimeout:   defaultArcTimeout,
	}, nil
}
