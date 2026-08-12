// Package enrich resolves per-sensor host details and MDM identifiers from the
// Falcon Hosts and Real Time Response APIs, memoizing results so the pipeline's
// cloud-detection gate and enrichment-consuming backends touch the network at
// most once per sensor within a bounded window.
package enrich

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/cenkalti/backoff/v5"
	"github.com/hashicorp/golang-lru/v2/expirable"
	"golang.org/x/sync/singleflight"

	"github.com/crowdstrike/falcon-integration-gateway/internal/config"
	"github.com/crowdstrike/falcon-integration-gateway/internal/events"
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

	// rtrCleanupTimeout bounds the RTR session delete that runs after a lookup
	// returns. It uses its own context so the session is still closed when the
	// caller's context was already cancelled (e.g. during shutdown).
	rtrCleanupTimeout = 5 * time.Second
)

// HostRTRClient is the slice of the Falcon client the enricher depends on. It is
// declared here, next to its only consumer, so the enricher can be tested with a
// hermetic call recorder in place of a live tenant connection.
type HostRTRClient interface {
	DeviceDetails(ctx context.Context, deviceID string) ([]*client.Device, error)
	InitRTRSession(ctx context.Context, deviceID string) (*client.RTRSession, error)
	ExecuteRTRCommand(ctx context.Context, cmd client.RTRCommand) (*client.RTRCommandResult, error)
	CheckRTRCommandStatus(ctx context.Context, cloudRequestID string, sequenceID int) (*client.RTRCommandStatus, error)
	DeleteRTRSession(ctx context.Context, sessionID string) error
}

// Resolver implements events.Enricher over a Falcon client, caching host details
// and MDM identifiers per sensor.
type Resolver struct {
	client HostRTRClient
	logger *slog.Logger

	hostCache *expirable.LRU[string, *events.HostDetails]
	hostGroup singleflight.Group

	mdmCache *expirable.LRU[string, string]
	mdmGroup singleflight.Group

	newBackOff   func() backoff.BackOff
	maxTries     uint
	pollInterval time.Duration
	mdmTimeout   time.Duration
}

// New constructs a Resolver whose per-sensor host and MDM caches are sized and
// expired from the [enrich] config section. The RTR timing (retry count, poll
// interval, MDM deadline) uses fixed defaults tuned for a live tenant. It
// returns an error rather than panicking when cache_size is out of range so a
// misconfiguration fails startup instead of the first lookup.
func New(cfg *config.Config, c HostRTRClient, logger *slog.Logger) (*Resolver, error) {
	size := cfg.Enrich.CacheSize
	if size < 1 {
		return nil, fmt.Errorf("enrich: cache size must be positive, got %d", size)
	}
	ttl := cfg.Enrich.CacheTTLDuration

	return &Resolver{
		client:       c,
		logger:       logger,
		hostCache:    expirable.NewLRU[string, *events.HostDetails](size, nil, ttl),
		mdmCache:     expirable.NewLRU[string, string](size, nil, ttl),
		newBackOff:   func() backoff.BackOff { return backoff.NewExponentialBackOff() },
		maxTries:     defaultMaxTries,
		pollInterval: defaultPollInterval,
		mdmTimeout:   defaultMDMTimeout,
	}, nil
}
