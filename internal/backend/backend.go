// Package backend defines the pluggable backend contract and the registry that
// instantiates the set enabled by config.
//
// Each backend registers a Constructor under a name in its init(); Build
// instantiates the enabled set. Adding a backend is a new package plus a
// blank import (see internal/cli/run.go) so its init() runs. One list must be
// kept in sync by hand: config.validBackendNames, the startup allow-list, which
// cannot import this registry without an import cycle. TestBackendNamesMatchConfig
// fails if the two drift apart.
package backend

import (
	"context"
	"log/slog"

	"github.com/crowdstrike/falcon-integration-gateway/internal/config"
	"github.com/crowdstrike/falcon-integration-gateway/internal/events"
)

// AllEventTypes is the sentinel a backend returns from RelevantEventTypes when
// it accepts every event type. When any enabled backend uses it, the
// server-side eventType filter union collapses to "no filter" (nil).
var AllEventTypes = []string{"*"}

// Backend is the contract every backend package implements.
//
// IsRelevant and Process receive an *events.EnrichedEvent: the raw stream event
// plus lazy accessors that resolve host details and MDM identifiers on demand.
// The embedded *events.Event promotes the raw accessors, so a backend that
// ignores enrichment reads it exactly as a raw event.
type Backend interface {
	// Name returns the backend's registry name (e.g. "GENERIC").
	Name() string
	// RelevantEventTypes returns the event types this backend consumes, or
	// AllEventTypes to accept everything.
	RelevantEventTypes() []string
	// IsRelevant is the per-event, backend-specific filter (third dispatch gate).
	IsRelevant(ctx context.Context, ev *events.EnrichedEvent) bool
	// Process submits the event; a returned error enables at-least-once retry.
	Process(ctx context.Context, ev *events.EnrichedEvent) error
}

// Closer is optionally implemented by backends that hold resources (SDK
// clients, sockets) to flush/close on shutdown.
type Closer interface {
	Close(ctx context.Context) error
}

// Constructor builds a Backend from resolved config and a logger. It returns an
// error to abort startup.
type Constructor func(cfg *config.Config, logger *slog.Logger) (Backend, error)
