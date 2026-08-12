// Package backend defines the pluggable backend contract and a single
// source-of-truth registry.
//
// It is a port of the Backend contract and dispatch logic in
// fig/backends/__init__.py. Each backend registers a Constructor under a name;
// Build instantiates the set enabled by config. The registry replaces the
// Python "four coordinated edits with duplicated ALL_BACKENDS".
package backend

import (
	"context"
	"log/slog"

	"github.com/crowdstrike/falcon-integration-gateway/internal/config"
	"github.com/crowdstrike/falcon-integration-gateway/internal/events"
)

// AllEventTypes is the sentinel a backend returns from RelevantEventTypes when
// it accepts every event type. When any enabled backend uses it, the
// server-side eventType filter union collapses to "no filter" (nil). Port of
// the "ALL" sentinel in fig/backends/__init__.py.
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
// error to abort startup (port of Python's constructor raising).
type Constructor func(cfg *config.Config, logger *slog.Logger) (Backend, error)
