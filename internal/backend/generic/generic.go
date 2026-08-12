// Package generic implements the GENERIC reference backend, which simply logs
// each received Falcon event to stdout. It is the P1 reference backend and a
// port of fig/backends/generic/__init__.py.
package generic

import (
	"context"
	"log/slog"
	"strings"

	"github.com/crowdstrike/falcon-integration-gateway/internal/backend"
	"github.com/crowdstrike/falcon-integration-gateway/internal/config"
	"github.com/crowdstrike/falcon-integration-gateway/internal/events"
)

// Runtime is the GENERIC backend. It accepts every event and logs it.
type Runtime struct {
	logger     *slog.Logger
	eventTypes []string
}

// New constructs the GENERIC backend. It matches backend.Constructor and is
// registered in init(). Port of Runtime.__init__ in
// fig/backends/generic/__init__.py: it resolves the configured event types and
// logs them on startup.
func New(cfg *config.Config, logger *slog.Logger) (backend.Backend, error) {
	r := &Runtime{
		logger:     logger,
		eventTypes: parseEventTypes(cfg.Generic.EventTypes, logger),
	}
	if isAll(r.eventTypes) {
		logger.Info("GENERIC Backend is enabled for ALL event types.")
	} else {
		logger.Info("GENERIC Backend is enabled for event types.", "event_types", r.eventTypes)
	}
	return r, nil
}

// parseEventTypes mirrors the RELEVANT_EVENT_TYPES property in the Python
// source: "ALL" (case-insensitive, trimmed) yields the AllEventTypes sentinel;
// otherwise the value is comma-split and trimmed; an empty parsed list logs a
// warning and falls back to AllEventTypes.
func parseEventTypes(raw string, logger *slog.Logger) []string {
	if strings.EqualFold(strings.TrimSpace(raw), "ALL") {
		return backend.AllEventTypes
	}

	var types []string
	for _, t := range strings.Split(raw, ",") {
		if trimmed := strings.TrimSpace(t); trimmed != "" {
			types = append(types, trimmed)
		}
	}

	if len(types) == 0 {
		logger.Warn("GENERIC backend has empty event_types configuration, defaulting to ALL")
		return backend.AllEventTypes
	}
	return types
}

func isAll(types []string) bool {
	return len(types) == 1 && types[0] == backend.AllEventTypes[0]
}

// Name returns the backend registry name.
func (r *Runtime) Name() string {
	return "GENERIC"
}

// RelevantEventTypes returns the configured event types, or AllEventTypes.
func (r *Runtime) RelevantEventTypes() []string {
	return r.eventTypes
}

// IsRelevant always returns true; GENERIC accepts every event.
func (r *Runtime) IsRelevant(_ context.Context, _ *events.EnrichedEvent) bool {
	return true
}

// Process logs the event. Identifying metadata is logged at INFO; the full raw
// event body — which carries tenant data (CID, source IPs, API client IDs) — is
// logged separately at DEBUG so it is emitted only when an operator opts into
// verbose logging rather than by default. It never fails.
func (r *Runtime) Process(_ context.Context, ev *events.EnrichedEvent) error {
	r.logger.Info("GENERIC event",
		"event_type", ev.EventType(),
		"feed_id", ev.FeedID,
		"offset", ev.Offset(),
		"uid", ev.UID(),
	)
	r.logger.Debug("GENERIC event body",
		"uid", ev.UID(),
		"event", string(ev.Raw),
	)
	return nil
}

func init() {
	backend.Register("GENERIC", New)
}
