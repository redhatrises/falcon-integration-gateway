package backend

// DropError signals a backend deliberately dropped an event: it is handled (the
// watermark advances) but was not delivered. Reason labels the drop for metrics.
//
// The pipeline recognizes a DropError via errors.As and, rather than retrying or
// counting the event as delivered or failed, records it under
// fig_events_dropped_total{backend,reason} and advances the resume watermark. A
// backend returns one from Process when it intentionally declines an event (for
// example, a permission-denied resource it cannot reach, or an unresolvable
// host) instead of returning a bare nil, which the pipeline would otherwise
// count as a successful delivery.
type DropError struct{ Reason string }

// Error implements the error interface.
func (e *DropError) Error() string { return "backend: event dropped: " + e.Reason }

// Dropped returns a DropError labeled with reason, for a backend to return from
// Process when it deliberately drops an event.
func Dropped(reason string) error { return &DropError{Reason: reason} }
