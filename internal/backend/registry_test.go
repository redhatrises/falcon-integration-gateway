package backend

import (
	"context"
	"slices"
	"testing"

	"github.com/crowdstrike/falcon-integration-gateway/internal/events"
)

// stubBackend is a minimal Backend whose only meaningful behaviour is the set of
// event types it declares; the other methods satisfy the interface.
type stubBackend struct {
	types []string
}

func (s stubBackend) Name() string                 { return "stub" }
func (s stubBackend) RelevantEventTypes() []string { return s.types }
func (s stubBackend) IsRelevant(context.Context, *events.EnrichedEvent) bool {
	return true
}
func (s stubBackend) Process(context.Context, *events.EnrichedEvent) error { return nil }

func TestUnionEventTypes(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		backends []Backend
		want     []string
	}{
		{
			name:     "no backends yields no server-side filter",
			backends: nil,
			want:     nil,
		},
		{
			name:     "single backend with types",
			backends: []Backend{stubBackend{types: []string{"EppDetectionSummaryEvent"}}},
			want:     []string{"EppDetectionSummaryEvent"},
		},
		{
			name: "union is sorted and de-duplicated across backends",
			backends: []Backend{
				stubBackend{types: []string{"B", "A"}},
				stubBackend{types: []string{"A", "C"}},
			},
			want: []string{"A", "B", "C"},
		},
		{
			name: "any AllEventTypes collapses the union to nil",
			backends: []Backend{
				stubBackend{types: []string{"EppDetectionSummaryEvent"}},
				stubBackend{types: AllEventTypes},
			},
			want: nil,
		},
		{
			name:     "AllEventTypes alone yields nil",
			backends: []Backend{stubBackend{types: AllEventTypes}},
			want:     nil,
		},
		{
			name:     "backend declaring no types yields nil",
			backends: []Backend{stubBackend{types: nil}},
			want:     nil,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := UnionEventTypes(tc.backends)
			if !slices.Equal(got, tc.want) {
				t.Errorf("UnionEventTypes() = %v, want %v", got, tc.want)
			}
		})
	}
}
