package backend

import (
	"errors"
	"fmt"
	"testing"
)

func TestDroppedIsRecognizedAsDropError(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		reason string
	}{
		{"permission denied", "permission_denied"},
		{"asset not found", "asset_not_found"},
		{"host unresolved", "host_unresolved"},
		{"empty reason", ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := Dropped(tc.reason)

			var drop *DropError
			if !errors.As(err, &drop) {
				t.Fatalf("errors.As(%v) = false, want a *DropError", err)
			}
			if drop.Reason != tc.reason {
				t.Errorf("Reason = %q, want %q", drop.Reason, tc.reason)
			}
		})
	}
}

func TestDropErrorUnwrapsThroughWrapping(t *testing.T) {
	t.Parallel()

	wrapped := fmt.Errorf("deliver: %w", Dropped("permission_denied"))

	var drop *DropError
	if !errors.As(wrapped, &drop) {
		t.Fatalf("errors.As(%v) = false, want a *DropError through the wrap", wrapped)
	}
	if drop.Reason != "permission_denied" {
		t.Errorf("Reason = %q, want %q", drop.Reason, "permission_denied")
	}
}
