// Package utils holds small, dependency-free helpers shared across packages
// that cannot import one another without an import cycle (for example the stream
// supervisor and the worker pipeline, or config and the backend registry). It
// imports only the standard library so any package may depend on it.
package utils

import (
	"context"
	"errors"
	"strings"
	"time"
)

// Sleep waits for d or until ctx is cancelled. It returns true if the full
// duration elapsed (or d is non-positive) and false if ctx was cancelled first.
func Sleep(ctx context.Context, d time.Duration) bool {
	if d <= 0 {
		return ctx.Err() == nil
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

// IsCanceled reports whether err is a context cancellation or deadline, i.e. the
// graceful-shutdown signal rather than a fatal fault.
func IsCanceled(err error) bool {
	return errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)
}

// SplitCSV splits a comma-separated string into trimmed, non-empty tokens. A
// blank or whitespace-only input yields a nil slice.
func SplitCSV(s string) []string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if t := strings.TrimSpace(p); t != "" {
			out = append(out, t)
		}
	}
	return out
}
