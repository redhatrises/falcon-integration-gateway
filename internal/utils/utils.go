// Package utils holds small, dependency-free helpers shared across packages
// that cannot import one another without an import cycle (for example the stream
// supervisor and the worker pipeline, or config and the backend registry). It
// imports only the standard library so any package may depend on it.
package utils

import (
	"context"
	"encoding/json"
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

// PollUntil calls check immediately and then every interval until it reports
// done, honoring ctx between polls. It returns nil once check reports done, the
// check's error if a poll fails, or ctx.Err() if ctx is cancelled or its
// deadline passes while waiting. check is always invoked at least once, before
// any wait, so an already-complete condition returns without sleeping. The
// caller owns the bound: derive a deadline on ctx to cap the total wait.
func PollUntil(ctx context.Context, interval time.Duration, check func(context.Context) (done bool, err error)) error {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		done, err := check(ctx)
		if err != nil {
			return err
		}
		if done {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

// IntFromAny extracts an int from a JSON-decoded value, returning 0 for any
// non-numeric value. A fractional value is truncated toward zero, whether it
// arrives as a float64 or as a decimal-formatted json.Number (the form produced
// when the stream is decoded with UseNumber).
func IntFromAny(v any) int {
	switch n := v.(type) {
	case float64:
		return int(n)
	case int:
		return n
	case json.Number:
		if i, err := n.Int64(); err == nil {
			return int(i)
		}
		// A decimal-formatted literal (e.g. "3.0") is not a valid Int64; fall
		// back to the float parse and truncate, matching the float64 branch.
		if f, err := n.Float64(); err == nil {
			return int(f)
		}
		return 0
	default:
		return 0
	}
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
