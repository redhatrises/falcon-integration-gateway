// Package logging constructs the structured slog logger used across FIG.
//
// It emits JSON to stdout with a level parsed case-insensitively from config
// (logging.level). golangci-lint's sloglint linter mandates log/slog; this is
// the single place a handler is built.
package logging

import (
	"log/slog"
	"os"
	"strings"
)

// New returns a slog.Logger backed by a JSON handler writing to stdout.
//
// level is parsed case-insensitively: DEBUG, INFO, WARN, ERROR. Any
// unrecognized or empty value defaults to INFO.
func New(level string) *slog.Logger {
	handler := slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: parseLevel(level),
	})
	return slog.New(handler)
}

// parseLevel maps a case-insensitive level string to slog.Level, defaulting to
// slog.LevelInfo for unknown or empty input.
func parseLevel(level string) slog.Level {
	switch strings.ToUpper(strings.TrimSpace(level)) {
	case "DEBUG":
		return slog.LevelDebug
	case "WARN", "WARNING":
		return slog.LevelWarn
	case "ERROR":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}
