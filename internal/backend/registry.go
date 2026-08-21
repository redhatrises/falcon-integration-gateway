package backend

import (
	"fmt"
	"log/slog"
	"sort"
	"sync"

	"github.com/crowdstrike/falcon-integration-gateway/internal/config"
)

// registry holds registered backend constructors keyed by name. It is
// package-global so backend packages can Register from their init().
var (
	registryMu sync.RWMutex
	registry   = map[string]Constructor{}
)

// Register adds a backend Constructor under name. It panics on a duplicate
// registration, which is a programming error surfaced at init time.
func Register(name string, c Constructor) {
	registryMu.Lock()
	defer registryMu.Unlock()
	if _, exists := registry[name]; exists {
		panic(fmt.Sprintf("backend: duplicate registration for %q", name))
	}
	registry[name] = c
}

// Build instantiates the backends named in names, in the given order. It
// returns an error if any name is unregistered or a constructor fails.
func Build(names []string, cfg *config.Config, logger *slog.Logger) ([]Backend, error) {
	registryMu.RLock()
	defer registryMu.RUnlock()

	backends := make([]Backend, 0, len(names))
	for _, name := range names {
		ctor, ok := registry[name]
		if !ok {
			return nil, fmt.Errorf("backend: unknown backend %q", name)
		}
		b, err := ctor(cfg, logger)
		if err != nil {
			return nil, fmt.Errorf("backend: constructing %q: %w", name, err)
		}
		backends = append(backends, b)
	}
	return backends, nil
}

// Names returns the sorted list of registered backend names. config validation
// should stay in sync with this set.
func Names() []string {
	registryMu.RLock()
	defer registryMu.RUnlock()

	names := make([]string, 0, len(registry))
	for name := range registry {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// UnionEventTypes computes the server-side eventType filter for a set of
// backends. It returns nil if ANY backend uses AllEventTypes (contains "*"),
// meaning no server-side filter is applied; otherwise it returns the sorted,
// de-duplicated union of every backend's RelevantEventTypes.
func UnionEventTypes(bs []Backend) []string {
	seen := map[string]struct{}{}
	for _, b := range bs {
		for _, t := range b.RelevantEventTypes() {
			if t == "*" {
				return nil
			}
			seen[t] = struct{}{}
		}
	}
	if len(seen) == 0 {
		return nil
	}
	types := make([]string, 0, len(seen))
	for t := range seen {
		types = append(types, t)
	}
	sort.Strings(types)
	return types
}
