// Package version holds build-stamped version metadata and constructs the
// Falcon API User-Agent string.
//
// Version and Commit are overridable at build time via:
//
//	go build -ldflags "-X github.com/crowdstrike/falcon-integration-gateway/internal/version.Version=1.2.3 \
//	                   -X github.com/crowdstrike/falcon-integration-gateway/internal/version.Commit=abcdef"
package version

// Version is the release version; overridden via -ldflags at build time.
var Version = "0.0.0+dev"

// Commit is the git commit the binary was built from; overridden via -ldflags.
var Commit = "unknown"
