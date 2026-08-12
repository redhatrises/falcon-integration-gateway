// Package e2e contains live end-to-end tests that run FIG against a real
// CrowdStrike Falcon tenant. They are excluded from `make test` (unit) and run
// only via `make test-e2e`, and they Skip unless FALCON_CLIENT_ID and
// FALCON_CLIENT_SECRET are present so a checkout without credentials stays green.
package e2e

import (
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

// TestE2E is the Ginkgo entry point for the live end-to-end suite.
func TestE2E(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "FIG End-to-End Suite")
}
