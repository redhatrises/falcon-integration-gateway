package e2e

import (
	"context"
	"os"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/crowdstrike/falcon-integration-gateway/internal/cli"
	"github.com/crowdstrike/falcon-integration-gateway/internal/config"
	"github.com/crowdstrike/falcon-integration-gateway/internal/logging"
)

// liveRunWindow is how long the daemon is left streaming before the test
// cancels it. It only needs to be long enough to establish a stream session
// and observe the GENERIC backend logging at least one event or heartbeat.
const liveRunWindow = 30 * time.Second

var _ = Describe("GENERIC backend against a live tenant", Label("live"), func() {
	BeforeEach(func() {
		if os.Getenv("FALCON_CLIENT_ID") == "" || os.Getenv("FALCON_CLIENT_SECRET") == "" {
			Skip("FALCON_CLIENT_ID/FALCON_CLIENT_SECRET not set; skipping live e2e")
		}
	})

	It("boots, streams, and shuts down gracefully", func() {
		// Force the GENERIC backend and an ephemeral offset store so the test
		// never touches the durable on-disk offsets file.
		Expect(os.Setenv("FIG_BACKENDS", "GENERIC")).To(Succeed())
		GinkgoT().Setenv("EVENTS_OFFSET_STORE", "memory")

		cfg, err := config.Load("", nil)
		Expect(err).NotTo(HaveOccurred())
		cfg.Events.OffsetStore = "memory"
		Expect(cfg.Validate()).To(Succeed())

		ctx, cancel := context.WithTimeout(context.Background(), liveRunWindow)
		defer cancel()

		// Run blocks until the context deadline cancels it; a graceful shutdown
		// returns nil.
		done := make(chan error, 1)
		go func() { done <- cli.Run(ctx, cfg, logging.New(cfg.Logging.Level)) }()

		select {
		case err := <-done:
			Expect(err).NotTo(HaveOccurred())
		case <-time.After(liveRunWindow + 15*time.Second):
			Fail("daemon did not shut down within the grace period after context cancellation")
		}
	})
})
