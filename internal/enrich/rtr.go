package enrich

import (
	"context"

	"github.com/crowdstrike/falcon-integration-gateway/internal/falcon/client"
	"github.com/crowdstrike/falcon-integration-gateway/internal/metrics"
	"github.com/crowdstrike/falcon-integration-gateway/internal/utils"
)

// runRTRCommand opens an RTR session on the sensor, runs cmd to completion, and
// always closes the session before returning. The session is closed under a
// fresh short-lived context so cleanup still runs when the caller's context was
// already cancelled (e.g. during shutdown). The command's final status is
// returned for the caller to parse. The caller supplies cmd without a
// SessionID; it is filled in once the session opens.
func (e *Resolver) runRTRCommand(ctx context.Context, sensorID string, cmd client.RTRCommand) (*client.RTRCommandStatus, error) {
	sess, err := e.client.InitRTRSession(ctx, sensorID)
	if err != nil {
		return nil, err
	}
	metrics.EnrichRTRSessions.Inc()
	defer func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), client.RTRCleanupTimeout)
		defer cancel()
		if derr := e.client.DeleteRTRSession(cleanupCtx, sess.SessionID); derr != nil {
			e.logger.WarnContext(ctx, "failed to close RTR session", "sensor_id", sensorID)
		}
	}()

	cmd.SessionID = sess.SessionID
	res, err := e.client.ExecuteRTRCommand(ctx, cmd)
	if err != nil {
		return nil, err
	}
	return e.pollCommand(ctx, res.CloudRequestID)
}

// pollCommand waits for an RTR command to complete, returning its final status.
// It polls on a fixed interval bounded by mdmTimeout so a command that never
// completes cannot wedge a worker (unlike the legacy unbounded busy-wait).
func (e *Resolver) pollCommand(ctx context.Context, cloudRequestID string) (*client.RTRCommandStatus, error) {
	ctx, cancel := context.WithTimeout(ctx, e.mdmTimeout)
	defer cancel()

	var status *client.RTRCommandStatus
	err := utils.PollUntil(ctx, e.pollInterval, func(ctx context.Context) (bool, error) {
		var err error
		status, err = e.client.CheckRTRCommandStatus(ctx, cloudRequestID, 0)
		if err != nil {
			return false, err
		}
		return status.Complete, nil
	})
	if err != nil {
		return nil, err
	}
	return status, nil
}
