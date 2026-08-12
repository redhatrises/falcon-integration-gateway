// Package stream is the producer side of FIG: a supervisor that lists the
// Falcon event streams for the configured application, opens a long-poll HTTP
// connection to each, and emits decoded events onto a channel for the pipeline
// to consume.
//
// It is a re-architecture of fig/falcon/stream.py. The offset/whence resumption
// tree (connection.go) and the stream-URL construction are ported faithfully so
// the Falcon wire behaviour is identical; everything else (supervision, backoff,
// context cancellation, the read-idle watchdog) is new.
//
// The long-poll data feed uses a plain net/http client rather than the gofalcon
// SDK: the feed is a long-lived, chunked, newline-delimited JSON response that
// the generated SDK reader is not built to stream. The control plane (listing
// and refreshing sessions) still goes through internal/falcon/client.
package stream

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/crowdstrike/falcon-integration-gateway/internal/events"
)

// errIdleTimeout is returned by a connection when no bytes (not even a
// heartbeat) arrive within the idle timeout, signalling a dead wire that the
// supervisor should reconnect.
var errIdleTimeout = errors.New("stream: idle timeout")

// defaultIdleTimeout bounds how long a connection waits for the next line (data
// or heartbeat) before treating the wire as dead. The Python client used a 60s
// socket timeout; a heartbeat arrives well inside this window.
const defaultIdleTimeout = 120 * time.Second

// resolveOffset ports the offset/whence decision tree from
// fig/falcon/stream.py:88-109, substituting the persisted queueOffset
// (offset.Store.Load) for the Python queue's last_offset.
//
// It returns the offset to resume from and whether to use whence=2 (start from
// the newest event). whence=2 is used only on a first-ever connection with
// start_from_newest set; once anything has been committed, queueOffset is
// non-zero and the resume falls back to it so events are not re-delivered.
func resolveOffset(configOffset, queueOffset uint64, startFromNewest bool) (offset uint64, useWhence bool) {
	if startFromNewest {
		if queueOffset == 0 {
			return 0, true
		}
		return queueOffset, false
	}
	if configOffset == 0 && queueOffset == 0 {
		return 0, false
	}
	return max(configOffset, queueOffset), false
}

// connectionConfig holds the immutable inputs to a single long-poll session.
type connectionConfig struct {
	url         string
	token       string
	feedID      string
	offset      uint64
	useWhence   bool
	eventTypes  []string
	seedFloor   func(context.Context, uint64) error
	httpClient  *http.Client
	idleTimeout time.Duration
	logger      *slog.Logger
}

// connection is a single long-poll session against one Falcon event stream. It
// is created fresh for each (re)connect so the resume offset is re-resolved
// from the store every time.
type connection struct {
	cfg connectionConfig
}

// newConnection builds a connection from cfg, applying the default idle timeout
// when none is set.
func newConnection(cfg connectionConfig) *connection {
	if cfg.idleTimeout <= 0 {
		cfg.idleTimeout = defaultIdleTimeout
	}
	if cfg.logger == nil {
		cfg.logger = slog.Default()
	}
	return &connection{cfg: cfg}
}

// buildURL constructs the long-poll URL. Port of StreamingConnection.open
// (fig/falcon/stream.py:158-184): whence=2 on start-from-newest, otherwise an
// offset of lastSeen+1 (or 0 when lastSeen is 0), with an optional
// &eventType= server-side filter appended.
func (c *connection) buildURL() string {
	filter := ""
	if len(c.cfg.eventTypes) > 0 {
		filter = "&eventType=" + strings.Join(c.cfg.eventTypes, ",")
	}
	if c.cfg.useWhence {
		return c.cfg.url + "&whence=2" + filter
	}
	offsetValue := uint64(0)
	if c.cfg.offset != 0 {
		offsetValue = c.cfg.offset + 1
	}
	return c.cfg.url + "&offset=" + strconv.FormatUint(offsetValue, 10) + filter
}

// run opens the connection and reads newline-delimited JSON, emitting each
// decoded event onto out until the stream closes, the context is cancelled, or
// an error occurs.
//
// Return semantics:
//   - nil: the server closed the stream (io.EOF), the normal signal in the
//     Python client (a swallowed ChunkedEncodingError). The supervisor
//     reconnects at the resumed offset.
//   - ctx.Err(): the parent context was cancelled (graceful shutdown).
//   - errIdleTimeout / a wrapped network error: the wire died; reconnect.
//
// Every event is forwarded; no severity, age, or event-type filtering happens
// here. Dropping events in the producer would create offset gaps that stall the
// pipeline's contiguous-run commit watermark, so all filtering is done in the
// pipeline, which advances the watermark past filtered events.
func (c *connection) run(ctx context.Context, out chan<- *events.Event) error {
	// A child context lets the idle watchdog tear down just this HTTP request
	// without cancelling the parent (which would stop the whole daemon).
	reqCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	url := c.buildURL()
	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, url, nil)
	if err != nil {
		return fmt.Errorf("stream: build request: %w", err)
	}
	req.Header.Set("Authorization", "Token "+c.cfg.token)
	req.Header.Set("Connection", "Keep-Alive")

	c.cfg.logger.Info("opening streaming connection", "whence", c.cfg.useWhence, "offset", c.cfg.offset)

	resp, err := c.cfg.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("stream: open connection: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck // read-only body, close error is not actionable

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("stream: unexpected status %d %s", resp.StatusCode, http.StatusText(resp.StatusCode))
	}

	// The idle watchdog cancels the request if no line arrives within the idle
	// timeout. It is re-armed on every received line and paused across a
	// backpressure-blocked emit so a slow consumer is not read as a dead wire.
	watchdog := time.AfterFunc(c.cfg.idleTimeout, cancel)
	defer watchdog.Stop()

	scanner := bufio.NewScanner(resp.Body)
	// Large detection lines (MITRE/network arrays) exceed the 64 KB default and
	// would fail the scan, so allow up to 4 MB per line.
	scanner.Buffer(make([]byte, 0, 64<<10), 4<<20)

	// The first delivered event fixes where the resume watermark must start: the
	// stream begins at whatever offset Falcon has retained (far above a cold-start
	// 0), so the pipeline's contiguous-run watermark is seeded to firstOffset-1
	// before the event is emitted. Without this the watermark would wait for an
	// offset 1 that never arrives and never commit anything.
	seeded := false

	for scanner.Scan() {
		watchdog.Reset(c.cfg.idleTimeout)

		line := scanner.Bytes()
		if len(bytes.TrimSpace(line)) == 0 {
			// Blank line: a heartbeat. Skip it; the watchdog was just reset.
			continue
		}

		ev, err := events.ParseLine(line, c.cfg.feedID)
		if err != nil {
			c.cfg.logger.Warn("skipping malformed stream line", "error", err)
			continue
		}

		if !seeded {
			if off := ev.Offset(); off > 0 && c.cfg.seedFloor != nil {
				if err := c.cfg.seedFloor(ctx, off-1); err != nil {
					return fmt.Errorf("stream: seed offset floor: %w", err)
				}
			}
			seeded = true
		}

		// Pause the watchdog while (possibly) blocked on backpressure so a slow
		// pipeline is not mistaken for a dead connection.
		watchdog.Stop()
		select {
		case out <- ev:
		case <-ctx.Done():
			return ctx.Err()
		}
		watchdog.Reset(c.cfg.idleTimeout)
	}

	if err := scanner.Err(); err != nil {
		// Parent cancelled: graceful shutdown, surface the cancellation.
		if ctx.Err() != nil {
			return ctx.Err()
		}
		// Only the watchdog cancelled reqCtx: report a dead wire.
		if reqCtx.Err() != nil {
			return fmt.Errorf("stream: read after %s of silence: %w", c.cfg.idleTimeout, errIdleTimeout)
		}
		return fmt.Errorf("stream: read: %w", err)
	}

	// scanner.Scan returned false with no error: the server closed the stream.
	// This is the normal close signal; the supervisor reconnects.
	return nil
}

// defaultHTTPClient returns an http.Client tuned for a long-lived streaming
// feed: no overall Timeout (the connection is meant to stay open), but explicit
// dial, TLS-handshake, and response-header timeouts so a stalled setup fails
// fast rather than hanging forever.
func defaultHTTPClient() *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyFromEnvironment,
			DialContext: (&net.Dialer{
				Timeout:   30 * time.Second,
				KeepAlive: 30 * time.Second,
			}).DialContext,
			ForceAttemptHTTP2:     true,
			MaxIdleConns:          10,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ResponseHeaderTimeout: 30 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
		},
	}
}
